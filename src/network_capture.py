"""
Dynamic Network Capture Analysis
Uses Playwright + Chrome DevTools Protocol to monitor extension network behavior at runtime.

Threat-driven scoring engine: scores individual requests, detects beaconing patterns,
flags post-navigation exfil, and uses aggregated verdicts instead of single-hit flags.

Requires: pip install playwright && playwright install chromium
This module degrades gracefully if playwright is not installed.
"""

import time
import re
import tempfile
import shutil
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Centralized detection regex (Python equivalents)
# ---------------------------------------------------------------------------

DETECTION_REGEX = {
    # Domain & routing
    'IP_LITERAL': re.compile(r'^https?://\d{1,3}(\.\d{1,3}){3}(:\d+)?(/|$)'),
    'SUSPICIOUS_TLD': re.compile(
        r'\.(top|xyz|win|club|online|site|space|click|fit|rest|work|loan|men'
        r'|gq|ml|cf|tk|buzz|surf|icu|cam|cyou|cfd|sbs|quest)(/|$)', re.I),
    'DDNS': re.compile(r'\.(duckdns|no-ip|dynu|ddns|hopto)\.', re.I),

    # Sensitive indicators
    'CREDENTIAL_KEYS': re.compile(
        r'(password|passwd|pwd|token|auth_token|session_id|cookie|bearer|csrf'
        r'|api_key|apikey|secret|access_token|refresh_token)', re.I),
    'JWT': re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
    'BASE64_BLOB': re.compile(r'[A-Za-z0-9+/]{100,}={0,2}'),

    # Exfil / beaconing paths
    'BEACON_PATH': re.compile(r'(ping|heartbeat|collect|telemetry|track|beacon|report)', re.I),

    # Encoding tricks
    'URL_ENCODED_CRED': re.compile(r'(%3D|%2F|%2B|%40){5,}', re.I),
}

# Domains that should never be flagged on their own (CDN / infra noise)
DOMAIN_ALLOWLIST = {
    # Google
    'googleapis.com', 'google.com', 'gstatic.com', 'googleusercontent.com',
    'accounts.google.com', 'chrome.google.com', 'google-analytics.com',
    'googletagmanager.com', 'analytics.google.com',
    # Firebase
    'firebaseio.com', 'firebase.google.com', 'firebasestorage.googleapis.com',
    'firebaseapp.com',
    # CDNs
    'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
    'jsdelivr.net', 'unpkg.com', 'cdn.jsdelivr.net',
    'akamai.net', 'fastly.net', 'cloudfront.net',
    # Common services
    'jquery.com', 'github.com', 'githubusercontent.com',
    'sentry.io', 'bugsnag.com',
    # Analytics (expected noise)
    'mixpanel.com', 'amplitude.com', 'segment.com',
    # Browser vendors
    'mozilla.org', 'microsoft.com', 'apple.com',
    # Payment (legitimate)
    'stripe.com', 'paypal.com',
}

# ---------------------------------------------------------------------------
# Known SaaS WebSocket endpoints (domain + path patterns) - Stage 2 fast exit
# ---------------------------------------------------------------------------
KNOWN_SAAS_WEBSOCKETS = {
    # ActionCable (Ruby on Rails real-time) - used by qualified.com, basecamp, hey.com, etc.
    'actioncable': {
        'path_pattern': re.compile(r'/cable(\?|$)', re.I),
        'description': 'ActionCable (Rails real-time framework)',
    },
    # Firebase Realtime Database
    'firebase': {
        'domain_pattern': re.compile(r'\.firebaseio\.com$', re.I),
        'description': 'Firebase Realtime Database',
    },
    # Pusher
    'pusher': {
        'domain_pattern': re.compile(r'ws.*\.pusher\.com$', re.I),
        'description': 'Pusher real-time messaging',
    },
    # Intercom
    'intercom': {
        'domain_pattern': re.compile(r'\.intercom\.io$', re.I),
        'description': 'Intercom customer messaging',
    },
    # Drift / qualified / common sales chat SaaS
    'qualified': {
        'domain_pattern': re.compile(r'\.qualified\.com$', re.I),
        'description': 'Qualified.com sales chat',
    },
    'drift': {
        'domain_pattern': re.compile(r'\.drift\.com$', re.I),
        'description': 'Drift chat widget',
    },
    # Socket.IO / generic SaaS analytics
    'socketio': {
        'path_pattern': re.compile(r'/socket\.io/', re.I),
        'description': 'Socket.IO transport',
    },
    # Zendesk
    'zendesk': {
        'domain_pattern': re.compile(r'\.zendesk\.com$', re.I),
        'description': 'Zendesk support chat',
    },
    # LiveChat
    'livechat': {
        'domain_pattern': re.compile(r'\.livechatinc\.com$', re.I),
        'description': 'LiveChat support widget',
    },
    # Crisp
    'crisp': {
        'domain_pattern': re.compile(r'\.crisp\.chat$', re.I),
        'description': 'Crisp chat widget',
    },
}

# Known benign SaaS URL path patterns for regular HTTP requests
KNOWN_SAAS_PATHS = [
    # ActionCable
    re.compile(r'/cable(\?|$)', re.I),
    # Firebase REST / realtime
    re.compile(r'\.firebaseio\.com/.*\.json', re.I),
    re.compile(r'firebaseinstallations\.googleapis\.com', re.I),
    # Analytics beacons (expected noise)
    re.compile(r'/collect\?.*tid=UA-', re.I),  # Google Analytics
    re.compile(r'/g/collect\?', re.I),  # GA4
    re.compile(r'analytics\.google\.com', re.I),
    re.compile(r'/api/v\d+/track', re.I),  # Segment/Mixpanel
]

# Default trigger pages to provoke extension behavior
DEFAULT_TRIGGER_URLS = [
    'https://mail.google.com',
    'https://www.amazon.com',
    'https://github.com/login',
    'https://www.facebook.com',
    'https://www.wikipedia.org',
    'https://example.com',
]

# Scoring thresholds
SCORE_SUSPICIOUS = 4    # Individual request flagged
SCORE_HIGH = 7          # Strong single-request signal
VERDICT_MIN_EVENTS = 3  # Minimum suspicious events for verdict
BEACON_MIN_HITS = 3     # Minimum repeated hits to same endpoint


def _is_allowlisted(domain):
    """Check if a domain (or parent) is in the allowlist."""
    domain = domain.lower()
    if domain in DOMAIN_ALLOWLIST:
        return True
    for allowed in DOMAIN_ALLOWLIST:
        if domain.endswith('.' + allowed):
            return True
    return False


def _is_static_resource(url, resource_type):
    """Check if request is a plain static resource fetch (no payload concern)."""
    static_types = {'Image', 'Stylesheet', 'Font', 'Media'}
    if resource_type in static_types:
        return True
    for ext in ('.js', '.css', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.woff', '.woff2', '.ttf', '.ico'):
        if url.split('?')[0].lower().endswith(ext):
            return True
    return False


def score_request(req):
    """Score a single request for suspiciousness. Returns (score, reasons)."""
    url = req.get('url', '')
    method = req.get('method', 'GET')
    post_data = req.get('post_data') or ''
    headers = req.get('headers', {})
    resource_type = req.get('resource_type', 'Unknown')

    score = 0
    reasons = []

    # Skip internal extension resources
    if url.startswith('chrome-extension://'):
        return 0, []

    parsed = urlparse(url)
    domain = parsed.netloc or ''

    # Skip static resources with no payload
    if _is_static_resource(url, resource_type) and not post_data:
        return 0, []

    # Skip known SaaS path patterns (analytics beacons, Firebase REST, ActionCable)
    for saas_path in KNOWN_SAAS_PATHS:
        if saas_path.search(url):
            return 0, []

    # --- Routing indicators ---
    if DETECTION_REGEX['IP_LITERAL'].search(url):
        score += 3
        reasons.append('Request to raw IP address (C2 indicator)')

    if DETECTION_REGEX['SUSPICIOUS_TLD'].search(url):
        score += 2
        reasons.append(f'Suspicious TLD detected')

    if DETECTION_REGEX['DDNS'].search(url):
        score += 3
        reasons.append('DDNS domain (dynamic DNS - evasion indicator)')

    if not _is_allowlisted(domain) and domain:
        score += 1
        reasons.append(f'Non-allowlisted domain ({domain})')

    # Non-HTTPS
    if parsed.scheme == 'http' and domain:
        score += 2
        reasons.append('Unencrypted HTTP connection')

    # --- Payload indicators ---
    if DETECTION_REGEX['JWT'].search(post_data):
        score += 4
        reasons.append('JWT token in POST body (credential exfiltration)')

    if DETECTION_REGEX['BASE64_BLOB'].search(post_data):
        score += 3
        reasons.append('Large base64 blob in POST body (encoded data exfil)')

    if DETECTION_REGEX['CREDENTIAL_KEYS'].search(post_data):
        score += 3
        reasons.append('Credential-like keys in POST body')

    if DETECTION_REGEX['CREDENTIAL_KEYS'].search(url):
        score += 2
        reasons.append('Credential-like keys in URL parameters')

    if DETECTION_REGEX['URL_ENCODED_CRED'].search(post_data):
        score += 2
        reasons.append('Heavily URL-encoded POST payload')

    # --- Method abuse ---
    if method == 'POST' and len(post_data) > 1000:
        score += 2
        reasons.append(f'Large POST body ({len(post_data)} bytes)')
    elif method == 'POST' and post_data:
        score += 1
        reasons.append('POST request with body data')

    # --- Beaconing hint (path patterns) ---
    if DETECTION_REGEX['BEACON_PATH'].search(parsed.path or ''):
        score += 1
        reasons.append('Beacon-like URL path')

    # --- Auth/cookie header exfil ---
    auth = headers.get('Authorization') or headers.get('authorization', '')
    cookie = headers.get('Cookie') or headers.get('cookie', '')
    if auth:
        score += 2
        reasons.append('Sends Authorization header')
    if cookie and not _is_allowlisted(domain):
        score += 2
        reasons.append('Sends cookies to non-allowlisted domain')

    return score, reasons


class NetworkCaptureAnalyzer:
    """Captures and analyzes network traffic from a Chrome extension at runtime."""

    def __init__(self, trigger_urls=None):
        self.trigger_urls = trigger_urls or DEFAULT_TRIGGER_URLS
        self._captured_requests = []
        self._websocket_connections = {}
        self._navigation_timestamps = []  # Track when pages load
        self._pw = None
        self._browser = None
        self._temp_dir = None

    def analyze(self, extension_dir, extension_id, timeout=30, host_permission_domains=None):
        """
        Launch Chromium with the extension, browse trigger pages, capture network traffic.

        Args:
            extension_dir: Path to unpacked extension directory
            extension_id: Chrome extension ID (32-char string)
            timeout: Total seconds to spend browsing trigger pages
            host_permission_domains: Optional list of domains from host_permissions/content_scripts

        Returns:
            dict: Structured network capture results
        """
        # Build combined trigger URL list: defaults + host_permission domains
        combined_urls = list(self.trigger_urls)
        hp_urls_added = []
        if host_permission_domains:
            has_all_urls = any(d.strip() in ('*', '<all_urls>') for d in host_permission_domains)
            if has_all_urls:
                print("[NETWORK] Extension has <all_urls> access - using default trigger pages only")
            else:
                seen = {urlparse(u).netloc or urlparse(u).path for u in combined_urls}
                for domain in host_permission_domains:
                    domain = domain.strip().lower()
                    if not domain or domain == '*':
                        continue
                    if domain.startswith('*.'):
                        domain = domain[2:]
                    if not domain:
                        continue
                    if domain in seen:
                        continue
                    seen.add(domain)
                    url = f'https://{domain}'
                    combined_urls.append(url)
                    hp_urls_added.append(url)

        if hp_urls_added:
            print(f"[NETWORK] Added {len(hp_urls_added)} host_permission domain(s) to trigger list:")
            for u in hp_urls_added:
                print(f"          + {u}")

        self._active_trigger_urls = combined_urls
        self._captured_requests = []
        self._websocket_connections = {}
        self._navigation_timestamps = []
        start_time = time.time()

        if not self._check_playwright_available():
            return {
                'available': False,
                'error': 'Playwright not installed. Run: pip install playwright && playwright install chromium',
                'extension_requests': [],
                'websocket_connections': [],
                'suspicious_connections': [],
                'new_domains': [],
                'beaconing': [],
                'post_nav_exfil': [],
                'verdict': 'UNAVAILABLE',
                'summary': self._empty_summary()
            }

        try:
            from playwright.sync_api import sync_playwright

            ext_path = str(Path(extension_dir).resolve()).replace('\\', '/')

            self._temp_dir = tempfile.mkdtemp(prefix='ext_capture_')

            print(f"[NETWORK] Launching Chromium with extension loaded...")
            self._pw = sync_playwright().start()

            self._browser = self._pw.chromium.launch_persistent_context(
                user_data_dir=self._temp_dir,
                headless=False,
                args=[
                    '--headless=new',
                    f'--disable-extensions-except={ext_path}',
                    f'--load-extension={ext_path}',
                    '--no-first-run',
                    '--disable-default-apps',
                    '--disable-popup-blocking',
                    '--disable-background-timer-throttling',
                ],
                ignore_default_args=['--enable-automation'],
            )

            # Give extension time to initialize
            time.sleep(2)

            self._browse_trigger_pages(timeout)

            elapsed = time.time() - start_time

            # ---------- Analyze captured traffic ----------
            extension_requests = self._filter_extension_requests(extension_id)

            # Score every request
            scored = self._score_all_requests(extension_requests)

            # Detect beaconing (repeated hits to same endpoint)
            beaconing = self._detect_beaconing(extension_requests)

            # Detect post-navigation exfil (requests within 3s of page load)
            post_nav_exfil = self._detect_post_navigation_exfil(extension_requests)

            # WebSocket analysis
            ws_list = list(self._websocket_connections.values())
            ws_suspicious = self._score_websockets(ws_list)

            # Extract new domains for VT
            new_domains = self._extract_new_domains(extension_requests)

            # Check hard escalation first (for reporting)
            hard_escalated, escalation_detail = self._check_hard_escalation(scored, ws_suspicious)

            # Aggregate verdict
            verdict = self._compute_verdict(scored, beaconing, post_nav_exfil, ws_suspicious)

            summary = {
                'total_requests': len(self._captured_requests),
                'extension_requests': len(extension_requests),
                'suspicious_count': len(scored),
                'high_score_count': len([s for s in scored if s['score'] >= SCORE_HIGH]),
                'data_exfil_detected': any(
                    s.get('method') == 'POST' and s.get('post_data')
                    for s in scored if s['score'] >= SCORE_HIGH
                ),
                'beaconing_detected': len(beaconing) > 0,
                'post_nav_exfil_detected': len(post_nav_exfil) > 0,
                'websocket_count': len(ws_list),
                'websocket_suspicious': len(ws_suspicious),
                'duration_seconds': round(elapsed, 1),
                'trigger_pages_loaded': len(self._active_trigger_urls),
                'host_permission_pages': len(hp_urls_added),
                'hard_escalation': hard_escalated,
                'escalation_detail': escalation_detail,
                'verdict': verdict,
            }

            return {
                'available': True,
                'extension_requests': extension_requests,
                'websocket_connections': ws_list,
                'suspicious_connections': scored,
                'beaconing': beaconing,
                'post_nav_exfil': post_nav_exfil,
                'new_domains': new_domains,
                'verdict': verdict,
                'summary': summary,
            }

        except Exception as e:
            return {
                'available': False,
                'error': str(e),
                'extension_requests': [],
                'websocket_connections': [],
                'suspicious_connections': [],
                'beaconing': [],
                'post_nav_exfil': [],
                'new_domains': [],
                'verdict': 'ERROR',
                'summary': self._empty_summary()
            }
        finally:
            self._cleanup()

    # ------------------------------------------------------------------
    # Browser interaction
    # ------------------------------------------------------------------

    def _browse_trigger_pages(self, timeout):
        """Navigate to trigger URLs and capture network traffic."""
        urls = self._active_trigger_urls or self.trigger_urls
        per_page = max(3, timeout / len(urls))

        for url in urls:
            try:
                print(f"[NETWORK] Browsing {url}...")
                page = self._browser.new_page()
                self._attach_cdp_listeners(page)

                # Record navigation timestamp for post-nav exfil detection
                nav_time = time.time()
                self._navigation_timestamps.append(nav_time)

                page.goto(url, wait_until='domcontentloaded', timeout=int(per_page * 1000))
                # Wait for extension to react
                page.wait_for_timeout(int(per_page * 500))

                # Simulate minimal interaction
                try:
                    page.mouse.move(300, 300)
                    page.mouse.click(300, 300)
                except Exception:
                    pass

                page.close()
            except Exception as e:
                print(f"[NETWORK] Could not load {url}: {e}")
                continue

    def _attach_cdp_listeners(self, page):
        """Attach Chrome DevTools Protocol network listeners to a page."""
        try:
            client = page.context.new_cdp_session(page)
            client.send('Network.enable')

            client.on('Network.requestWillBeSent', self._on_request)
            client.on('Network.webSocketCreated', self._on_ws_created)
            client.on('Network.webSocketFrameSent', self._on_ws_frame_sent)
            client.on('Network.webSocketFrameReceived', self._on_ws_frame_received)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # CDP event handlers
    # ------------------------------------------------------------------

    def _on_request(self, params):
        request = params.get('request', {})
        initiator = params.get('initiator', {})

        self._captured_requests.append({
            'url': request.get('url', ''),
            'method': request.get('method', 'GET'),
            'headers': request.get('headers', {}),
            'post_data': request.get('postData'),
            'resource_type': params.get('type', 'Unknown'),
            'initiator_url': initiator.get('url', ''),
            'initiator_type': initiator.get('type', ''),
            'initiator_stack': initiator.get('stack', {}),
            'timestamp': params.get('wallTime', time.time()),
            'request_id': params.get('requestId', ''),
        })

    def _on_ws_created(self, params):
        rid = params.get('requestId', '')
        self._websocket_connections[rid] = {
            'url': params.get('url', ''),
            'request_id': rid,
            'timestamp': time.time(),
            'frames_sent': [],
            'frames_received': [],
        }

    def _on_ws_frame_sent(self, params):
        rid = params.get('requestId', '')
        if rid in self._websocket_connections:
            payload = params.get('response', {}).get('payloadData', '')
            self._websocket_connections[rid]['frames_sent'].append(payload[:500])

    def _on_ws_frame_received(self, params):
        rid = params.get('requestId', '')
        if rid in self._websocket_connections:
            payload = params.get('response', {}).get('payloadData', '')
            self._websocket_connections[rid]['frames_received'].append(payload[:500])

    # ------------------------------------------------------------------
    # Traffic filtering
    # ------------------------------------------------------------------

    def _filter_extension_requests(self, extension_id):
        """Filter captured requests to those initiated by the extension."""
        ext_prefix = f'chrome-extension://{extension_id}'
        extension_reqs = []

        for req in self._captured_requests:
            if ext_prefix in (req.get('initiator_url') or ''):
                extension_reqs.append(req)
                continue
            if req.get('url', '').startswith(ext_prefix):
                extension_reqs.append(req)
                continue
            stack = req.get('initiator_stack', {})
            frames = stack.get('callFrames', [])
            if any(ext_prefix in (f.get('url') or '') for f in frames):
                extension_reqs.append(req)
                continue

        return extension_reqs

    # ------------------------------------------------------------------
    # Scoring engine
    # ------------------------------------------------------------------

    def _score_all_requests(self, extension_requests):
        """Score every extension request and return those above threshold."""
        suspicious = []

        for req in extension_requests:
            score, reasons = score_request(req)

            if score >= SCORE_SUSPICIOUS:
                url = req.get('url', '')
                parsed = urlparse(url)
                post_data = req.get('post_data') or ''

                severity = 'CRITICAL' if score >= SCORE_HIGH else (
                    'HIGH' if score >= 5 else 'MEDIUM')

                suspicious.append({
                    'url': url,
                    'method': req.get('method', 'GET'),
                    'domain': parsed.netloc or '',
                    'score': score,
                    'reasons': reasons,
                    'severity': severity,
                    'post_data_preview': (post_data[:200] + '...') if len(post_data) > 200 else post_data,
                    'post_data': post_data,
                    'timestamp': req.get('timestamp'),
                })

        return suspicious

    def _detect_beaconing(self, extension_requests):
        """Detect repeated requests to the same endpoint (beaconing / heartbeat)."""
        endpoint_hits = defaultdict(list)

        for req in extension_requests:
            url = req.get('url', '')
            if url.startswith('chrome-extension://'):
                continue
            parsed = urlparse(url)
            # Normalize: scheme + host + path (ignore query params)
            endpoint = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            endpoint_hits[endpoint].append(req.get('timestamp', 0))

        beacons = []
        for endpoint, timestamps in endpoint_hits.items():
            if len(timestamps) >= BEACON_MIN_HITS:
                parsed = urlparse(endpoint)
                domain = parsed.netloc or ''

                # Skip allowlisted domains (analytics pings are expected)
                if _is_allowlisted(domain):
                    continue

                # Calculate interval regularity
                sorted_ts = sorted(timestamps)
                intervals = [sorted_ts[i+1] - sorted_ts[i] for i in range(len(sorted_ts)-1)]
                avg_interval = sum(intervals) / len(intervals) if intervals else 0

                beacons.append({
                    'endpoint': endpoint,
                    'domain': domain,
                    'hit_count': len(timestamps),
                    'avg_interval_seconds': round(avg_interval, 1),
                    'severity': 'HIGH' if len(timestamps) >= 5 else 'MEDIUM',
                    'reason': f'Endpoint hit {len(timestamps)} times '
                              f'(avg interval: {avg_interval:.1f}s) - potential beaconing/C2',
                })

        return beacons

    def _detect_post_navigation_exfil(self, extension_requests):
        """Detect extension requests fired within 3 seconds of a page navigation."""
        POST_NAV_WINDOW = 3.0  # seconds
        post_nav = []

        for req in extension_requests:
            url = req.get('url', '')
            if url.startswith('chrome-extension://'):
                continue

            ts = req.get('timestamp', 0)
            parsed = urlparse(url)
            domain = parsed.netloc or ''

            # Skip allowlisted (every extension pings google on nav)
            if _is_allowlisted(domain):
                continue

            for nav_ts in self._navigation_timestamps:
                delta = ts - nav_ts
                if 0 < delta <= POST_NAV_WINDOW:
                    score, reasons = score_request(req)
                    if score >= SCORE_SUSPICIOUS:
                        post_nav.append({
                            'url': url,
                            'method': req.get('method', 'GET'),
                            'domain': domain,
                            'score': score,
                            'seconds_after_navigation': round(delta, 2),
                            'reasons': reasons,
                            'severity': 'HIGH' if score >= SCORE_HIGH else 'MEDIUM',
                        })
                    break  # Only count against closest navigation

        return post_nav

    def _is_known_saas_websocket(self, url, domain, path):
        """Check if a WebSocket URL matches a known SaaS pattern (Stage 2 fast exit)."""
        for saas_name, pattern in KNOWN_SAAS_WEBSOCKETS.items():
            # Check domain pattern
            if 'domain_pattern' in pattern and pattern['domain_pattern'].search(domain):
                return True, saas_name, pattern['description']
            # Check path pattern
            if 'path_pattern' in pattern and pattern['path_pattern'].search(path):
                return True, saas_name, pattern['description']
        return False, None, None

    def _score_websockets(self, ws_list):
        """Score WebSocket connections for suspicious patterns.

        Includes:
        - Known SaaS suppression (ActionCable, Firebase, Pusher, etc.)
        - Frame-aware scoring (0 frames sent = likely benign)
        - Payload inspection for credential exfil indicators
        """
        suspicious_ws = []

        for ws in ws_list:
            url = ws.get('url', '')
            parsed = urlparse(url)
            domain = parsed.netloc or ''
            path = parsed.path or ''
            reasons = []
            score = 0
            frames_sent = ws.get('frames_sent', [])
            frames_received = ws.get('frames_received', [])

            # --- Stage 1: Allowlist fast exit ---
            if _is_allowlisted(domain):
                continue

            # --- Stage 2: Known SaaS fast exit ---
            is_saas, saas_name, saas_desc = self._is_known_saas_websocket(url, domain, path)
            if is_saas:
                # Known SaaS with 0 frames sent = completely benign, skip
                if len(frames_sent) == 0:
                    continue
                # Known SaaS with frames sent but no credential indicators = skip
                has_cred_in_frames = any(
                    DETECTION_REGEX['CREDENTIAL_KEYS'].search(f) or
                    DETECTION_REGEX['JWT'].search(f)
                    for f in frames_sent
                )
                if not has_cred_in_frames:
                    continue
                # Known SaaS but sending credential-like data = still flag but note context
                reasons.append(f'Known SaaS ({saas_desc}) but sending credential-like data')
                score += 2

            # --- Stage 3: Frame-aware scoring ---
            # 0 frames sent = passive listener, likely benign
            if len(frames_sent) == 0:
                # Still check for suspicious routing indicators but with lower weight
                if DETECTION_REGEX['SUSPICIOUS_TLD'].search(url):
                    score += 1
                    reasons.append('Suspicious TLD (passive WebSocket)')
                if DETECTION_REGEX['IP_LITERAL'].search(url):
                    score += 2
                    reasons.append('Raw IP address (passive WebSocket)')
                if DETECTION_REGEX['DDNS'].search(url):
                    score += 2
                    reasons.append('DDNS domain (passive WebSocket)')
                # Passive WS to unknown domain is still mildly interesting
                if score > 0:
                    score = max(1, score - 1)  # Reduce by 1 for passive
                if score < SCORE_SUSPICIOUS:
                    continue

            # --- Stage 4: Active WebSocket scoring (frames_sent > 0) ---
            if len(frames_sent) > 0:
                score += 1  # Active outbound = baseline risk bump
                reasons.append(f'Active WebSocket ({len(frames_sent)} frames sent)')

            # Non-standard port
            port = parsed.port
            if port and port not in (80, 443, 8080, 8443):
                score += 2
                reasons.append(f'Non-standard port ({port})')

            # Suspicious TLD
            if DETECTION_REGEX['SUSPICIOUS_TLD'].search(url) and 'Suspicious TLD' not in str(reasons):
                score += 2
                reasons.append('Suspicious TLD')

            # DDNS
            if DETECTION_REGEX['DDNS'].search(url) and 'DDNS' not in str(reasons):
                score += 3
                reasons.append('DDNS domain')

            # IP literal
            if DETECTION_REGEX['IP_LITERAL'].search(url) and 'Raw IP' not in str(reasons):
                score += 3
                reasons.append('Raw IP address')

            # --- Stage 5: Payload inspection on sent frames ---
            for frame in frames_sent:
                if DETECTION_REGEX['BASE64_BLOB'].search(frame):
                    score += 3
                    reasons.append('Base64 blob in WebSocket frame')
                    break
                if DETECTION_REGEX['JWT'].search(frame):
                    score += 4
                    reasons.append('JWT token in WebSocket frame')
                    break
                if DETECTION_REGEX['CREDENTIAL_KEYS'].search(frame):
                    score += 3
                    reasons.append('Credential-like keys in WebSocket frame')
                    break

            if score >= SCORE_SUSPICIOUS:
                suspicious_ws.append({
                    'url': url,
                    'domain': domain,
                    'score': score,
                    'reasons': reasons,
                    'frames_sent_count': len(frames_sent),
                    'frames_received_count': len(frames_received),
                    'is_saas': is_saas if is_saas else False,
                    'saas_service': saas_name,
                    'severity': 'CRITICAL' if score >= SCORE_HIGH else 'HIGH',
                })

        return suspicious_ws

    # ------------------------------------------------------------------
    # Aggregated verdict
    # ------------------------------------------------------------------

    def _check_hard_escalation(self, scored, ws_suspicious):
        """
        Hard escalation: credential keywords + outbound network + non-allowlisted domain
        = immediate MALICIOUS regardless of aggregate score.

        This catches single high-confidence exfil events that might not meet
        the normal convergence thresholds.
        """
        for s in scored:
            domain = s.get('domain', '')
            reasons_str = ' '.join(s.get('reasons', []))
            has_cred = bool(DETECTION_REGEX['CREDENTIAL_KEYS'].search(
                (s.get('post_data') or '') + ' ' + s.get('url', '')
            ))
            has_jwt = bool(DETECTION_REGEX['JWT'].search(s.get('post_data') or ''))
            is_outbound = s.get('method') in ('POST', 'PUT', 'PATCH') and s.get('post_data')
            not_allowlisted = not _is_allowlisted(domain)

            if (has_cred or has_jwt) and is_outbound and not_allowlisted:
                return True, {
                    'trigger': 'credential_exfil',
                    'url': s.get('url', ''),
                    'domain': domain,
                    'reason': 'Credential/token data sent via POST to non-allowlisted domain',
                }

        # Check WebSocket frames for credential exfil to non-allowlisted domains
        for ws in ws_suspicious:
            domain = ws.get('domain', '')
            if _is_allowlisted(domain):
                continue
            frames = ws.get('frames_sent_count', 0)
            if frames > 0:
                reasons_str = ' '.join(ws.get('reasons', []))
                if 'credential' in reasons_str.lower() or 'JWT' in reasons_str:
                    return True, {
                        'trigger': 'ws_credential_exfil',
                        'url': ws.get('url', ''),
                        'domain': domain,
                        'reason': 'Credential/token data sent via WebSocket to non-allowlisted domain',
                    }

        return False, None

    def _compute_verdict(self, scored, beaconing, post_nav_exfil, ws_suspicious):
        """
        Compute overall verdict using aggregation, not single hits.

        Includes hard escalation triggers that bypass normal thresholds:
        - Credential keywords + outbound POST + non-allowlisted domain = MALICIOUS

        Returns: 'MALICIOUS', 'SUSPICIOUS', 'LOW_RISK', or 'CLEAN'
        """
        # --- Hard escalation check (overrides everything) ---
        hard_escalated, escalation_detail = self._check_hard_escalation(scored, ws_suspicious)
        if hard_escalated:
            return 'MALICIOUS'

        high_score_events = [s for s in scored if s['score'] >= SCORE_HIGH]
        has_beaconing = len(beaconing) > 0
        has_post_nav = len(post_nav_exfil) > 0
        has_ws_suspicious = len(ws_suspicious) > 0

        # MALICIOUS: multiple strong signals converge
        if (len(high_score_events) >= 2 and (has_beaconing or has_post_nav)):
            return 'MALICIOUS'
        if len(high_score_events) >= 3:
            return 'MALICIOUS'
        if has_beaconing and has_post_nav and len(scored) >= VERDICT_MIN_EVENTS:
            return 'MALICIOUS'

        # SUSPICIOUS: some signals but not convergent enough
        if len(scored) >= VERDICT_MIN_EVENTS and any(s['score'] >= SCORE_HIGH for s in scored):
            return 'SUSPICIOUS'
        if has_beaconing or has_post_nav:
            return 'SUSPICIOUS'
        if has_ws_suspicious:
            return 'SUSPICIOUS'
        if len(scored) >= VERDICT_MIN_EVENTS:
            return 'SUSPICIOUS'

        # LOW_RISK: a few hits but nothing alarming
        if len(scored) > 0:
            return 'LOW_RISK'

        return 'CLEAN'

    # ------------------------------------------------------------------
    # Domain extraction
    # ------------------------------------------------------------------

    def _extract_new_domains(self, extension_requests):
        """Extract unique domains from extension requests for VT checking."""
        domains = set()
        for req in extension_requests:
            url = req.get('url', '')
            if url.startswith('chrome-extension://'):
                continue
            parsed = urlparse(url)
            if parsed.netloc:
                domains.add(parsed.netloc)
        return list(domains)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _check_playwright_available(self):
        try:
            import playwright  # noqa: F401
            return True
        except ImportError:
            return False

    def _empty_summary(self):
        return {
            'total_requests': 0,
            'extension_requests': 0,
            'suspicious_count': 0,
            'high_score_count': 0,
            'data_exfil_detected': False,
            'beaconing_detected': False,
            'post_nav_exfil_detected': False,
            'websocket_count': 0,
            'websocket_suspicious': 0,
            'duration_seconds': 0,
            'trigger_pages_loaded': 0,
            'verdict': 'UNAVAILABLE',
        }

    def _cleanup(self):
        """Close browser and clean up temporary profile."""
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            pass
        try:
            if self._pw:
                self._pw.stop()
        except Exception:
            pass
        try:
            if self._temp_dir:
                shutil.rmtree(self._temp_dir, ignore_errors=True)
        except Exception:
            pass
        self._browser = None
        self._pw = None
        self._temp_dir = None
