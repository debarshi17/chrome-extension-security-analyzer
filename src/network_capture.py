"""
Dynamic Network Capture Analysis - Enhanced Edition
Uses Playwright + Chrome DevTools Protocol to monitor extension network behavior at runtime.

Enhanced detection capabilities based on 2025 academic research:
- DOM event injection detection (onreset/onerror code injection)
- CSP header removal detection
- Credential form monitoring
- Keylogger pattern detection
- Storage exfiltration correlation
- Screen capture and clipboard monitoring
- Overlay attack detection
- Remote config/bloom filter detection

Requires: pip install playwright && playwright install chromium
This module degrades gracefully if playwright is not installed.
"""

import time
import re
import tempfile
import shutil
import json
import hashlib
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

    # === ENHANCED DETECTION PATTERNS (2025 Research) ===

    # DOM Event Injection (Palant research - onreset/onerror code injection)
    'DOM_EVENT_HANDLER': re.compile(r'\b(onreset|onerror|onload|onmouseover|onfocus|onblur)\s*=', re.I),
    'DOM_INJECTION_TRIGGER': re.compile(r'\.(reset|click|focus|blur|dispatchEvent)\s*\(', re.I),

    # Keylogger patterns
    'KEYLOGGER_LISTENER': re.compile(r'addEventListener\s*\(\s*[\'"]key(down|up|press)[\'"]', re.I),
    'KEYLOGGER_ONKEY': re.compile(r'\b(onkeydown|onkeyup|onkeypress)\s*=', re.I),
    'KEYSTROKE_DATA': re.compile(r'(keyCode|charCode|which|key|code)\s*[:\]=]', re.I),

    # Form/Credential harvesting
    'PASSWORD_FIELD_ACCESS': re.compile(r'(input\[type=[\'"]?password|\.value|getElementById|querySelector).*password', re.I),
    'FORM_DATA_COLLECT': re.compile(r'(FormData|serializeArray|\.val\(\)|\.value)', re.I),
    'LOGIN_FORM_SELECTOR': re.compile(r'(login|signin|auth|credential|passwd)', re.I),

    # Storage exfiltration
    'STORAGE_ACCESS': re.compile(r'(localStorage|sessionStorage|indexedDB|chrome\.storage)\.(get|set|remove)', re.I),
    'COOKIE_ACCESS': re.compile(r'(document\.cookie|chrome\.cookies\.get)', re.I),

    # Screen capture / clipboard
    'SCREEN_CAPTURE': re.compile(r'(captureVisibleTab|desktopCapture|getDisplayMedia|mediaDevices)', re.I),
    'CLIPBOARD_ACCESS': re.compile(r'(navigator\.clipboard|execCommand\s*\(\s*[\'"]copy|ClipboardEvent)', re.I),

    # CSP manipulation
    'CSP_HEADER': re.compile(r'content-security-policy', re.I),
    'CSP_REMOVAL': re.compile(r'(removeHeader|modifyHeaders).*content-security-policy', re.I),

    # Remote config / delayed activation
    'REMOTE_CONFIG': re.compile(r'(config|settings|rules|checklist|bff)\.(json|bin)', re.I),
    'BLOOM_FILTER': re.compile(r'(bloom|filter|hash|sha256|sha-256)', re.I),
    'DELAYED_EVAL': re.compile(r'(setTimeout|setInterval)\s*\([^,]+,\s*\d{5,}', re.I),  # 10+ second delays

    # Overlay attacks (DOM clickjacking)
    'OPACITY_ZERO': re.compile(r'opacity\s*[:\=]\s*0([^.]|$)', re.I),
    'INVISIBLE_ELEMENT': re.compile(r'(visibility\s*:\s*hidden|display\s*:\s*none|position\s*:\s*absolute.*-\d{4,})', re.I),
    'FULLSCREEN_OVERLAY': re.compile(r'(position\s*:\s*fixed|z-index\s*:\s*\d{5,}|100vw|100vh)', re.I),
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
    """
    Captures and analyzes network traffic from a Chrome extension at runtime.

    Enhanced detection capabilities (2025 research-based):
    - DOM event injection (onreset/onerror code execution)
    - CSP header removal detection
    - Credential form monitoring
    - Keylogger pattern detection
    - Storage exfiltration correlation
    - Screen capture and clipboard monitoring
    - Overlay attack detection
    - Remote config/bloom filter detection
    """

    def __init__(self, trigger_urls=None):
        self.trigger_urls = trigger_urls or DEFAULT_TRIGGER_URLS
        self._captured_requests = []
        self._websocket_connections = {}
        self._navigation_timestamps = []  # Track when pages load
        self._pw = None
        self._browser = None
        self._temp_dir = None

        # === ENHANCED DETECTION DATA STRUCTURES ===

        # DOM manipulation tracking
        self._dom_mutations = []          # DOM attribute changes (onreset, onerror injection)
        self._script_evaluations = []     # Runtime.evaluate calls

        # Keyboard/input monitoring
        self._keyboard_listeners = []     # Detected keydown/keyup listeners
        self._input_access = []           # Password field / form access

        # Storage access tracking
        self._storage_access = []         # localStorage/sessionStorage/chrome.storage
        self._cookie_access = []          # Cookie read/write events

        # Response header tracking (CSP removal)
        self._response_headers = {}       # URL -> headers mapping
        self._csp_removals = []           # Detected CSP header removals

        # Screen/clipboard monitoring
        self._screen_captures = []        # captureVisibleTab calls
        self._clipboard_access = []       # Clipboard API usage

        # Remote config detection
        self._config_downloads = []       # JSON/binary config file downloads
        self._large_storage_writes = []   # Large blob writes to extension storage

        # Console messages (for detecting eval/injection)
        self._console_messages = []

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

        # Reset enhanced detection data structures
        self._dom_mutations = []
        self._script_evaluations = []
        self._keyboard_listeners = []
        self._input_access = []
        self._storage_access = []
        self._cookie_access = []
        self._response_headers = {}
        self._csp_removals = []
        self._screen_captures = []
        self._clipboard_access = []
        self._config_downloads = []
        self._large_storage_writes = []
        self._console_messages = []

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
                'summary': self._empty_summary(),
                'enhanced_detection': {
                    'findings': [],
                    'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}
                }
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

            # === ENHANCED DETECTION ANALYSIS ===
            enhanced_detection = self._get_enhanced_detection_summary()
            enhanced_summary = enhanced_detection.get('summary', {})

            # Check hard escalation first (for reporting)
            hard_escalated, escalation_detail = self._check_hard_escalation(scored, ws_suspicious)

            # Aggregate verdict (now includes enhanced detection)
            verdict = self._compute_verdict(
                scored, beaconing, post_nav_exfil, ws_suspicious,
                enhanced=enhanced_detection
            )

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
                # Enhanced detection summary
                'enhanced_detection': {
                    'total_findings': enhanced_summary.get('total', 0),
                    'critical': enhanced_summary.get('critical', 0),
                    'high': enhanced_summary.get('high', 0),
                    'medium': enhanced_summary.get('medium', 0),
                    'dom_injection_detected': len(enhanced_detection.get('dom_injection', [])) > 0,
                    'csp_removal_detected': len(enhanced_detection.get('csp_removal', [])) > 0,
                    'keylogger_detected': len(enhanced_detection.get('keylogger', [])) > 0,
                    'credential_harvesting_detected': len(enhanced_detection.get('credential_harvesting', [])) > 0,
                    'storage_exfil_detected': len(enhanced_detection.get('storage_exfiltration', [])) > 0,
                    'screen_capture_detected': len(enhanced_detection.get('screen_clipboard', [])) > 0,
                },
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
                # Enhanced detection details
                'enhanced_detection': enhanced_detection,
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
                'summary': self._empty_summary(),
                'enhanced_detection': {
                    'findings': [],
                    'summary': {'total': 0, 'critical': 0, 'high': 0, 'medium': 0}
                }
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
        """Attach Chrome DevTools Protocol network listeners to a page.

        Enhanced with additional listeners for:
        - Response headers (CSP removal detection)
        - Console API (eval/injection detection)
        - Script execution (keylogger/DOM injection detection)
        """
        try:
            client = page.context.new_cdp_session(page)

            # Enable required CDP domains
            client.send('Network.enable')
            client.send('Runtime.enable')
            client.send('Log.enable')

            # Network event handlers
            client.on('Network.requestWillBeSent', self._on_request)
            client.on('Network.responseReceived', self._on_response)  # CSP detection
            client.on('Network.webSocketCreated', self._on_ws_created)
            client.on('Network.webSocketFrameSent', self._on_ws_frame_sent)
            client.on('Network.webSocketFrameReceived', self._on_ws_frame_received)

            # Runtime/console handlers for injection detection
            client.on('Runtime.consoleAPICalled', self._on_console)
            client.on('Runtime.exceptionThrown', self._on_exception)

            # Log handler for additional context
            client.on('Log.entryAdded', self._on_log_entry)

            # Store client reference for script injection
            self._current_cdp_client = client

        except Exception as e:
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

    # === ENHANCED CDP EVENT HANDLERS ===

    def _on_response(self, params):
        """Track response headers for CSP removal detection."""
        response = params.get('response', {})
        url = response.get('url', '')
        headers = response.get('headers', {})
        request_id = params.get('requestId', '')

        # Store headers for analysis
        self._response_headers[request_id] = {
            'url': url,
            'headers': headers,
            'timestamp': time.time()
        }

        # Check for CSP header presence/absence on HTML pages
        content_type = headers.get('content-type', headers.get('Content-Type', ''))
        if 'text/html' in content_type.lower():
            has_csp = any(
                'content-security-policy' in k.lower()
                for k in headers.keys()
            )
            if not has_csp:
                # Page loaded without CSP - could be removed by extension
                self._csp_removals.append({
                    'url': url,
                    'request_id': request_id,
                    'timestamp': time.time(),
                    'reason': 'HTML page loaded without CSP header'
                })

    def _on_console(self, params):
        """Track console API calls for eval/injection detection."""
        call_type = params.get('type', '')
        args = params.get('args', [])
        stack = params.get('stackTrace', {})

        message_parts = []
        for arg in args:
            if arg.get('type') == 'string':
                message_parts.append(arg.get('value', ''))

        message = ' '.join(message_parts)

        self._console_messages.append({
            'type': call_type,
            'message': message[:500],
            'stack': stack,
            'timestamp': time.time()
        })

        # Check for keylogger patterns in console output
        if DETECTION_REGEX['KEYSTROKE_DATA'].search(message):
            self._keyboard_listeners.append({
                'type': 'console_keystroke_data',
                'message': message[:200],
                'severity': 'HIGH',
                'timestamp': time.time()
            })

        # Check for credential patterns
        if DETECTION_REGEX['CREDENTIAL_KEYS'].search(message):
            self._input_access.append({
                'type': 'console_credential_data',
                'message': message[:200],
                'severity': 'CRITICAL',
                'timestamp': time.time()
            })

    def _on_exception(self, params):
        """Track runtime exceptions (may reveal injection attempts)."""
        details = params.get('exceptionDetails', {})
        exception = details.get('exception', {})
        description = exception.get('description', '')

        # onerror/onreset injection attempts may throw
        if 'reset' in description.lower() or 'event' in description.lower():
            self._dom_mutations.append({
                'type': 'exception_during_event',
                'description': description[:200],
                'timestamp': time.time()
            })

    def _on_log_entry(self, params):
        """Track log entries for additional context."""
        entry = params.get('entry', {})
        text = entry.get('text', '')
        source = entry.get('source', '')
        level = entry.get('level', '')
        url = entry.get('url', '')

        # Detect extension-initiated script injection
        if 'chrome-extension://' in url:
            # Check for DOM event handler patterns
            if DETECTION_REGEX['DOM_EVENT_HANDLER'].search(text):
                self._dom_mutations.append({
                    'type': 'dom_event_injection',
                    'text': text[:200],
                    'url': url,
                    'severity': 'CRITICAL',
                    'timestamp': time.time()
                })

            # Check for keylogger patterns
            if DETECTION_REGEX['KEYLOGGER_LISTENER'].search(text):
                self._keyboard_listeners.append({
                    'type': 'keylogger_listener_detected',
                    'text': text[:200],
                    'url': url,
                    'severity': 'CRITICAL',
                    'timestamp': time.time()
                })

            # Check for clipboard access
            if DETECTION_REGEX['CLIPBOARD_ACCESS'].search(text):
                self._clipboard_access.append({
                    'type': 'clipboard_access_detected',
                    'text': text[:200],
                    'url': url,
                    'severity': 'HIGH',
                    'timestamp': time.time()
                })

            # Check for screen capture
            if DETECTION_REGEX['SCREEN_CAPTURE'].search(text):
                self._screen_captures.append({
                    'type': 'screen_capture_detected',
                    'text': text[:200],
                    'url': url,
                    'severity': 'CRITICAL',
                    'timestamp': time.time()
                })

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

    def _compute_verdict(self, scored, beaconing, post_nav_exfil, ws_suspicious, enhanced=None):
        """
        Compute overall verdict using aggregation, not single hits.

        Includes hard escalation triggers that bypass normal thresholds:
        - Credential keywords + outbound POST + non-allowlisted domain = MALICIOUS
        - Enhanced detection: keylogger, DOM injection, CSP removal = MALICIOUS

        Returns: 'MALICIOUS', 'SUSPICIOUS', 'LOW_RISK', or 'CLEAN'
        """
        # --- Hard escalation check (overrides everything) ---
        hard_escalated, escalation_detail = self._check_hard_escalation(scored, ws_suspicious)
        if hard_escalated:
            return 'MALICIOUS'

        # --- Enhanced detection escalation ---
        if enhanced:
            summary = enhanced.get('summary', {})
            critical_count = summary.get('critical', 0)
            high_count = summary.get('high', 0)

            # Any critical finding = MALICIOUS
            if critical_count > 0:
                return 'MALICIOUS'

            # Multiple high findings = MALICIOUS
            if high_count >= 2:
                return 'MALICIOUS'

            # DOM injection or keylogger detected = MALICIOUS
            if enhanced.get('dom_injection') or enhanced.get('keylogger'):
                return 'MALICIOUS'

            # CSP removal detected = SUSPICIOUS (could be legit ad blocker)
            if enhanced.get('csp_removal'):
                # Escalate to MALICIOUS if combined with other signals
                if len(scored) >= 2 or beaconing or post_nav_exfil:
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

        # Enhanced detection: any high finding = SUSPICIOUS
        if enhanced and enhanced.get('summary', {}).get('high', 0) > 0:
            return 'SUSPICIOUS'

        # LOW_RISK: a few hits but nothing alarming
        if len(scored) > 0:
            return 'LOW_RISK'

        # Enhanced detection: any medium finding = LOW_RISK
        if enhanced and enhanced.get('summary', {}).get('medium', 0) > 0:
            return 'LOW_RISK'

        return 'CLEAN'

    # ==================================================================
    # ENHANCED DETECTION ANALYSIS FUNCTIONS (2025 Research-based)
    # ==================================================================

    def _analyze_dom_injection(self):
        """
        Detect DOM event injection attacks (onreset/onerror code execution).

        Based on Palant's 2025 research: malware writes code to DOM event handlers
        like onreset, then triggers the event to execute arbitrary JavaScript.
        """
        findings = []

        for mutation in self._dom_mutations:
            if mutation.get('type') == 'dom_event_injection':
                findings.append({
                    'type': 'DOM_EVENT_INJECTION',
                    'severity': 'CRITICAL',
                    'description': 'Extension injects code via DOM event handlers (onreset/onerror)',
                    'details': mutation.get('text', '')[:200],
                    'url': mutation.get('url', ''),
                    'timestamp': mutation.get('timestamp'),
                    'research_ref': 'Palant 2025 - Advanced malicious Chrome extension analysis'
                })

        # Also check captured requests for DOM injection patterns in POST data
        for req in self._captured_requests:
            post_data = req.get('post_data', '') or ''
            if DETECTION_REGEX['DOM_EVENT_HANDLER'].search(post_data):
                if DETECTION_REGEX['DOM_INJECTION_TRIGGER'].search(post_data):
                    findings.append({
                        'type': 'DOM_INJECTION_PAYLOAD',
                        'severity': 'CRITICAL',
                        'description': 'Network request contains DOM event injection payload',
                        'url': req.get('url', ''),
                        'timestamp': req.get('timestamp')
                    })

        return findings

    def _analyze_csp_removal(self):
        """
        Detect CSP header removal via declarativeNetRequest.

        Extensions can use declarativeNetRequest to strip Content-Security-Policy
        headers, enabling script injection on protected pages.
        """
        findings = []

        # Check for pages without CSP that should have it
        for removal in self._csp_removals:
            url = removal.get('url', '')
            parsed = urlparse(url)
            domain = parsed.netloc or ''

            # High-value targets that should have CSP
            high_value_domains = [
                'google.com', 'facebook.com', 'amazon.com', 'github.com',
                'microsoft.com', 'apple.com', 'twitter.com', 'linkedin.com'
            ]

            is_high_value = any(hv in domain.lower() for hv in high_value_domains)

            if is_high_value:
                findings.append({
                    'type': 'CSP_REMOVED',
                    'severity': 'CRITICAL',
                    'description': f'High-value site loaded without CSP (likely removed by extension)',
                    'url': url,
                    'domain': domain,
                    'timestamp': removal.get('timestamp'),
                    'research_ref': 'Extension removes CSP to enable script injection'
                })

        return findings

    def _analyze_keylogger_patterns(self):
        """
        Detect keylogger behavior patterns.

        Monitors for:
        - keydown/keyup/keypress event listeners
        - Keystroke data in outbound traffic
        - Console output containing key data
        """
        findings = []

        # Check detected keyboard listeners
        for listener in self._keyboard_listeners:
            findings.append({
                'type': 'KEYLOGGER_DETECTED',
                'severity': listener.get('severity', 'CRITICAL'),
                'description': f"Keyboard event listener detected: {listener.get('type')}",
                'details': listener.get('text', listener.get('message', ''))[:200],
                'timestamp': listener.get('timestamp'),
                'research_ref': 'LayerX 2025 - Keylogger extension analysis'
            })

        # Check outbound requests for keystroke data
        for req in self._captured_requests:
            post_data = req.get('post_data', '') or ''
            url = req.get('url', '')

            if url.startswith('chrome-extension://'):
                continue

            # Check for keystroke patterns in POST data
            if DETECTION_REGEX['KEYSTROKE_DATA'].search(post_data):
                parsed = urlparse(url)
                domain = parsed.netloc or ''

                if not _is_allowlisted(domain):
                    findings.append({
                        'type': 'KEYSTROKE_EXFIL',
                        'severity': 'CRITICAL',
                        'description': 'Keystroke data detected in outbound request',
                        'url': url,
                        'domain': domain,
                        'post_data_preview': post_data[:100],
                        'timestamp': req.get('timestamp')
                    })

        return findings

    def _analyze_credential_harvesting(self):
        """
        Detect credential/form field harvesting.

        Monitors for:
        - Password field value access
        - Form data collection and exfiltration
        - Login form targeting
        """
        findings = []

        # Check detected input access
        for access in self._input_access:
            findings.append({
                'type': 'CREDENTIAL_ACCESS',
                'severity': access.get('severity', 'CRITICAL'),
                'description': f"Credential/form data access detected: {access.get('type')}",
                'details': access.get('message', '')[:200],
                'timestamp': access.get('timestamp')
            })

        # Check outbound requests for credential patterns
        for req in self._captured_requests:
            post_data = req.get('post_data', '') or ''
            url = req.get('url', '')

            if url.startswith('chrome-extension://'):
                continue

            # Check for password/credential data in POST
            if DETECTION_REGEX['PASSWORD_FIELD_ACCESS'].search(post_data):
                parsed = urlparse(url)
                domain = parsed.netloc or ''

                if not _is_allowlisted(domain):
                    findings.append({
                        'type': 'CREDENTIAL_EXFIL',
                        'severity': 'CRITICAL',
                        'description': 'Password/credential data in outbound request',
                        'url': url,
                        'domain': domain,
                        'timestamp': req.get('timestamp')
                    })

            # Check for form data collection
            if DETECTION_REGEX['FORM_DATA_COLLECT'].search(post_data):
                if DETECTION_REGEX['LOGIN_FORM_SELECTOR'].search(post_data):
                    parsed = urlparse(url)
                    domain = parsed.netloc or ''

                    if not _is_allowlisted(domain):
                        findings.append({
                            'type': 'LOGIN_FORM_HARVESTING',
                            'severity': 'HIGH',
                            'description': 'Login form data collection detected',
                            'url': url,
                            'domain': domain,
                            'timestamp': req.get('timestamp')
                        })

        return findings

    def _analyze_storage_exfiltration(self):
        """
        Detect storage data exfiltration.

        Correlates storage access (localStorage/sessionStorage/chrome.storage)
        with outbound network requests.
        """
        findings = []

        # Check for storage access patterns in outbound requests
        for req in self._captured_requests:
            post_data = req.get('post_data', '') or ''
            url = req.get('url', '')

            if url.startswith('chrome-extension://'):
                continue

            # Large POST with storage-like data
            if len(post_data) > 500:
                # Check if contains storage patterns
                has_storage_pattern = (
                    DETECTION_REGEX['STORAGE_ACCESS'].search(post_data) or
                    DETECTION_REGEX['COOKIE_ACCESS'].search(post_data) or
                    # Large JSON object (likely storage dump)
                    (post_data.startswith('{') and post_data.count(':') > 5)
                )

                if has_storage_pattern:
                    parsed = urlparse(url)
                    domain = parsed.netloc or ''

                    if not _is_allowlisted(domain):
                        findings.append({
                            'type': 'STORAGE_EXFIL',
                            'severity': 'HIGH',
                            'description': 'Large storage-like data in outbound request',
                            'url': url,
                            'domain': domain,
                            'data_size': len(post_data),
                            'timestamp': req.get('timestamp')
                        })

        # Check cookie access
        for access in self._cookie_access:
            findings.append({
                'type': 'COOKIE_ACCESS',
                'severity': 'HIGH',
                'description': f"Cookie access detected: {access.get('type')}",
                'timestamp': access.get('timestamp')
            })

        return findings

    def _analyze_screen_clipboard(self):
        """
        Detect screen capture and clipboard access.

        Monitors for:
        - chrome.tabs.captureVisibleTab usage
        - desktopCapture API
        - navigator.clipboard access
        """
        findings = []

        # Screen captures
        for capture in self._screen_captures:
            findings.append({
                'type': 'SCREEN_CAPTURE',
                'severity': 'CRITICAL',
                'description': f"Screen capture detected: {capture.get('type')}",
                'details': capture.get('text', '')[:200],
                'url': capture.get('url', ''),
                'timestamp': capture.get('timestamp')
            })

        # Clipboard access
        for access in self._clipboard_access:
            findings.append({
                'type': 'CLIPBOARD_ACCESS',
                'severity': 'HIGH',
                'description': f"Clipboard access detected: {access.get('type')}",
                'details': access.get('text', '')[:200],
                'url': access.get('url', ''),
                'timestamp': access.get('timestamp')
            })

        # Check for clipboard data in outbound requests
        for req in self._captured_requests:
            post_data = req.get('post_data', '') or ''
            url = req.get('url', '')

            if url.startswith('chrome-extension://'):
                continue

            if DETECTION_REGEX['CLIPBOARD_ACCESS'].search(post_data):
                parsed = urlparse(url)
                domain = parsed.netloc or ''

                if not _is_allowlisted(domain):
                    findings.append({
                        'type': 'CLIPBOARD_EXFIL',
                        'severity': 'HIGH',
                        'description': 'Clipboard data in outbound request',
                        'url': url,
                        'domain': domain,
                        'timestamp': req.get('timestamp')
                    })

        return findings

    def _analyze_remote_config(self):
        """
        Detect remote configuration / bloom filter downloads.

        Malware often downloads decision logic (bloom filters, config files)
        from remote servers to control activation.
        """
        findings = []

        # Check for config file downloads
        for req in self._captured_requests:
            url = req.get('url', '')
            resource_type = req.get('resource_type', '')

            if url.startswith('chrome-extension://'):
                continue

            parsed = urlparse(url)
            path = parsed.path.lower()

            # Config file patterns
            if DETECTION_REGEX['REMOTE_CONFIG'].search(path):
                findings.append({
                    'type': 'REMOTE_CONFIG_DOWNLOAD',
                    'severity': 'MEDIUM',
                    'description': 'Extension downloads remote configuration file',
                    'url': url,
                    'timestamp': req.get('timestamp'),
                    'research_ref': 'Palant 2025 - Bloom filter activation mechanism'
                })

            # Binary/blob downloads (potential bloom filters)
            if resource_type in ('Fetch', 'XHR', 'Other'):
                if '.bin' in path or '.dat' in path:
                    findings.append({
                        'type': 'BINARY_CONFIG_DOWNLOAD',
                        'severity': 'MEDIUM',
                        'description': 'Extension downloads binary data (possible bloom filter)',
                        'url': url,
                        'timestamp': req.get('timestamp')
                    })

        # Check for large storage writes (bloom filter storage)
        for write in self._large_storage_writes:
            findings.append({
                'type': 'LARGE_STORAGE_WRITE',
                'severity': 'MEDIUM',
                'description': f"Large data written to extension storage ({write.get('size')} bytes)",
                'timestamp': write.get('timestamp')
            })

        return findings

    def _analyze_overlay_attacks(self):
        """
        Detect overlay/clickjacking attacks.

        Based on DOM-based Extension Clickjacking research (2025):
        - Invisible elements (opacity: 0) receiving focus
        - Fullscreen overlays
        - Off-screen positioned elements
        """
        findings = []

        # Check console messages for overlay patterns
        for msg in self._console_messages:
            text = msg.get('message', '')

            if DETECTION_REGEX['OPACITY_ZERO'].search(text):
                findings.append({
                    'type': 'INVISIBLE_ELEMENT',
                    'severity': 'HIGH',
                    'description': 'Invisible element detected (opacity: 0)',
                    'details': text[:200],
                    'timestamp': msg.get('timestamp'),
                    'research_ref': 'DOM-based Extension Clickjacking 2025'
                })

            if DETECTION_REGEX['FULLSCREEN_OVERLAY'].search(text):
                findings.append({
                    'type': 'FULLSCREEN_OVERLAY',
                    'severity': 'MEDIUM',
                    'description': 'Fullscreen overlay element detected',
                    'details': text[:200],
                    'timestamp': msg.get('timestamp')
                })

        return findings

    def _get_enhanced_detection_summary(self):
        """Aggregate all enhanced detection findings."""
        dom_injection = self._analyze_dom_injection()
        csp_removal = self._analyze_csp_removal()
        keylogger = self._analyze_keylogger_patterns()
        credential = self._analyze_credential_harvesting()
        storage = self._analyze_storage_exfiltration()
        screen_clip = self._analyze_screen_clipboard()
        remote_cfg = self._analyze_remote_config()
        overlay = self._analyze_overlay_attacks()

        all_findings = (
            dom_injection + csp_removal + keylogger + credential +
            storage + screen_clip + remote_cfg + overlay
        )

        # Categorize by severity
        critical = [f for f in all_findings if f.get('severity') == 'CRITICAL']
        high = [f for f in all_findings if f.get('severity') == 'HIGH']
        medium = [f for f in all_findings if f.get('severity') == 'MEDIUM']

        return {
            'findings': all_findings,
            'dom_injection': dom_injection,
            'csp_removal': csp_removal,
            'keylogger': keylogger,
            'credential_harvesting': credential,
            'storage_exfiltration': storage,
            'screen_clipboard': screen_clip,
            'remote_config': remote_cfg,
            'overlay_attacks': overlay,
            'summary': {
                'total': len(all_findings),
                'critical': len(critical),
                'high': len(high),
                'medium': len(medium)
            }
        }

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
            # Enhanced detection fields
            'enhanced_detection': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'dom_injection_detected': False,
                'csp_removal_detected': False,
                'keylogger_detected': False,
                'credential_harvesting_detected': False,
                'storage_exfil_detected': False,
                'screen_capture_detected': False,
            },
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
