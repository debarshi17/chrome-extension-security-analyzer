"""
False Positive Suppression
Filters out known benign patterns that should not trigger malware alerts
"""

import re


class FalsePositiveFilter:
    """Suppress common false positives in extension analysis"""

    # Known benign domains that should never be flagged
    BENIGN_DOMAINS = {
        # Google services
        'googleapis.com', 'google.com', 'gstatic.com', 'googleusercontent.com',
        'accounts.google.com', 'chrome.google.com',
        'fonts.googleapis.com', 'fonts.gstatic.com',

        # Firebase (commonly flagged due to abuse by other apps)
        'firebaseio.com', 'firebase.google.com', 'firebasestorage.googleapis.com',
        'firebaseapp.com',

        # CDNs / cloud infrastructure
        'cloudflare.com', 'cloudflareinsights.com', 'cdnjs.cloudflare.com',
        'jsdelivr.net', 'unpkg.com', 'cdn.jsdelivr.net',
        'akamai.net', 'fastly.net',
        'cloudfront.net', 's3.amazonaws.com',
        'azurewebsites.net', 'blob.core.windows.net',
        'herokuapp.com', 'vercel.app', 'netlify.app', 'pages.dev',

        # Common libraries
        'jquery.com', 'jquerycdn.com',

        # Analytics (benign tracking)
        'google-analytics.com', 'googletagmanager.com', 'analytics.google.com',
        'mixpanel.com', 'amplitude.com', 'segment.com',

        # Payment processors
        'stripe.com', 'paypal.com', 'braintreepayments.com',

        # Dev tools / registries
        'github.com', 'githubusercontent.com', 'gitlab.com',
        'npmjs.org', 'npmjs.com', 'registry.npmjs.org', 'yarnpkg.com',
        'stackoverflow.com', 'developer.mozilla.org', 'w3.org',

        # Browser vendors
        'mozilla.org', 'microsoft.com', 'apple.com',

        # Auth / identity providers
        'okta.com', 'auth0.com', 'onelogin.com', 'duo.com',

        # Error tracking / monitoring
        'sentry.io', 'sentry-cdn.com', 'bugsnag.com',
        'datadog.com', 'datadoghq.com', 'newrelic.com',
        'rollbar.com', 'logrocket.com',

        # Fonts / resources
        'use.typekit.net', 'use.fontawesome.com',

        # SaaS (not exfil destinations)
        'intercom.io', 'zendesk.com', 'hubspot.com',
        'salesforce.com', 'shopify.com',

        # Social / content
        'reddit.com', 'medium.com', 'wikipedia.org',
        'gravatar.com', 'wp.com',

        # RFC 2606 reserved (documentation/examples — never malicious)
        'example.com', 'example.org', 'example.net', 'example.edu', 'example.mil', 'example.int',
    }

    # Known benign libraries/patterns
    BENIGN_LIBRARY_PATTERNS = [
        # jQuery and related
        r'jquery[-.][\d\.]+\.js',
        r'jquery\.min\.js',
        r'sizzle\.js',  # jQuery selector engine - NOT DGA!
        r'lodash\.js',
        r'underscore\.js',

        # React/Vue/Angular
        r'react[-.][\d\.]+\.js',
        r'vue[-.][\d\.]+\.js',
        r'angular[-.][\d\.]+\.js',

        # lit-html / Polymer / LitElement
        r'lit-html',
        r'lit-element',
        r'polymer',
        r'\$lit\$',
        r'\{\{lit-',

        # Other frameworks
        r'svelte',
        r'preact',
        r'ember',
        r'backbone',
        r'handlebars',

        # Common UI libraries
        r'bootstrap[-.][\d\.]+\.js',
        r'fontawesome',
        r'material-ui',

        # Polyfills
        r'polyfill\.js',
        r'babel-polyfill',

        # Analytics
        r'google-analytics\.com/analytics\.js',
        r'ga\.js'
    ]

    # Benign Chrome API usage patterns
    BENIGN_API_USAGE = {
        'storage': 'Used for preferences and settings',
        'tabs': 'May be legitimate for UI shortcuts or tab management',
        'alarms': 'Used for scheduled tasks (reminders, updates)',
        'runtime.onInstalled': 'Standard initialization event',
        'contextMenus': 'Adds menu items to right-click menu',
        'notifications': 'Displays notifications to user'
    }

    # Benign timeout patterns (< 60 seconds is typically legitimate)
    BENIGN_TIMEOUT_MAX = 60000  # 60 seconds in milliseconds

    def __init__(self):
        """Initialize false positive filter"""
        pass

    def is_benign_domain(self, domain):
        """
        Check if domain is known benign

        Args:
            domain: Domain name to check

        Returns:
            tuple: (is_benign, reason)
        """
        if domain is None or not isinstance(domain, str):
            return False, None
        domain_lower = domain.strip().lower()
        if not domain_lower:
            return False, None

        # Check exact matches
        if domain_lower in self.BENIGN_DOMAINS:
            return True, f'Known benign domain ({domain})'

        # Check subdomain matches
        for benign_domain in self.BENIGN_DOMAINS:
            if domain_lower.endswith('.' + benign_domain) or domain_lower == benign_domain:
                return True, f'Subdomain of known benign service ({benign_domain})'

        return False, None

    def is_benign_library(self, filename_or_url):
        """
        Check if file is a known benign library

        Args:
            filename_or_url: Filename or URL to check

        Returns:
            tuple: (is_benign, library_name)
        """
        filename_lower = filename_or_url.lower()

        for pattern in self.BENIGN_LIBRARY_PATTERNS:
            if re.search(pattern, filename_lower):
                return True, pattern

        return False, None

    def is_benign_timeout(self, timeout_ms):
        """
        Check if timeout duration is benign

        Args:
            timeout_ms: Timeout in milliseconds

        Returns:
            tuple: (is_benign, reason)
        """
        try:
            timeout_value = int(timeout_ms)

            if timeout_value <= self.BENIGN_TIMEOUT_MAX:
                return True, f'Short timeout ({timeout_value}ms) - likely legitimate'

            return False, None
        except:
            return False, None

    def is_firebase_domain(self, domain):
        """
        Specifically check if domain is Firebase

        Firebase domains are VERY commonly flagged as malicious due to abuse
        by other applications, but presence alone is not evidence of malware

        Args:
            domain: Domain to check

        Returns:
            tuple: (is_firebase, warning_message)
        """
        firebase_indicators = [
            'firebaseio.com',
            'firebase.google.com',
            'firebasestorage.googleapis.com',
            'firebaseapp.com'
        ]

        domain_lower = domain.lower()

        for indicator in firebase_indicators:
            if indicator in domain_lower:
                return True, (
                    'Firebase domain detected. Firebase is commonly flagged by security '
                    'vendors due to abuse by other applications. Presence alone does not '
                    'indicate malicious behavior. Review actual data being transmitted.'
                )

        return False, None

    def filter_virustotal_results(self, vt_results):
        """
        Filter VirusTotal results to suppress false positives

        Args:
            vt_results: List of VirusTotal domain results

        Returns:
            dict: Filtered results with suppressed false positives
        """
        filtered = []
        suppressed = []

        for result in vt_results:
            domain = (result.get('domain') or '').strip()

            # Check if benign
            is_benign, reason = self.is_benign_domain(domain)

            if is_benign:
                suppressed.append({
                    'domain': domain,
                    'reason': reason,
                    'original_threat_level': result.get('threat_level'),
                    'vt_detections': result.get('stats', {}).get('malicious', 0)
                })
            else:
                # Check if Firebase
                is_firebase, firebase_warning = self.is_firebase_domain(domain)

                if is_firebase:
                    # Keep result but add context
                    result['firebase_domain'] = True
                    result['context_warning'] = firebase_warning
                    # Downgrade threat level if only low detection count
                    if result.get('stats', {}).get('malicious', 0) < 3:
                        result['original_threat_level'] = result.get('threat_level')
                        result['threat_level'] = 'SUSPICIOUS_FALSE_POSITIVE_LIKELY'

                filtered.append(result)

        return {
            'filtered_results': filtered,
            'suppressed_false_positives': suppressed,
            'suppression_count': len(suppressed)
        }

    def filter_malicious_patterns(self, patterns, context=None):
        """
        Filter malicious code patterns to remove false positives

        Args:
            patterns: List of detected malicious patterns
            context: Optional dict with analysis context (e.g. {'uses_firebase': True})

        Returns:
            dict: Filtered patterns
        """
        filtered = []
        suppressed = []
        context = context or {}
        uses_firebase = context.get('uses_firebase', False)

        for pattern in patterns:
            pattern_name = pattern.get('name', '')
            evidence = pattern.get('evidence', '')
            severity = pattern.get('severity', '')

            # Check if evidence contains benign library
            is_benign, library_name = self.is_benign_library(evidence)

            if is_benign:
                suppressed.append({
                    'pattern': pattern_name,
                    'reason': f'Benign library detected: {library_name}',
                    'evidence': evidence[:100]
                })
                continue

            # Firebase context: downgrade patterns that are weak when
            # the only backend is Firebase (legitimate infrastructure)
            if uses_firebase and severity in ('high', 'critical'):
                technique = pattern.get('technique', '')
                # These patterns over-fire when Firebase is the data destination
                # because Firebase config contains 'authDomain' which matches auth patterns
                if technique in ('URL-conditional activation', 'DOM monitoring near sensitive fields'):
                    pattern = dict(pattern)  # don't mutate original
                    pattern['severity'] = 'low'
                    pattern['fp_note'] = (
                        'Downgraded: extension uses Firebase as backend. '
                        'Firebase config contains authDomain which can trigger '
                        'auth-related heuristics. Verify actual behavior.'
                    )

            filtered.append(pattern)

        return {
            'filtered_patterns': filtered,
            'suppressed_patterns': suppressed,
            'suppression_count': len(suppressed)
        }


def test_false_positive_filter():
    """Test false positive filter"""
    print("=" * 80)
    print("FALSE POSITIVE FILTER TEST")
    print("=" * 80)

    filter = FalsePositiveFilter()

    # Test benign domains
    print("\n1. Testing Benign Domain Detection:")
    print("-" * 80)

    test_domains = [
        'api.firebase.google.com',
        'cdn.jsdelivr.net',
        'jquery.com',
        'malicious-test.top',
        'zoomcorder.firebaseio.com',  # From your report
        'google-analytics.com'
    ]

    for domain in test_domains:
        is_benign, reason = filter.is_benign_domain(domain)
        status = "[BENIGN]" if is_benign else "[CHECK]"
        print(f"{status} {domain}")
        if reason:
            print(f"         Reason: {reason}")

    # Test Firebase detection
    print("\n2. Testing Firebase Detection:")
    print("-" * 80)

    firebase_domains = [
        'app.firebaseio.com',
        'zoomcorder.firebaseio.com',
        'malicious.top'
    ]

    for domain in firebase_domains:
        is_firebase, warning = filter.is_firebase_domain(domain)
        if is_firebase:
            print(f"[FIREBASE] {domain}")
            print(f"           {warning}")
        else:
            print(f"[NOT FIREBASE] {domain}")

    # Test library detection
    print("\n3. Testing Benign Library Detection:")
    print("-" * 80)

    test_files = [
        'jquery-3.6.0.min.js',
        'sizzle.js',  # Should NOT be flagged as DGA!
        'react-17.0.2.js',
        'malicious-script.js'
    ]

    for file in test_files:
        is_benign, library = filter.is_benign_library(file)
        status = "[BENIGN]" if is_benign else "[CHECK]"
        print(f"{status} {file}")
        if library:
            print(f"         Library: {library}")

    # Test timeout detection
    print("\n4. Testing Timeout Detection:")
    print("-" * 80)

    test_timeouts = [1000, 5000, 30000, 60000, 300000, 86400000]

    for timeout in test_timeouts:
        is_benign, reason = filter.is_benign_timeout(timeout)
        status = "[BENIGN]" if is_benign else "[SUSPICIOUS]"
        seconds = timeout / 1000
        print(f"{status} {timeout}ms ({seconds}s)")
        if reason:
            print(f"         {reason}")


if __name__ == "__main__":
    test_false_positive_filter()
