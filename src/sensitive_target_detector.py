"""
Sensitive Target Detection Module

Detects extensions specifically targeting high-value data sources:
- Email (Gmail, Outlook, Yahoo Mail, ProtonMail)
- Productivity (Slack, Notion, Google Drive, Dropbox)
- Banking / Finance (Chase, PayPal, Coinbase)
- Authentication / SSO (Google Accounts, Microsoft, Okta, Auth0)

Checks:
1. Manifest content_scripts matches for sensitive domains
2. Host permission patterns targeting sensitive services
3. Gmail-specific surveillance code (DOM selectors, compose hooks)
"""

import re
from pathlib import Path


SENSITIVE_TARGETS = {
    'email': {
        'domains': [
            'mail.google.com', 'outlook.live.com', 'outlook.office.com',
            'outlook.office365.com', 'mail.yahoo.com', 'mail.protonmail.com',
            'mail.proton.me',
        ],
        'severity': 'critical',
        'risk_description': 'Email surveillance capability',
    },
    'productivity': {
        'domains': [
            'slack.com', 'app.slack.com', 'notion.so', 'drive.google.com',
            'docs.google.com', 'sheets.google.com', 'dropbox.com',
            'airtable.com', 'asana.com', 'trello.com', 'linear.app',
            'github.com', 'gitlab.com',
        ],
        'severity': 'high',
        'risk_description': 'Corporate data access',
    },
    'finance': {
        'domains': [
            'chase.com', 'bankofamerica.com', 'wellsfargo.com',
            'paypal.com', 'venmo.com', 'coinbase.com', 'binance.com',
            'kraken.com', 'crypto.com', 'robinhood.com',
        ],
        'severity': 'critical',
        'risk_description': 'Financial data targeting',
    },
    'auth': {
        'domains': [
            'accounts.google.com', 'login.microsoftonline.com',
            'auth0.com', 'okta.com', 'login.okta.com',
            'sso.', 'login.', 'signin.',
        ],
        'severity': 'critical',
        'risk_description': 'Authentication / SSO targeting',
    },
}

# Gmail-specific surveillance indicators
_GMAIL_INDICATORS = [
    (r'gmail\.com', 'Gmail domain reference'),
    (r'\.ii\.gt|\.adn|\.gs|\.aeH|\.bsQ', 'Gmail DOM class selectors'),
    (r'MutationObserver[^}]{0,120}(gmail|mail\.google)', 'Gmail MutationObserver'),
    (r'compose|draft|inbox|sent|threadlist', 'Gmail UI element targeting'),
    (r'data-message-id|data-thread-id|data-legacy-message-id', 'Gmail message ID extraction'),
    (r'aria-label="[^"]*[Cc]ompose"', 'Gmail Compose button detection'),
    (r'editable[^}]{0,60}contenteditable', 'Gmail editable area targeting'),
]


class SensitiveTargetDetector:
    """Detect extensions that target high-value services."""

    def analyze(self, manifest, extension_path=None):
        """Run all sensitive target checks.

        Args:
            manifest: Parsed manifest.json dict.
            extension_path: Optional Path to extension directory for code scanning.

        Returns:
            dict with ``targets`` list, ``gmail_module`` list, and ``risk_multiplier``.
        """
        targets = self.analyze_manifest(manifest)
        gmail = []
        if extension_path:
            gmail = self.detect_gmail_module(Path(extension_path))

        # Compute a risk multiplier based on what was found
        multiplier = 1.0
        has_email = any(t['category'] == 'email' for t in targets)
        has_finance = any(t['category'] == 'finance' for t in targets)
        has_auth = any(t['category'] == 'auth' for t in targets)

        if gmail:
            multiplier = max(multiplier, 1.4)
        if has_email:
            multiplier = max(multiplier, 1.3)
        if has_finance:
            multiplier = max(multiplier, 1.3)
        if has_auth:
            multiplier = max(multiplier, 1.2)

        return {
            'targets': targets,
            'gmail_module': gmail,
            'risk_multiplier': multiplier,
            'categories': list(set(t['category'] for t in targets)),
        }

    # ------------------------------------------------------------------
    def analyze_manifest(self, manifest):
        """Check content_scripts and host_permissions for sensitive targets."""
        findings = []

        # Check content_scripts → matches
        for cs in manifest.get('content_scripts', []):
            for match_pattern in cs.get('matches', []):
                for category, config in SENSITIVE_TARGETS.items():
                    for domain in config['domains']:
                        if domain in match_pattern:
                            findings.append({
                                'type': 'SENSITIVE_TARGET',
                                'category': category,
                                'domain': domain,
                                'severity': config['severity'],
                                'description': config['risk_description'],
                                'run_at': cs.get('run_at', 'document_idle'),
                                'source': 'content_scripts',
                                'risk_multiplier': (
                                    1.5 if cs.get('run_at') == 'document_start' else 1.0
                                ),
                            })

        # Check host_permissions and permissions for url patterns
        all_perms = (
            manifest.get('host_permissions', [])
            + manifest.get('permissions', [])
            + manifest.get('optional_permissions', [])
            + manifest.get('optional_host_permissions', [])
        )
        for perm in all_perms:
            for category, config in SENSITIVE_TARGETS.items():
                for domain in config['domains']:
                    if domain in str(perm):
                        # Avoid duplicates from content_scripts
                        if not any(
                            f['domain'] == domain and f['source'] == 'host_permissions'
                            for f in findings
                        ):
                            findings.append({
                                'type': 'SENSITIVE_TARGET',
                                'category': category,
                                'domain': domain,
                                'severity': config['severity'],
                                'description': config['risk_description'],
                                'source': 'host_permissions',
                                'risk_multiplier': 1.0,
                            })

        return findings

    # ------------------------------------------------------------------
    def detect_gmail_module(self, extension_path):
        """Detect Gmail-specific surveillance code in extension JS files."""
        findings = []

        for js_file in extension_path.rglob('*.js'):
            # Skip node_modules / bower_components
            parts = js_file.parts
            if 'node_modules' in parts or 'bower_components' in parts:
                continue
            # Skip very large files
            try:
                size = js_file.stat().st_size
            except OSError:
                continue
            if size > 5 * 1024 * 1024:
                continue

            try:
                content = js_file.read_text(errors='ignore')
            except Exception:
                continue

            matches = []
            for pattern, desc in _GMAIL_INDICATORS:
                if re.search(pattern, content, re.IGNORECASE):
                    matches.append(desc)

            if len(matches) >= 3:  # Multiple indicators = Gmail module
                findings.append({
                    'type': 'GMAIL_SURVEILLANCE_MODULE',
                    'severity': 'critical',
                    'file': str(js_file.name),
                    'indicators': matches,
                    'indicator_count': len(matches),
                    'description': (
                        'Dedicated Gmail surveillance code detected — can read '
                        'emails, drafts, compose content'
                    ),
                })

        return findings
