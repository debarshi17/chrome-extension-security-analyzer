"""
Campaign Fingerprinting System

Generates fingerprints for malicious extension campaign clustering:
- Code hashes (normalized, excluding libraries)
- External domain infrastructure fingerprint
- Behavioral capability fingerprint
- Cross-extension similarity detection

Checks new extensions against a database of known campaign signatures.
"""

import hashlib
import json
import re
from pathlib import Path


class CampaignFingerprinter:
    """Generate fingerprints for campaign clustering."""

    def __init__(self, campaign_db_path=None):
        self.campaign_db_path = campaign_db_path or (
            Path(__file__).parent / 'data' / 'campaign_signatures.json'
        )
        self.known_campaigns = self._load_known_campaigns()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def fingerprint_extension(self, extension_path, results):
        """Generate campaign fingerprint for an extension.

        Args:
            extension_path: Path to unpacked extension directory.
            results: Full analysis results dict.

        Returns:
            dict with code_hashes, domains, infra_fingerprint,
            capability_fingerprint, matched_campaigns.
        """
        extension_path = Path(extension_path)
        fingerprint = {
            'code_hashes': [],
            'domains': [],
            'infra_fingerprint': '',
            'capability_fingerprint': '',
            'matched_campaigns': [],
        }

        # 1. Hash key JavaScript files (skip libraries)
        for js_file in extension_path.rglob('*.js'):
            if not self._is_extension_code(js_file):
                continue
            try:
                content = js_file.read_text(errors='ignore')
            except Exception:
                continue
            # Normalize whitespace for better cross-version matching
            normalized = re.sub(r'\s+', ' ', content).strip()
            if len(normalized) < 100:
                continue
            file_hash = hashlib.sha256(normalized.encode()).hexdigest()[:16]
            fingerprint['code_hashes'].append({
                'file': js_file.name,
                'hash': file_hash,
                'size': len(normalized),
            })

        # 2. Extract external domains from findings
        domains = set()
        for pattern in results.get('malicious_patterns', []):
            context = pattern.get('context', '')
            found = re.findall(r'https?://([a-zA-Z0-9.-]+)', context)
            domains.update(found)
        # Also from AST exfiltration destinations
        for exfil in results.get('ast_results', {}).get('data_exfiltration', []):
            dest = exfil.get('destination', '')
            if dest and not dest.startswith('<'):
                domains.add(dest)
        fingerprint['domains'] = sorted(domains)

        # 3. Infrastructure fingerprint (hash of sorted domains)
        if domains:
            fingerprint['infra_fingerprint'] = hashlib.md5(
                '|'.join(sorted(domains)).encode()
            ).hexdigest()[:12]

        # 4. Capability fingerprint (sorted set of techniques)
        techniques = sorted(set(
            p.get('technique', '') for p in results.get('malicious_patterns', [])
            if p.get('technique')
        ))
        if techniques:
            fingerprint['capability_fingerprint'] = hashlib.md5(
                '|'.join(techniques).encode()
            ).hexdigest()[:12]

        # 5. Check against known campaigns
        for campaign in self.known_campaigns:
            score = self._match_campaign(fingerprint, campaign, results)
            if score >= campaign.get('threshold', 0.6):
                fingerprint['matched_campaigns'].append({
                    'name': campaign['name'],
                    'confidence': round(score, 2),
                    'description': campaign.get('description', ''),
                    'reference': campaign.get('reference', ''),
                })

        return fingerprint

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------
    def _is_extension_code(self, js_file):
        """Return True if the file is likely extension code, not a library."""
        parts = js_file.parts
        if 'node_modules' in parts or 'bower_components' in parts:
            return False
        name = js_file.name.lower()
        # Common library filenames
        libs = [
            'jquery', 'lodash', 'underscore', 'backbone', 'angular',
            'react', 'vue', 'moment', 'axios', 'bootstrap', 'popper',
            'd3', 'three', 'chart', 'socket.io', 'polyfill',
        ]
        if any(lib in name for lib in libs):
            return False
        try:
            if js_file.stat().st_size > 5 * 1024 * 1024:
                return False
        except OSError:
            return False
        return True

    def _match_campaign(self, fingerprint, campaign, results):
        """Score how well fingerprint matches a known campaign (0.0-1.0)."""
        signals = 0
        total_signals = 0

        # Domain overlap
        campaign_domains = set(campaign.get('domains', []))
        if campaign_domains:
            total_signals += 1
            overlap = campaign_domains & set(fingerprint['domains'])
            if overlap:
                signals += len(overlap) / len(campaign_domains)

        # Infrastructure fingerprint match
        if campaign.get('infra_fingerprint'):
            total_signals += 1
            if fingerprint['infra_fingerprint'] == campaign['infra_fingerprint']:
                signals += 1

        # Gmail module presence
        if campaign.get('gmail_module'):
            total_signals += 1
            sensitive = results.get('sensitive_targets', {})
            if isinstance(sensitive, dict) and sensitive.get('gmail_module'):
                signals += 1

        # Required indicators
        for indicator in campaign.get('indicators', []):
            total_signals += 1
            patterns = results.get('malicious_patterns', [])
            techniques = set(p.get('technique', '') for p in patterns)
            if indicator in techniques:
                signals += 1
            # Also check pattern names
            pattern_names = set(p.get('name', '').lower() for p in patterns)
            if indicator.lower() in pattern_names:
                signals += 0.5

        if total_signals == 0:
            return 0.0
        return signals / total_signals

    def _load_known_campaigns(self):
        """Load known malicious campaign signatures from JSON."""
        if self.campaign_db_path.exists():
            try:
                with open(self.campaign_db_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                pass

        # Built-in signatures
        return [
            {
                'name': 'ChatGPT Search / GhostPoster Gmail Campaign',
                'description': (
                    'Extensions disguised as AI/ChatGPT tools that inject fullscreen '
                    'iframes to external domains and contain Gmail surveillance modules.'
                ),
                'domains': ['tapnetic.pro', 'chatgpt-app.pro'],
                'gmail_module': True,
                'indicators': ['Remote C2 UI', 'DOM surveillance', 'Form interception'],
                'threshold': 0.5,
                'reference': 'https://research.example.com/ghostposter',
            },
            {
                'name': 'PDF Toolbox / Polymorphic Extension Campaign',
                'description': (
                    'Extensions with legitimate surface functionality that fetch and '
                    'execute remote code via obfuscated loaders.'
                ),
                'domains': ['serasearchtop.com'],
                'indicators': [
                    'Remote script injection', 'Delayed activation',
                    'Remote C2 UI', 'Anti-debugging',
                ],
                'threshold': 0.5,
            },
            {
                'name': 'Great Suspender / Extension Takeover Campaign',
                'description': (
                    'Legitimate extensions acquired by malicious actors who inject '
                    'tracking and data exfiltration code.'
                ),
                'indicators': [
                    'Data exfiltration', 'Device fingerprinting',
                    'Delayed activation', 'Remote script injection',
                ],
                'threshold': 0.6,
            },
        ]

    def save_campaign_db(self, campaigns=None):
        """Persist campaign signatures to disk."""
        campaigns = campaigns or self.known_campaigns
        self.campaign_db_path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.campaign_db_path, 'w', encoding='utf-8') as f:
            json.dump(campaigns, f, indent=2)
