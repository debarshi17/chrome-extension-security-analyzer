"""
Supply Chain Version Diff Analysis

Compares the current extension version against a previously stored analysis
to detect supply chain attacks: sudden permission escalation, new external
domains, obfuscation introduction, developer changes.

Usage:
    diff = VersionDiffAnalyzer()
    # After analyzing an extension, store the baseline:
    diff.store_baseline(extension_id, results)
    # On next scan, compare against baseline:
    changes = diff.compare(extension_id, new_results)
"""

import json
import os
from pathlib import Path
from datetime import datetime


class VersionDiffAnalyzer:
    """Detects supply chain attack indicators by comparing extension versions."""

    def __init__(self, storage_dir=None):
        self.storage_dir = Path(storage_dir or 'data/version_baselines')
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def _baseline_path(self, extension_id):
        safe_id = extension_id.replace('/', '_').replace('\\', '_')
        return self.storage_dir / f'{safe_id}.json'

    def store_baseline(self, extension_id, results):
        """Store a snapshot of the current analysis for future comparison."""
        baseline = {
            'extension_id': extension_id,
            'version': results.get('version', 'unknown'),
            'timestamp': datetime.utcnow().isoformat(),
            'name': results.get('name', ''),
            'description': results.get('description', ''),
            # Permissions snapshot
            'permissions': results.get('permissions', {}).get('all', []),
            'attack_paths': [
                ap.get('name') for ap in
                results.get('permissions', {}).get('attack_paths', [])
            ],
            # Code indicators
            'pattern_count': len(results.get('malicious_patterns', [])),
            'pattern_severities': {
                'critical': sum(1 for p in results.get('malicious_patterns', [])
                                if p.get('severity') == 'critical'),
                'high': sum(1 for p in results.get('malicious_patterns', [])
                            if p.get('severity') == 'high'),
            },
            'pattern_techniques': list(set(
                p.get('technique', '') for p in results.get('malicious_patterns', [])
            )),
            # External domains
            'external_scripts': [
                s.get('url', '') for s in results.get('external_scripts', [])
            ],
            # Obfuscation
            'obfuscated_files': list(results.get('obfuscation_indicators', {}).keys()),
            # Risk
            'risk_score': results.get('risk_score', 0),
            'risk_level': results.get('risk_level', 'UNKNOWN'),
            # CSP
            'csp': results.get('csp_analysis', {}).get('raw_csp', ''),
            # Store metadata
            'author': results.get('store_metadata', {}).get('author', ''),
            'author_verified': results.get('store_metadata', {}).get('author_verified', False),
        }

        path = self._baseline_path(extension_id)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(baseline, f, indent=2)

        return path

    def has_baseline(self, extension_id):
        return self._baseline_path(extension_id).exists()

    def load_baseline(self, extension_id):
        path = self._baseline_path(extension_id)
        if not path.exists():
            return None
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)

    def compare(self, extension_id, new_results):
        """
        Compare current analysis against stored baseline.

        Returns dict with:
          - changes: list of detected changes with severity
          - risk_delta: change in risk score
          - version_change: old -> new version
          - supply_chain_risk: 0-5 score
        """
        baseline = self.load_baseline(extension_id)
        if not baseline:
            return {
                'has_baseline': False,
                'changes': [],
                'risk_delta': 0,
                'supply_chain_risk': 0,
                'message': 'No previous version baseline stored. '
                           'Current analysis will be saved as baseline.',
            }

        changes = []
        supply_chain_score = 0.0

        old_version = baseline.get('version', '?')
        new_version = new_results.get('version', '?')

        # 1. Permission escalation
        old_perms = set(baseline.get('permissions', []))
        new_perms = set(new_results.get('permissions', {}).get('all', []))
        added_perms = new_perms - old_perms
        removed_perms = old_perms - new_perms

        if added_perms:
            # Check if any are high-risk
            high_risk_added = [p for p in added_perms
                               if p.lower() in ('<all_urls>', 'cookies', 'webrequest',
                                                 'webrequestblocking', 'management',
                                                 'debugger', 'nativemessaging',
                                                 'desktopcapture', 'tabcapture',
                                                 'proxy', 'scripting')]
            if high_risk_added:
                changes.append({
                    'type': 'permission_escalation',
                    'severity': 'critical',
                    'description': f'High-risk permissions ADDED: {", ".join(high_risk_added)}',
                    'details': {'added': list(added_perms)},
                })
                supply_chain_score += 2.0
            else:
                changes.append({
                    'type': 'permission_change',
                    'severity': 'medium',
                    'description': f'{len(added_perms)} new permission(s) added: {", ".join(list(added_perms)[:5])}',
                    'details': {'added': list(added_perms)},
                })
                supply_chain_score += 0.5

        # 2. New attack paths
        old_paths = set(baseline.get('attack_paths', []))
        new_paths = set(
            ap.get('name', '') for ap in
            new_results.get('permissions', {}).get('attack_paths', [])
        )
        new_attack_paths = new_paths - old_paths
        if new_attack_paths:
            changes.append({
                'type': 'new_attack_paths',
                'severity': 'critical',
                'description': f'New attack paths enabled: {", ".join(new_attack_paths)}',
                'details': {'new_paths': list(new_attack_paths)},
            })
            supply_chain_score += 2.0

        # 3. New external domains
        old_scripts = set(baseline.get('external_scripts', []))
        new_scripts = set(
            s.get('url', '') for s in new_results.get('external_scripts', [])
        )
        added_scripts = new_scripts - old_scripts
        if added_scripts:
            changes.append({
                'type': 'new_external_scripts',
                'severity': 'high',
                'description': f'{len(added_scripts)} new external script source(s)',
                'details': {'added': list(added_scripts)[:10]},
            })
            supply_chain_score += 1.0

        # 4. Obfuscation introduced
        old_obf = set(baseline.get('obfuscated_files', []))
        new_obf = set(new_results.get('obfuscation_indicators', {}).keys())
        new_obfuscation = new_obf - old_obf
        if new_obfuscation and not old_obf:
            changes.append({
                'type': 'obfuscation_introduced',
                'severity': 'high',
                'description': f'Obfuscation newly introduced in {len(new_obfuscation)} file(s)',
                'details': {'files': list(new_obfuscation)[:5]},
            })
            supply_chain_score += 1.5

        # 5. Critical pattern count increase
        old_crits = baseline.get('pattern_severities', {}).get('critical', 0)
        new_crits = sum(1 for p in new_results.get('malicious_patterns', [])
                        if p.get('severity') == 'critical')
        if new_crits > old_crits and new_crits > 0:
            delta = new_crits - old_crits
            changes.append({
                'type': 'critical_pattern_increase',
                'severity': 'high',
                'description': f'{delta} new critical-severity pattern(s) detected',
                'details': {'old': old_crits, 'new': new_crits},
            })
            supply_chain_score += 1.0

        # 6. New techniques (attack capabilities)
        old_techniques = set(baseline.get('pattern_techniques', []))
        new_techniques = set(
            p.get('technique', '') for p in
            new_results.get('malicious_patterns', [])
        )
        new_techs = new_techniques - old_techniques
        dangerous_new = new_techs & {
            'Credential theft', 'Cookie theft', 'Screen capture/surveillance',
            'Keystroke logging', 'Code injection', 'Remote code loading',
            'Wallet hijacking', 'Data exfiltration',
        }
        if dangerous_new:
            changes.append({
                'type': 'new_dangerous_techniques',
                'severity': 'critical',
                'description': f'New dangerous techniques: {", ".join(dangerous_new)}',
                'details': {'techniques': list(dangerous_new)},
            })
            supply_chain_score += 2.0

        # 7. CSP weakened
        old_csp = baseline.get('csp', '')
        new_csp = new_results.get('csp_analysis', {}).get('raw_csp', '')
        if old_csp and not new_csp:
            changes.append({
                'type': 'csp_removed',
                'severity': 'high',
                'description': 'CSP removed from manifest (was previously defined)',
                'details': {'old_csp': old_csp[:100]},
            })
            supply_chain_score += 1.0
        elif 'unsafe-eval' in new_csp and 'unsafe-eval' not in old_csp:
            changes.append({
                'type': 'csp_weakened',
                'severity': 'high',
                'description': "unsafe-eval added to CSP (wasn't present before)",
                'details': {},
            })
            supply_chain_score += 1.0

        # 8. Developer change
        old_author = baseline.get('author', '')
        new_author = new_results.get('store_metadata', {}).get('author', '')
        if old_author and new_author and old_author != new_author:
            changes.append({
                'type': 'developer_change',
                'severity': 'high',
                'description': f'Developer changed: "{old_author}" -> "{new_author}"',
                'details': {'old': old_author, 'new': new_author},
            })
            supply_chain_score += 1.5

        # Risk delta
        old_score = baseline.get('risk_score', 0)
        new_score = new_results.get('risk_score', 0)
        risk_delta = new_score - old_score

        return {
            'has_baseline': True,
            'old_version': old_version,
            'new_version': new_version,
            'baseline_date': baseline.get('timestamp', ''),
            'changes': changes,
            'change_count': len(changes),
            'risk_delta': round(risk_delta, 1),
            'supply_chain_risk': min(supply_chain_score, 5.0),
            'supply_chain_level': (
                'CRITICAL' if supply_chain_score >= 4 else
                'HIGH' if supply_chain_score >= 2.5 else
                'MEDIUM' if supply_chain_score >= 1 else
                'LOW'
            ),
        }
