"""
Enhanced Detection Engine v2.0

Integrates:
- JSON-based detection rules
- Taint analysis engine
- Entropy analysis for obfuscation detection
- Comprehensive regex library for sensitive data
- AST-based pattern matching

Based on research from:
- JavaSith framework (arXiv:2505.21263)
- GitLab Threat Intelligence malicious extension analysis
- LayerX GhostPoster campaign analysis
"""

import json
import re
import math
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from collections import defaultdict
import esprima

from taint_analyzer import TaintAnalyzer, EntropyAnalyzer


class SensitiveDataDetector:
    """
    Comprehensive regex library for detecting sensitive data patterns.
    Includes cryptocurrency, financial, PII, and authentication patterns.
    """

    def __init__(self):
        # Load patterns from detection_rules.json
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> Dict:
        """Load regex patterns from detection rules JSON"""
        try:
            rules_path = Path(__file__).parent / 'detection_rules.json'
            with open(rules_path, 'r') as f:
                rules = json.load(f)
            return rules.get('regex_library', {})
        except Exception:
            return self._get_default_patterns()

    def _get_default_patterns(self) -> Dict:
        """Default patterns if JSON load fails"""
        return {
            'WALLET_ADDRESS': {
                'ethereum': r'0x[a-fA-F0-9]{40}',
                'bitcoin_legacy': r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}',
                'bitcoin_segwit': r'bc1[ac-hj-np-z02-9]{39,59}',
                'solana': r'[1-9A-HJ-NP-Za-km-z]{32,44}',
            },
            'MNEMONIC_SEED': {
                '12_word': r'\b([a-z]+\s+){11}[a-z]+\b',
                '24_word': r'\b([a-z]+\s+){23}[a-z]+\b',
            },
            'CREDIT_CARD': {
                'generic': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b',
            },
            'JWT': {
                'pattern': r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
            }
        }

    def detect_all(self, content: str) -> List[Dict]:
        """
        Scan content for all sensitive data patterns.

        Returns list of findings with type, pattern matched, and context.
        """
        findings = []

        for category, patterns in self.patterns.items():
            for pattern_name, pattern in patterns.items():
                if isinstance(pattern, str):
                    try:
                        for match in re.finditer(pattern, content, re.IGNORECASE):
                            # Get context around match
                            start = max(0, match.start() - 50)
                            end = min(len(content), match.end() + 50)
                            context = content[start:end]

                            findings.append({
                                'type': 'SENSITIVE_DATA',
                                'category': category,
                                'pattern_name': pattern_name,
                                'matched_value': match.group()[:50] + '...' if len(match.group()) > 50 else match.group(),
                                'context': context,
                                'position': match.start(),
                                'severity': self._get_severity(category),
                                'description': f"Detected {category} pattern: {pattern_name}"
                            })
                    except re.error:
                        continue

        return findings

    def _get_severity(self, category: str) -> str:
        """Map category to severity level"""
        critical = ['PRIVATE_KEY', 'MNEMONIC_SEED', 'CREDIT_CARD']
        high = ['WALLET_ADDRESS', 'API_KEYS', 'JWT', 'SSN']

        if category in critical:
            return 'critical'
        elif category in high:
            return 'high'
        return 'medium'

    def detect_crypto_patterns(self, content: str) -> List[Dict]:
        """Specialized detection for cryptocurrency-related patterns"""
        findings = []

        # Wallet address detection with validation
        wallet_patterns = [
            (r'0x[a-fA-F0-9]{40}', 'Ethereum', 'ETH'),
            (r'[13][a-km-zA-HJ-NP-Z1-9]{25,34}', 'Bitcoin Legacy', 'BTC'),
            (r'bc1[ac-hj-np-z02-9]{39,59}', 'Bitcoin Segwit', 'BTC'),
            (r'[1-9A-HJ-NP-Za-km-z]{32,44}', 'Solana', 'SOL'),
            (r'4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}', 'Monero', 'XMR'),
        ]

        for pattern, name, currency in wallet_patterns:
            for match in re.finditer(pattern, content):
                # Check if in suspicious context (assignment, regex test, etc.)
                start = max(0, match.start() - 100)
                context = content[start:match.start()]

                is_suspicious = any(kw in context.lower() for kw in
                                    ['replace', 'clipboard', 'writetext', 'copy', 'paste',
                                     'regex', 'test', 'match', 'attacker', 'my_wallet'])

                findings.append({
                    'type': 'CRYPTO_ADDRESS',
                    'currency': currency,
                    'address_type': name,
                    'address': match.group(),
                    'suspicious_context': is_suspicious,
                    'severity': 'critical' if is_suspicious else 'high',
                    'description': f"{name} address detected" + (" in suspicious context" if is_suspicious else "")
                })

        # Mnemonic seed phrase detection
        mnemonic_patterns = [
            r'(seed|mnemonic|phrase|recovery|backup)\s*[:=]?\s*["\']([a-z]+\s+){11,23}[a-z]+["\']',
            r'["\']([a-z]+\s+){11}[a-z]+["\']',  # 12 words
            r'["\']([a-z]+\s+){23}[a-z]+["\']',  # 24 words
        ]

        for pattern in mnemonic_patterns:
            for match in re.finditer(pattern, content, re.IGNORECASE):
                findings.append({
                    'type': 'MNEMONIC_SEED',
                    'pattern': 'BIP39 Recovery Phrase',
                    'preview': match.group()[:100] + '...',
                    'severity': 'critical',
                    'description': 'Potential wallet recovery seed phrase detected'
                })

        # Private key patterns
        private_key_patterns = [
            (r'["\'][0-9a-fA-F]{64}["\']', 'Hex Private Key'),
            (r'5[HJK][1-9A-HJ-NP-Za-km-z]{49}', 'WIF Private Key'),
            (r'(privateKey|private_key|privkey)\s*[:=]\s*["\'][^"\']+["\']', 'Named Private Key'),
        ]

        for pattern, name in private_key_patterns:
            for match in re.finditer(pattern, content):
                findings.append({
                    'type': 'PRIVATE_KEY',
                    'pattern_name': name,
                    'severity': 'critical',
                    'description': f'{name} pattern detected - potential key theft'
                })

        return findings


class ObfuscationDetector:
    """
    Advanced obfuscation detection using entropy analysis and AST patterns.
    Detects JavaScript obfuscator signatures, string array rotation, and more.
    """

    def __init__(self):
        self.entropy_analyzer = EntropyAnalyzer()

    def analyze(self, content: str, file_path: str = "") -> Dict:
        """
        Comprehensive obfuscation analysis.

        Returns dict with obfuscation indicators and confidence score.
        """
        indicators = []
        techniques_detected = []

        # 1. Entropy analysis
        high_entropy_strings = self.entropy_analyzer.detect_high_entropy_strings(content)
        if high_entropy_strings:
            indicators.append({
                'technique': 'HIGH_ENTROPY_STRINGS',
                'count': len(high_entropy_strings),
                'severity': 'high' if len(high_entropy_strings) >= 5 else 'medium'
            })
            techniques_detected.append('String encoding/encryption')

        # 2. JavaScript obfuscator signature (_0x pattern)
        obfuscator_pattern = re.findall(r'_0x[0-9a-f]{4,}', content)
        if len(obfuscator_pattern) >= 5:
            indicators.append({
                'technique': 'JS_OBFUSCATOR',
                'count': len(obfuscator_pattern),
                'severity': 'high'
            })
            techniques_detected.append('JavaScript Obfuscator')

        # 3. String array with rotation function
        string_array = re.search(r'var\s+\w+\s*=\s*\[[^\]]{500,}\]', content)
        rotation_func = re.search(r'function\s*\w*\s*\([^)]*\)\s*\{[^}]*(shift|push|splice)[^}]*\}', content)
        if string_array and rotation_func:
            indicators.append({
                'technique': 'STRING_ARRAY_ROTATION',
                'severity': 'high'
            })
            techniques_detected.append('String array rotation')

        # 4. Eval via bracket notation (window['ev' + 'al'])
        eval_bypass = re.search(
            r'(window|this|self)\s*\[\s*["\'][^"\']+["\']\s*\+\s*["\'][^"\']+["\']\s*\]',
            content
        )
        if eval_bypass:
            indicators.append({
                'technique': 'EVAL_BYPASS',
                'severity': 'critical',
                'evidence': eval_bypass.group()
            })
            techniques_detected.append('Eval bypass via concatenation')

        # 5. Constructor bypass ()[constructor][constructor]
        constructor_bypass = re.search(
            r'\[\s*["\']constructor["\']\s*\]\s*\[\s*["\']constructor["\']\s*\]',
            content
        )
        if constructor_bypass:
            indicators.append({
                'technique': 'CONSTRUCTOR_BYPASS',
                'severity': 'critical',
                'evidence': constructor_bypass.group()
            })
            techniques_detected.append('Constructor chain bypass')

        # 6. Debugger anti-analysis
        debugger_loop = re.search(
            r'(while|for)\s*\([^)]*\)\s*\{[^}]*debugger[^}]*\}|setInterval\s*\([^)]*debugger',
            content
        )
        if debugger_loop:
            indicators.append({
                'technique': 'DEBUGGER_LOOP',
                'severity': 'high'
            })
            techniques_detected.append('Anti-debugging')

        # 7. Heavy use of String.fromCharCode
        fromcharcode = re.findall(r'String\.fromCharCode\s*\([^)]+\)', content)
        if len(fromcharcode) >= 3:
            indicators.append({
                'technique': 'CHARCODE_OBFUSCATION',
                'count': len(fromcharcode),
                'severity': 'medium'
            })
            techniques_detected.append('CharCode obfuscation')

        # 8. Hex string obfuscation (\x41\x42...)
        hex_strings = re.findall(r'\\x[0-9a-fA-F]{2}', content)
        if len(hex_strings) >= 20:
            indicators.append({
                'technique': 'HEX_STRING_OBFUSCATION',
                'count': len(hex_strings),
                'severity': 'high'
            })
            techniques_detected.append('Hex string encoding')

        # Calculate confidence score
        confidence = min(100, len(indicators) * 25)

        return {
            'is_obfuscated': len(indicators) >= 2,
            'confidence': confidence,
            'techniques_detected': techniques_detected,
            'indicators': indicators,
            'high_entropy_strings': high_entropy_strings[:5],  # Top 5
            'severity': 'critical' if confidence >= 75 else 'high' if confidence >= 50 else 'medium'
        }


class EnhancedDetectionEngine:
    """
    Main detection engine that integrates all detection modules.
    """

    def __init__(self):
        self.taint_analyzer = TaintAnalyzer()
        self.sensitive_detector = SensitiveDataDetector()
        self.obfuscation_detector = ObfuscationDetector()
        self.rules = self._load_rules()

    def _load_rules(self) -> List[Dict]:
        """Load detection rules from JSON"""
        try:
            rules_path = Path(__file__).parent / 'detection_rules.json'
            with open(rules_path, 'r') as f:
                data = json.load(f)
            return data.get('rules', [])
        except Exception:
            return []

    def analyze_extension(self, extension_dir: Path) -> Dict:
        """
        Run comprehensive analysis on an extension.

        Returns aggregated results from all detection modules.
        """
        extension_dir = Path(extension_dir)

        results = {
            'taint_flows': [],
            'sensitive_data': [],
            'obfuscation': [],
            'rule_matches': [],
            'crypto_findings': [],
            'summary': {
                'total_findings': 0,
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0
            }
        }

        print(f"\n[ENHANCED] Running enhanced detection on {extension_dir.name}...")

        js_files = list(extension_dir.rglob('*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                relative_path = str(js_file.relative_to(extension_dir))

                # 1. Taint analysis
                taint_results = self.taint_analyzer.analyze_file(relative_path, content)
                results['taint_flows'].extend(taint_results)

                # 2. Sensitive data detection
                sensitive_findings = self.sensitive_detector.detect_all(content)
                for finding in sensitive_findings:
                    finding['file'] = relative_path
                results['sensitive_data'].extend(sensitive_findings)

                # 3. Crypto-specific patterns
                crypto_findings = self.sensitive_detector.detect_crypto_patterns(content)
                for finding in crypto_findings:
                    finding['file'] = relative_path
                results['crypto_findings'].extend(crypto_findings)

                # 4. Obfuscation analysis
                obfuscation = self.obfuscation_detector.analyze(content, relative_path)
                if obfuscation['is_obfuscated']:
                    obfuscation['file'] = relative_path
                    results['obfuscation'].append(obfuscation)

                # 5. Rule-based detection
                rule_matches = self._apply_rules(content, relative_path)
                results['rule_matches'].extend(rule_matches)

            except Exception as e:
                continue

        # Calculate summary
        all_findings = (
            results['taint_flows'] +
            results['sensitive_data'] +
            results['crypto_findings'] +
            results['rule_matches']
        )

        results['summary']['total_findings'] = len(all_findings)

        for finding in all_findings:
            severity = finding.get('severity', 'medium').lower()
            if severity == 'critical':
                results['summary']['critical'] += 1
            elif severity == 'high':
                results['summary']['high'] += 1
            elif severity == 'medium':
                results['summary']['medium'] += 1
            else:
                results['summary']['low'] += 1

        # Print summary
        print(f"[ENHANCED] Analysis complete:")
        print(f"[ENHANCED]   Taint flows: {len(results['taint_flows'])}")
        print(f"[ENHANCED]   Sensitive data: {len(results['sensitive_data'])}")
        print(f"[ENHANCED]   Crypto patterns: {len(results['crypto_findings'])}")
        print(f"[ENHANCED]   Obfuscation: {len(results['obfuscation'])} files")
        print(f"[ENHANCED]   Rule matches: {len(results['rule_matches'])}")

        if results['summary']['critical'] > 0:
            print(f"[ENHANCED] [ALERT] {results['summary']['critical']} CRITICAL findings!")

        return results

    def _apply_rules(self, content: str, file_path: str) -> List[Dict]:
        """Apply regex-based detection rules"""
        matches = []

        for rule in self.rules:
            if 'regex' not in rule:
                continue

            try:
                pattern = rule['regex']
                for match in re.finditer(pattern, content, re.IGNORECASE | re.DOTALL):
                    # Get line number
                    line_num = content[:match.start()].count('\n') + 1

                    # Get context
                    start = max(0, match.start() - 100)
                    end = min(len(content), match.end() + 100)
                    context = content[start:end]

                    matches.append({
                        'rule_id': rule.get('id', 'UNKNOWN'),
                        'name': rule.get('name', 'Unknown Rule'),
                        'category': rule.get('category', 'UNKNOWN'),
                        'severity': rule.get('severity', 'medium'),
                        'description': rule.get('description', ''),
                        'file': file_path,
                        'line': line_num,
                        'evidence': match.group()[:500],
                        'context': context,
                        'mitre_attack': rule.get('mitre_attack', '')
                    })

                    # Only report first match per rule per file
                    break

            except re.error:
                continue

        return matches


class WalletHijackDetector:
    """
    Specialized detector for cryptocurrency wallet hijacking attacks.
    Detects clipboard swapping, wallet object override, and transaction injection.
    """

    def analyze(self, content: str, file_path: str = "") -> List[Dict]:
        """Detect wallet hijacking patterns"""
        findings = []

        # 1. Clipboard hijack pattern
        # Read clipboard -> check for wallet address -> replace with attacker address
        clipboard_pattern = re.search(
            r'clipboard\.(readText|read)[^}]*?'
            r'(0x[a-fA-F0-9]|bc1|[13][a-km-zA-HJ-NP-Z])[^}]*?'
            r'clipboard\.(writeText|write)',
            content, re.DOTALL | re.IGNORECASE
        )
        if clipboard_pattern:
            findings.append({
                'type': 'CLIPBOARD_HIJACK',
                'severity': 'critical',
                'description': 'Clipboard hijacking to replace wallet addresses',
                'technique': 'Reads clipboard, checks for wallet pattern, writes attacker address',
                'file': file_path,
                'mitre_attack': 'T1115'
            })

        # 2. Wallet object override
        wallet_override = re.search(
            r'(window\s*\.\s*(ethereum|solana|phantom|web3)\s*=|'
            r'Object\.defineProperty\s*\([^)]*["\']ethereum["\'])',
            content, re.IGNORECASE
        )
        if wallet_override:
            findings.append({
                'type': 'WALLET_OVERRIDE',
                'severity': 'critical',
                'description': 'Overrides browser wallet object to intercept transactions',
                'technique': 'window.ethereum/solana assignment or defineProperty',
                'evidence': wallet_override.group(),
                'file': file_path,
                'mitre_attack': 'T1565.002'
            })

        # 3. Transaction interception (approve calls)
        approve_inject = re.search(
            r'approve\s*\([^)]*(?:MAX_UINT|ffffffff|unlimited|0x[fF]+)',
            content, re.IGNORECASE
        )
        if approve_inject:
            findings.append({
                'type': 'APPROVE_INJECTION',
                'severity': 'critical',
                'description': 'Injects unlimited token approval to drain wallet',
                'technique': 'approve(spender, MAX_UINT) call injection',
                'file': file_path,
                'mitre_attack': 'T1565.002'
            })

        # 4. eth_sign phishing (signing arbitrary data)
        eth_sign_phish = re.search(
            r'eth_sign[^}]*?(document\.|input|value|password)',
            content, re.IGNORECASE | re.DOTALL
        )
        if eth_sign_phish:
            findings.append({
                'type': 'ETH_SIGN_PHISHING',
                'severity': 'critical',
                'description': 'Requests eth_sign for user-provided data (potential blank check)',
                'technique': 'eth_sign with user input allows signing arbitrary transactions',
                'file': file_path,
                'mitre_attack': 'T1539'
            })

        # 5. Private key extraction from DOM
        private_key_dom = re.search(
            r'(querySelector|getElementById|getElementsBy)[^}]*?(privateKey|private[_-]?key|secret[_-]?key|seed)[^}]*?\.value',
            content, re.IGNORECASE | re.DOTALL
        )
        if private_key_dom:
            findings.append({
                'type': 'PRIVATE_KEY_EXTRACTION',
                'severity': 'critical',
                'description': 'Extracts private keys from DOM input fields',
                'technique': 'DOM selection targeting private key inputs',
                'file': file_path,
                'mitre_attack': 'T1552.001'
            })

        return findings


class PhishingDetector:
    """
    Detects phishing and UI hijacking techniques.
    """

    def analyze(self, content: str, file_path: str = "") -> List[Dict]:
        """Detect phishing patterns"""
        findings = []

        # 1. Fullscreen iframe overlay
        iframe_overlay = re.search(
            r'createElement\s*\(["\']iframe["\']\)[^}]*?'
            r'(100vh|100vw|position\s*:\s*fixed|z-index\s*:\s*\d{4,})',
            content, re.DOTALL | re.IGNORECASE
        )
        if iframe_overlay:
            findings.append({
                'type': 'FULLSCREEN_IFRAME',
                'severity': 'critical',
                'description': 'Creates fullscreen iframe overlay (phishing/clickjacking)',
                'file': file_path,
                'mitre_attack': 'T1185'
            })

        # 2. Password field monitoring
        password_monitor = re.search(
            r'input\[type=["\']?password[^}]*?addEventListener[^}]*?(sendMessage|postMessage|fetch|XMLHttpRequest)',
            content, re.DOTALL | re.IGNORECASE
        )
        if password_monitor:
            findings.append({
                'type': 'PASSWORD_MONITORING',
                'severity': 'critical',
                'description': 'Monitors password fields and exfiltrates input',
                'file': file_path,
                'mitre_attack': 'T1056.001'
            })

        # 3. Form submit interception
        form_intercept = re.search(
            r'addEventListener\s*\(["\']submit["\'][^}]*?'
            r'(sendMessage|fetch|XMLHttpRequest|FormData)',
            content, re.DOTALL | re.IGNORECASE
        )
        if form_intercept:
            findings.append({
                'type': 'FORM_INTERCEPTION',
                'severity': 'high',
                'description': 'Intercepts form submissions',
                'file': file_path,
                'mitre_attack': 'T1056.003'
            })

        # 4. Extension UI hiding
        ui_hiding = re.search(
            r'(remove|uninstall|disable)[^}]*?(display\s*:\s*none|visibility\s*:\s*hidden)|'
            r'chrome://extensions[^}]*?(insertCSS|style)',
            content, re.DOTALL | re.IGNORECASE
        )
        if ui_hiding:
            findings.append({
                'type': 'UI_HIDING',
                'severity': 'high',
                'description': 'Hides extension management UI elements',
                'file': file_path,
                'mitre_attack': 'T1564.001'
            })

        # 5. Fake login page injection
        fake_login = re.search(
            r'innerHTML\s*=[^}]*?(login|signin|password|credential)[^}]*?form',
            content, re.DOTALL | re.IGNORECASE
        )
        if fake_login:
            findings.append({
                'type': 'FAKE_LOGIN_INJECTION',
                'severity': 'critical',
                'description': 'Injects fake login form into page',
                'file': file_path,
                'mitre_attack': 'T1056.002'
            })

        return findings


# Export main classes
__all__ = [
    'EnhancedDetectionEngine',
    'SensitiveDataDetector',
    'ObfuscationDetector',
    'WalletHijackDetector',
    'PhishingDetector'
]


if __name__ == "__main__":
    # Test the enhanced detection
    test_code = """
    // Clipboard hijack example
    navigator.clipboard.readText().then(text => {
        if (text.match(/^0x[a-fA-F0-9]{40}$/)) {
            navigator.clipboard.writeText('0xATTACKER_ADDRESS_HERE');
        }
    });

    // Obfuscated code
    var _0x1a2b = ['fetch', 'POST', 'cookie'];
    window['ev' + 'al']('alert(1)');

    // Wallet override
    window.ethereum = {
        request: function(args) {
            // Intercept transactions
            sendToServer(args);
            return originalEthereum.request(args);
        }
    };
    """

    detector = EnhancedDetectionEngine()

    # Analyze obfuscation
    obf = ObfuscationDetector()
    print("=== Obfuscation Analysis ===")
    print(json.dumps(obf.analyze(test_code), indent=2))

    # Wallet hijack
    wallet = WalletHijackDetector()
    print("\n=== Wallet Hijack Detection ===")
    print(json.dumps(wallet.analyze(test_code), indent=2))
