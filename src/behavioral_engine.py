"""
Behavioral Correlation Engine for Browser Extensions

Correlates findings from ALL analysis layers (permissions, code patterns, AST,
taint flows, advanced detection, enhanced detection) into compound threat patterns.

Each rule maps to a known attack archetype and fires only when multiple independent
signals converge - reducing false positives while catching sophisticated threats
that individual pattern matching misses.
"""


class BrowserBehavioralEngine:
    """Correlates static analysis findings into compound threat assessments."""

    # Technique categories used for grouping findings
    CREDENTIAL_TECHNIQUES = {
        'Credential theft', 'Cookie theft', 'CSRF token theft', 'OAuth token theft',
        'Password exfiltration', 'Token theft', 'Hidden field harvesting',
        'Credential syncing', 'Storage extraction', 'Identity harvesting',
    }
    KEYLOG_TECHNIQUES = {
        'Keystroke logging', 'CSS keylogging', 'Input monitoring',
    }
    SCREEN_CAPTURE_TECHNIQUES = {
        'Screen capture/surveillance', 'Screen recording', 'Screen surveillance',
        'Screenshot exfiltration', 'Image exfiltration', 'Image export',
    }
    EXFIL_TECHNIQUES = {
        'Data exfiltration', 'Binary data exfiltration', 'Screenshot exfiltration',
        'Beacon exfiltration', 'Encrypted exfiltration', 'Data collection',
        'Data extraction', 'IndexedDB exfiltration', 'Cross-extension exfiltration',
        'Media exfiltration', 'URL exfiltration', 'Form data extraction',
    }
    CODE_EXEC_TECHNIQUES = {
        'Code injection', 'Script injection', 'Remote script injection',
        'Remote code loading', 'Eval bypass', 'Constructor bypass',
        'Document write injection', 'Event handler injection',
    }
    NETWORK_TECHNIQUES = {
        'Network request', 'Network communication', 'WebSocket communication',
        'WebSocket exfiltration', 'Authenticated request', 'Covert channel',
        'External messaging',
    }
    CSP_BYPASS_TECHNIQUES = {
        'CSP bypass', 'Security header removal',
    }
    FINGERPRINT_TECHNIQUES = {
        'Device fingerprinting', 'Browser fingerprinting', 'Audio fingerprinting',
        'Font fingerprinting', 'IP fingerprinting', 'IP leak', 'ID generation',
    }
    CRYPTO_TECHNIQUES = {
        'Wallet hijacking', 'Clipboard hijacking', 'Crypto targeting',
        'Seed phrase theft', 'Private key theft', 'Token drain',
        'Signature phishing', 'Wallet phishing',
    }
    DOM_MANIPULATION_TECHNIQUES = {
        'DOM surveillance', 'DOM monitoring near sensitive fields',
        'Form interception', 'Overlay attack', 'Form injection',
        'UI manipulation', 'DOM enumeration', 'DOM traversal',
        'Autofill manipulation', 'Autofill harvesting',
    }
    EVASION_TECHNIQUES = {
        'Anti-debugging', 'Sandbox detection', 'Automation detection',
        'Interaction gating', 'Delayed activation', 'Delayed code execution',
        'Scheduled execution', 'URL-conditional activation',
        'Code obfuscation', 'String obfuscation', 'String array obfuscation',
        'URL obfuscation', 'Bracket notation obfuscation', 'Steganography',
        'Canvas steganography', 'Comment obfuscation',
    }
    TRAFFIC_TECHNIQUES = {
        'Request interception', 'Traffic interception', 'Traffic hijacking',
        'Header manipulation', 'Cookie manipulation', 'Proxy hijacking',
        'DNS manipulation', 'Certificate bypass', 'Security site blocking',
    }
    PHISHING_TECHNIQUES = {
        'Overlay attack', 'Password exfiltration', 'Form injection',
        'Notification phishing', 'OAuth phishing', 'Banking target detection',
        'Crypto exchange targeting',
    }

    def correlate(self, results):
        """
        Run all correlation rules against analysis results.

        Args:
            results: Complete analysis results dict containing:
                - permissions: {high_risk, medium_risk, low_risk, all, details, combination_warnings}
                - malicious_patterns: list of pattern findings
                - host_permissions: host permissions analysis
                - advanced_detection: {summary, findings...}
                - enhanced_detection: {taint_flows, crypto_findings, phishing_findings...}
                - settings_overrides: {search_hijacking, homepage_hijacking...}
                - ast_results: {data_exfiltration, ...}
                - store_metadata: {name, author, users...}
                - obfuscation_indicators: {file: {is_obfuscated, ...}}

        Returns:
            dict with 'correlations' list and 'summary'
        """
        patterns = results.get('malicious_patterns', [])
        permissions = results.get('permissions', {})
        host_perms = results.get('host_permissions', {})
        advanced = results.get('advanced_detection', {})
        enhanced = results.get('enhanced_detection', {})
        settings = results.get('settings_overrides', {})
        ast_results = results.get('ast_results', {})
        obfuscation = results.get('obfuscation_indicators', {})
        taint_flows = enhanced.get('taint_flows', [])

        # Build quick lookup sets
        all_perms = set(p.lower() if isinstance(p, str) else ''
                        for p in permissions.get('all', []))
        has_all_urls = any(p in all_perms for p in
                          ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'])

        techniques = set()
        for p in patterns:
            t = p.get('technique', '')
            if t:
                techniques.add(t)

        severities = {}
        for p in patterns:
            t = p.get('technique', '')
            s = p.get('severity', 'low')
            if t:
                sev_rank = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}.get(s, 0)
                severities[t] = max(severities.get(t, 0), sev_rank)

        # Category presence helpers
        has_credential = bool(techniques & self.CREDENTIAL_TECHNIQUES)
        has_keylog = bool(techniques & self.KEYLOG_TECHNIQUES)
        has_screen = bool(techniques & self.SCREEN_CAPTURE_TECHNIQUES)
        has_exfil = bool(techniques & self.EXFIL_TECHNIQUES)
        has_code_exec = bool(techniques & self.CODE_EXEC_TECHNIQUES)
        has_network = bool(techniques & self.NETWORK_TECHNIQUES)
        has_csp_bypass = bool(techniques & self.CSP_BYPASS_TECHNIQUES)
        has_fingerprint = bool(techniques & self.FINGERPRINT_TECHNIQUES)
        has_crypto = bool(techniques & self.CRYPTO_TECHNIQUES)
        has_dom = bool(techniques & self.DOM_MANIPULATION_TECHNIQUES)
        has_evasion = bool(techniques & self.EVASION_TECHNIQUES)
        has_traffic = bool(techniques & self.TRAFFIC_TECHNIQUES)
        has_phishing = bool(techniques & self.PHISHING_TECHNIQUES)

        # Permission checks
        has_cookies_perm = 'cookies' in all_perms
        has_scripting_perm = 'scripting' in all_perms
        has_webrequest_perm = ('webrequest' in all_perms or
                               'webrequestblocking' in all_perms)
        has_management_perm = 'management' in all_perms
        has_clipboard_read = 'clipboardread' in all_perms
        has_clipboard_write = 'clipboardwrite' in all_perms
        has_native_msg = 'nativemessaging' in all_perms
        has_tabs_perm = 'tabs' in all_perms
        has_history_perm = 'history' in all_perms
        has_desktop_capture = 'desktopcapture' in all_perms
        has_tab_capture = 'tabcapture' in all_perms
        has_identity_perm = 'identity' in all_perms

        # Advanced detection signals
        adv_findings = advanced.get('findings', []) if isinstance(advanced, dict) else []
        adv_summary = advanced.get('summary', {}) if isinstance(advanced, dict) else {}
        has_adv_critical = adv_summary.get('critical_findings', 0) > 0
        has_adv_csp = any(f.get('type') == 'csp_manipulation' for f in adv_findings)
        has_adv_websocket_c2 = any(f.get('type') == 'websocket_c2' for f in adv_findings)
        has_adv_delayed = any(f.get('type') == 'delayed_activation' for f in adv_findings)
        has_adv_dom_injection = any(f.get('type') == 'dom_event_injection' for f in adv_findings)

        # Taint flow signals
        has_taint_to_network = any(
            f.get('sink', {}).get('type') in ('network', 'fetch', 'xhr', 'websocket')
            for f in taint_flows
        )
        has_taint_from_credentials = any(
            f.get('source', {}).get('category') in ('credentials', 'cookies', 'passwords')
            for f in taint_flows
        )

        # Has obfuscated files
        has_obfuscation = len(obfuscation) > 0

        # AST data exfiltration
        has_ast_exfil = len(ast_results.get('data_exfiltration', [])) > 0

        correlations = []

        # ================================================================
        # Rule 1: Session Theft Chain
        # cookies permission + all_urls + network exfil (code or AST)
        # ================================================================
        if has_cookies_perm and has_all_urls and (has_exfil or has_network or has_ast_exfil):
            evidence_parts = ['cookies permission', '<all_urls> access']
            if has_ast_exfil:
                dests = [e.get('destination', '?')
                         for e in ast_results.get('data_exfiltration', [])[:3]]
                evidence_parts.append(f"POST to {', '.join(dests)}")
            elif has_exfil:
                evidence_parts.append('data exfiltration patterns in code')
            else:
                evidence_parts.append('network communication detected')

            correlations.append({
                'name': 'Session Theft Chain',
                'attack_type': 'session_hijacking',
                'severity': 'critical',
                'description': (
                    'Extension has cookies permission on ALL websites and sends data '
                    'to external servers. This is the architecture of session token '
                    'theft - cookies from any site can be read and exfiltrated.'
                ),
                'evidence': ' + '.join(evidence_parts),
                'components': ['cookies_perm', 'all_urls', 'network_exfil'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 2: Credential Harvester
        # Password/input monitoring + network POST + host access
        # ================================================================
        if (has_credential or has_keylog) and (has_network or has_exfil or has_ast_exfil):
            cred_techniques = techniques & (self.CREDENTIAL_TECHNIQUES | self.KEYLOG_TECHNIQUES)
            evidence_parts = [', '.join(list(cred_techniques)[:3])]
            if has_ast_exfil:
                evidence_parts.append('data sent to external server (AST confirmed)')
            else:
                evidence_parts.append('network exfiltration capability')

            sev = 'critical' if has_keylog else 'high'
            correlations.append({
                'name': 'Credential Harvester',
                'attack_type': 'credential_theft',
                'severity': sev,
                'description': (
                    'Extension monitors user input (passwords, keystrokes, form data) '
                    'and has network capabilities to exfiltrate captured credentials.'
                ),
                'evidence': ' + '.join(evidence_parts),
                'components': ['credential_capture', 'network_exfil'],
                'confidence': 'high' if has_keylog else 'medium',
            })

        # ================================================================
        # Rule 3: Surveillance Agent
        # Keylogger + screen capture + network
        # ================================================================
        if has_keylog and has_screen and (has_network or has_exfil):
            correlations.append({
                'name': 'Surveillance Agent',
                'attack_type': 'surveillance',
                'severity': 'critical',
                'description': (
                    'Extension combines keystroke logging with screen capture and '
                    'network exfiltration. This is a complete surveillance toolkit '
                    'capable of recording everything the user types and sees.'
                ),
                'evidence': 'Keystroke logging + screen capture + network exfiltration',
                'components': ['keylogger', 'screen_capture', 'network_exfil'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 4: Data Exfiltration Pipeline
        # Taint flow (source→sink) OR (credential access + encoding + network POST)
        # ================================================================
        if has_taint_to_network and has_taint_from_credentials:
            sources = [f.get('source', {}).get('api', '?') for f in taint_flows[:3]]
            sinks = [f.get('sink', {}).get('function', '?') for f in taint_flows[:3]]
            correlations.append({
                'name': 'Data Exfiltration Pipeline',
                'attack_type': 'data_exfiltration',
                'severity': 'critical',
                'description': (
                    'Taint analysis confirmed: sensitive data flows from credential '
                    'sources directly to network sinks. Data is read from browser '
                    'APIs and sent to external servers.'
                ),
                'evidence': f"Source: {', '.join(sources)} -> Sink: {', '.join(sinks)}",
                'components': ['taint_source', 'taint_sink', 'credential_data'],
                'confidence': 'high',
            })
        elif has_credential and has_exfil and has_obfuscation:
            correlations.append({
                'name': 'Data Exfiltration Pipeline (Obfuscated)',
                'attack_type': 'data_exfiltration',
                'severity': 'critical',
                'description': (
                    'Extension accesses credentials, has data exfiltration patterns, '
                    'AND uses code obfuscation. The combination of credential access, '
                    'exfiltration capability, and obfuscation strongly suggests malice.'
                ),
                'evidence': 'Credential access + data exfiltration + obfuscated code',
                'components': ['credential_access', 'exfiltration', 'obfuscation'],
                'confidence': 'medium',
            })

        # ================================================================
        # Rule 5: Remote Code Execution Chain
        # CSP removal/bypass + eval/Function + external script loading
        # ================================================================
        if (has_csp_bypass or has_adv_csp) and has_code_exec:
            correlations.append({
                'name': 'Remote Code Execution Chain',
                'attack_type': 'remote_code_exec',
                'severity': 'critical',
                'description': (
                    'Extension removes Content Security Policy protections AND '
                    'uses dynamic code execution (eval/Function/script injection). '
                    'CSP removal + code execution = ability to run arbitrary remote '
                    'code on any webpage the user visits.'
                ),
                'evidence': 'CSP bypass/removal + dynamic code execution',
                'components': ['csp_bypass', 'code_execution'],
                'confidence': 'high',
            })
        elif has_code_exec and has_network and has_all_urls:
            correlations.append({
                'name': 'Remote Code Execution Risk',
                'attack_type': 'remote_code_exec',
                'severity': 'high',
                'description': (
                    'Extension uses dynamic code execution with network access on '
                    'all URLs. Remote code can be fetched and executed on any page.'
                ),
                'evidence': 'Dynamic code execution + network + <all_urls>',
                'components': ['code_execution', 'network', 'all_urls'],
                'confidence': 'medium',
            })

        # ================================================================
        # Rule 6: Wallet Hijacker
        # Clipboard read+write + crypto address patterns
        # ================================================================
        if has_crypto and (has_clipboard_read or has_clipboard_write):
            correlations.append({
                'name': 'Cryptocurrency Wallet Hijacker',
                'attack_type': 'wallet_hijack',
                'severity': 'critical',
                'description': (
                    'Extension accesses clipboard AND targets cryptocurrency wallets. '
                    'This is the classic crypto address swap attack: read clipboard '
                    'for wallet addresses, replace with attacker address.'
                ),
                'evidence': 'Clipboard access + crypto wallet targeting patterns',
                'components': ['clipboard_access', 'crypto_targeting'],
                'confidence': 'high',
            })
        elif has_crypto and has_dom:
            correlations.append({
                'name': 'Cryptocurrency Theft via DOM',
                'attack_type': 'wallet_hijack',
                'severity': 'critical',
                'description': (
                    'Extension manipulates DOM elements AND targets crypto wallets. '
                    'May intercept transactions or inject fake wallet interfaces.'
                ),
                'evidence': 'DOM manipulation + crypto wallet targeting',
                'components': ['dom_manipulation', 'crypto_targeting'],
                'confidence': 'medium',
            })

        # ================================================================
        # Rule 7: Search/Homepage Hijacker
        # Settings override + affiliate params
        # ================================================================
        if settings.get('search_hijacking'):
            has_affiliate = settings['search_hijacking'].get('has_affiliate_params', False)
            correlations.append({
                'name': 'Search Engine Hijacker',
                'attack_type': 'search_hijack',
                'severity': 'high' if has_affiliate else 'medium',
                'description': (
                    'Extension overrides default search engine'
                    + (' with affiliate tracking parameters. '
                       'Revenue is generated from hijacked searches.'
                       if has_affiliate else
                       '. User searches may be redirected to attacker-controlled engine.')
                ),
                'evidence': ('Search override + affiliate params'
                             if has_affiliate else 'Search engine override'),
                'components': (['search_override', 'affiliate_params']
                               if has_affiliate else ['search_override']),
                'confidence': 'high',
            })

        if settings.get('homepage_hijacking') or settings.get('startup_hijacking'):
            correlations.append({
                'name': 'Homepage/Startup Hijacker',
                'attack_type': 'search_hijack',
                'severity': 'medium',
                'description': (
                    'Extension overrides browser homepage or startup pages. '
                    'User is redirected to attacker-controlled pages on browser launch.'
                ),
                'evidence': 'Homepage or startup page override',
                'components': ['homepage_override'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 8: Fingerprint Collector
        # Canvas/WebGL/audio fingerprinting + network exfil
        # ================================================================
        if has_fingerprint and (has_network or has_exfil):
            fp_types = techniques & self.FINGERPRINT_TECHNIQUES
            correlations.append({
                'name': 'Device Fingerprint Collector',
                'attack_type': 'fingerprinting',
                'severity': 'high',
                'description': (
                    'Extension collects device fingerprint data (canvas, WebGL, audio, '
                    'fonts, IP) and has network exfiltration capability. Device '
                    'fingerprinting enables cross-site user tracking.'
                ),
                'evidence': f"{', '.join(list(fp_types)[:3])} + network exfiltration",
                'components': ['fingerprinting', 'network_exfil'],
                'confidence': 'medium',
            })

        # ================================================================
        # Rule 9: Silent Tracker
        # <all_urls> + webRequest + beacon/POST + no visible UI
        # ================================================================
        if has_all_urls and has_webrequest_perm and (has_network or has_exfil):
            correlations.append({
                'name': 'Silent Web Tracker',
                'attack_type': 'tracking',
                'severity': 'high',
                'description': (
                    'Extension intercepts ALL web traffic via webRequest API and '
                    'sends data externally. This enables invisible tracking of '
                    'every website the user visits.'
                ),
                'evidence': '<all_urls> + webRequest + network exfiltration',
                'components': ['all_urls', 'web_request', 'exfiltration'],
                'confidence': 'medium',
            })

        # ================================================================
        # Rule 10: Extension Manipulator
        # management permission + scripting + network
        # ================================================================
        if has_management_perm and (has_scripting_perm or has_code_exec):
            correlations.append({
                'name': 'Extension Manipulation Chain',
                'attack_type': 'extension_manipulation',
                'severity': 'critical',
                'description': (
                    'Extension can manage other extensions (enable/disable/uninstall) '
                    'AND inject code. Can disable security extensions and replace '
                    'their functionality with malicious alternatives.'
                ),
                'evidence': 'management permission + code injection capability',
                'components': ['management_perm', 'code_injection'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 11: Staged Payload Loader
        # External script loading + eval/Function + delayed activation
        # ================================================================
        if has_code_exec and (has_adv_delayed or 'Delayed activation' in techniques
                             or 'Scheduled execution' in techniques):
            correlations.append({
                'name': 'Staged Payload Loader',
                'attack_type': 'staged_payload',
                'severity': 'critical',
                'description': (
                    'Extension uses dynamic code execution combined with delayed '
                    'or scheduled activation. Classic staged malware pattern: '
                    'appear benign during review, activate payload later.'
                ),
                'evidence': 'Dynamic code execution + delayed/scheduled activation',
                'components': ['code_execution', 'delayed_activation'],
                'confidence': 'high' if has_adv_delayed else 'medium',
            })

        # ================================================================
        # Rule 12: Form Overlay / Phishing Attack
        # DOM manipulation + form/input creation + credential capture + targeting
        # ================================================================
        if has_phishing and (has_credential or has_dom):
            phish_types = techniques & self.PHISHING_TECHNIQUES
            correlations.append({
                'name': 'Phishing Overlay Attack',
                'attack_type': 'phishing_overlay',
                'severity': 'critical',
                'description': (
                    'Extension creates fake UI overlays or forms to harvest user '
                    'credentials. Techniques include fullscreen iframes, cloned '
                    'login pages, and intercepted form submissions.'
                ),
                'evidence': f"{', '.join(list(phish_types)[:3])} + credential capture",
                'components': ['phishing_ui', 'credential_capture'],
                'confidence': 'high' if has_credential else 'medium',
            })

        # ================================================================
        # Rule 13: Traffic MitM / Proxy Hijack
        # webRequest + traffic interception + header manipulation
        # ================================================================
        if has_traffic and has_webrequest_perm:
            traffic_types = techniques & self.TRAFFIC_TECHNIQUES
            correlations.append({
                'name': 'Traffic Interception / MitM',
                'attack_type': 'traffic_mitm',
                'severity': 'critical',
                'description': (
                    'Extension intercepts and manipulates web traffic. Can modify '
                    'HTTP headers, redirect requests, inject content, or strip '
                    'security headers from responses.'
                ),
                'evidence': f"webRequest + {', '.join(list(traffic_types)[:3])}",
                'components': ['web_request_perm', 'traffic_manipulation'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 14: WebSocket C2 Channel
        # WebSocket communication + command patterns + persistence
        # ================================================================
        if has_adv_websocket_c2 or ('WebSocket communication' in techniques
                                     and has_code_exec):
            correlations.append({
                'name': 'WebSocket Command & Control',
                'attack_type': 'c2_channel',
                'severity': 'critical',
                'description': (
                    'Extension maintains WebSocket connection for real-time '
                    'command and control. Attacker can send commands, receive '
                    'exfiltrated data, and update malicious payloads remotely.'
                ),
                'evidence': 'WebSocket C2 patterns + dynamic code execution',
                'components': ['websocket', 'c2_commands', 'code_execution'],
                'confidence': 'high' if has_adv_websocket_c2 else 'medium',
            })

        # ================================================================
        # Rule 15: Evasion-Wrapped Payload
        # Obfuscation + anti-debugging + malicious capability
        # ================================================================
        malicious_capability = (has_credential or has_exfil or has_screen
                                or has_keylog or has_crypto)
        if has_evasion and malicious_capability and has_obfuscation:
            evasion_types = techniques & self.EVASION_TECHNIQUES
            correlations.append({
                'name': 'Evasion-Wrapped Malicious Payload',
                'attack_type': 'evasive_malware',
                'severity': 'critical',
                'description': (
                    'Extension uses anti-analysis evasion techniques (obfuscation, '
                    'anti-debugging, environment detection) to hide malicious '
                    'capabilities. Legitimate extensions do not need to evade analysis.'
                ),
                'evidence': (f"{', '.join(list(evasion_types)[:3])} + "
                             f"malicious capability detected"),
                'components': ['evasion', 'obfuscation', 'malicious_payload'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 16: Native System Escape
        # nativeMessaging + any other dangerous capability
        # ================================================================
        if has_native_msg and (has_credential or has_code_exec or has_exfil):
            correlations.append({
                'name': 'Native System Escape',
                'attack_type': 'system_escape',
                'severity': 'critical',
                'description': (
                    'Extension uses nativeMessaging to communicate with a local '
                    'native application. Combined with credential/code execution '
                    'capabilities, this enables full system compromise beyond '
                    'the browser sandbox.'
                ),
                'evidence': 'nativeMessaging + credential/code execution capability',
                'components': ['native_messaging', 'dangerous_capability'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 17: OAuth Token Exfiltration
        # identity permission + network + token patterns
        # ================================================================
        if has_identity_perm and (has_network or has_exfil):
            correlations.append({
                'name': 'OAuth Token Exfiltration',
                'attack_type': 'oauth_theft',
                'severity': 'critical',
                'description': (
                    'Extension uses Chrome identity API (OAuth tokens) with '
                    'network exfiltration. OAuth tokens provide full account '
                    'access to Google, Microsoft, or other identity providers.'
                ),
                'evidence': 'identity permission + network exfiltration',
                'components': ['identity_perm', 'network_exfil'],
                'confidence': 'high',
            })

        # ================================================================
        # Rule 18: Remote-Controlled Extension Architecture
        # Remote iframe C2 UI + all_urls or data collection
        # ================================================================
        has_remote_c2 = 'Remote C2 UI' in techniques
        if has_remote_c2 and has_all_urls:
            correlations.append({
                'name': 'Remote-Controlled Extension',
                'attack_type': 'remote_c2_extension',
                'severity': 'critical',
                'description': (
                    'Extension loads UI from external server while having access '
                    'to all websites. This architecture enables: silent feature '
                    'updates, server-side logic changes, and data exfiltration '
                    'without Chrome Store review. Classic extension-as-loader pattern.'
                ),
                'evidence': 'Remote iframe UI + <all_urls> permission',
                'components': ['remote_ui', 'full_web_access'],
                'confidence': 'high',
            })
        elif has_remote_c2 and (has_network or has_exfil):
            correlations.append({
                'name': 'Remote-Controlled Extension',
                'attack_type': 'remote_c2_extension',
                'severity': 'high',
                'description': (
                    'Extension loads UI from an external server and has network '
                    'exfiltration capability. Server can change extension behavior '
                    'without a Chrome Store update.'
                ),
                'evidence': 'Remote iframe UI + network exfiltration',
                'components': ['remote_ui', 'network_exfil'],
                'confidence': 'medium',
            })

        # Build summary
        summary = {
            'total_correlations': len(correlations),
            'critical': sum(1 for c in correlations if c['severity'] == 'critical'),
            'high': sum(1 for c in correlations if c['severity'] == 'high'),
            'medium': sum(1 for c in correlations if c['severity'] == 'medium'),
            'attack_types': list(set(c['attack_type'] for c in correlations)),
            'highest_severity': 'critical' if any(
                c['severity'] == 'critical' for c in correlations
            ) else 'high' if any(
                c['severity'] == 'high' for c in correlations
            ) else 'medium' if correlations else 'none',
        }

        return {
            'correlations': correlations,
            'summary': summary,
        }
