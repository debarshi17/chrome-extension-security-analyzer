"""
Enhanced Static Analysis Engine with VirusTotal Integration
Detects malicious Chrome extensions including campaign attribution
Based on DarkSpectre/ZoomStealer campaign analysis
"""

import json
import re
from pathlib import Path
from collections import defaultdict
import math
from ast_analyzer import JavaScriptASTAnalyzer


class EnhancedStaticAnalyzer:
    """Performs enhanced static analysis on Chrome extensions"""
    
    def __init__(self):
        self.ast_analyzer = JavaScriptASTAnalyzer() 
        # Dangerous permissions with detailed explanations
        self.dangerous_permissions = {
            'debugger': {
                'score': 10,
                'description': 'Can debug and inspect other extensions and web pages',
                'risk': 'CRITICAL - Full access to browser internals'
            },
            '<all_urls>': {
                'score': 9,
                'description': 'Access to ALL websites you visit',
                'risk': 'CRITICAL - Can read/modify all web pages'
            },
            'webRequest': {
                'score': 8,
                'description': 'Can intercept all network requests',
                'risk': 'HIGH - Can spy on all your web traffic'
            },
            'webRequestBlocking': {
                'score': 9,
                'description': 'Can block or modify network traffic',
                'risk': 'CRITICAL - Can hijack or block requests'
            },
            'proxy': {
                'score': 8,
                'description': 'Can change proxy settings',
                'risk': 'HIGH - Can route traffic through attacker servers'
            },
            'cookies': {
                'score': 7,
                'description': 'Can access cookies from all sites',
                'risk': 'HIGH - Can steal session tokens'
            },
            'history': {
                'score': 6,
                'description': 'Can read your browsing history',
                'risk': 'MEDIUM - Privacy violation'
            },
            'management': {
                'score': 8,
                'description': 'Can manage other extensions',
                'risk': 'HIGH - Can disable security extensions'
            },
            'nativeMessaging': {
                'score': 7,
                'description': 'Can communicate with native apps',
                'risk': 'HIGH - Can execute system commands'
            },
            'desktopCapture': {
                'score': 8,
                'description': 'Can capture screen content',
                'risk': 'HIGH - Can screenshot sensitive info'
            },
            'tabCapture': {
                'score': 7,
                'description': 'Can capture tab content',
                'risk': 'HIGH - Can record tab activity'
            },
            'clipboardRead': {
                'score': 6,
                'description': 'Can read clipboard data',
                'risk': 'MEDIUM - Can steal copied passwords'
            },
            'geolocation': {
                'score': 5,
                'description': 'Can access your location',
                'risk': 'MEDIUM - Privacy concern'
            },
        }
        
        # Settings override risks
        self.settings_override_risks = {
            'search_provider': 10,
            'homepage': 9,
            'startup_pages': 9,
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.xyz', '.top', '.club', '.online', '.site',
            '.uno', '.pw', '.tk', '.ml', '.ga', '.icu',
            '.bid', '.win', '.review', '.download'
        ]
        
        # Affiliate/tracking parameters
        self.affiliate_markers = [
            'fr=', 'partner=', 'affid=', 'utm_source=',
            'utm_medium=', 'subid=', 'clickid=', 'PC=',
            'aff_id=', 'ref=', 'referrer='
        ]
        
        # Malicious code patterns with better descriptions
        self.malicious_patterns = [
            {
                'name': 'Data Exfiltration via POST',
                'pattern': r'fetch\s*\([^)]*method\s*:\s*["\']POST["\']',
                'severity': 'high',
                'description': 'Sends data to external server (possible data theft)',
                'technique': 'Data exfiltration'
            },
            {
                'name': 'XMLHttpRequest to External Server',
                'pattern': r'new\s+XMLHttpRequest\s*\(',
                'severity': 'medium',
                'description': 'Makes network requests to external servers',
                'technique': 'Network communication'
            },
            {
                'name': 'Dynamic Code Execution (eval)',
                'pattern': r'\beval\s*\(',
                'severity': 'high',
                'description': 'Executes code from strings (severe security risk)',
                'technique': 'Code injection'
            },
            {
                'name': 'Base64 Decode (Obfuscation)',
                'pattern': r'atob\s*\(',
                'severity': 'medium',
                'description': 'Decodes base64 strings (often used to hide malicious code)',
                'technique': 'Code obfuscation'
            },
            {
                'name': 'Dynamic Function Creation',
                'pattern': r'new\s+Function\s*\(',
                'severity': 'high',
                'description': 'Creates functions at runtime (code injection risk)',
                'technique': 'Code injection'
            },
            {
                'name': 'Cookie Theft',
                'pattern': r'document\.cookie',
                'severity': 'high',
                'description': 'Accesses cookies (possible session hijacking)',
                'technique': 'Credential theft'
            },
            {
                'name': 'Keylogger Pattern',
                'pattern': r'addEventListener\s*\(\s*["\']key(press|down)["\']',
                'severity': 'high',
                'description': 'Captures keyboard input (keylogger)',
                'technique': 'Credential theft'
            },
            {
                'name': 'WebAssembly (Potential Crypto Mining)',
                'pattern': r'WebAssembly\.',
                'severity': 'medium',
                'description': 'Uses WebAssembly (can be used for crypto mining)',
                'technique': 'Resource abuse'
            },
            {
                'name': 'Background Worker',
                'pattern': r'new\s+Worker\s*\(',
                'severity': 'low',
                'description': 'Creates background workers',
                'technique': 'Background execution'
            },
            {
                'name': 'localStorage Access',
                'pattern': r'localStorage\.(getItem|setItem)',
                'severity': 'low',
                'description': 'Accesses browser local storage',
                'technique': 'Data persistence'
            },
        ]
    
    def analyze_extension(self, extension_dir):
        """
        Perform complete static analysis on an extension
        """
        extension_dir = Path(extension_dir)
        
        print(f"\n[+] Analyzing: {extension_dir.name}")
        
        # Read manifest
        manifest_path = extension_dir / "manifest.json"
        if not manifest_path.exists():
            print(f"[✗] No manifest.json found")
            return None
        
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
        
        extension_name = manifest.get('name', 'Unknown')
        print(f"[+] Extension: {extension_name}")
        print(f"[+] Version: {manifest.get('version', 'Unknown')}")
        
        # Initialize results
        results = {
            'extension_id': extension_dir.name,
            'name': extension_name,
            'version': manifest.get('version'),
            'manifest_version': manifest.get('manifest_version'),
            'permissions': {},
            'malicious_patterns': [],
            'external_scripts': [],
            'obfuscation_indicators': {},
            'settings_overrides': {},
            'campaign_attribution': None,
            'domain_analysis': [],
            'virustotal_results': [],  # NEW
            'ast_results': {},
            'risk_score': 0,
            'risk_level': 'UNKNOWN'
        }
        
        # Analyze permissions with details
        results['permissions'] = self.analyze_permissions(manifest)
        
        # Analyze settings overrides
        results['settings_overrides'] = self.analyze_settings_overrides(manifest)
        
        # Scan code files
        js_files = list(extension_dir.rglob('*.js'))
        print(f"[+] Scanning {len(js_files)} JavaScript files...")
        # Run AST analysis (CRITICAL - shows exact POST destinations)
        print(f"[+] Running AST analysis...")
        results['ast_results'] = self.ast_analyzer.analyze_directory(extension_dir)
        
        # Merge AST findings into malicious_patterns
        for exfil in results['ast_results'].get('data_exfiltration', []):
            results['malicious_patterns'].append({
                'name': exfil['type'],
                'severity': 'high',
                'description': f"Sends data to {exfil['destination']}",
                'technique': 'Data Exfiltration',
                'file': exfil.get('file', 'Unknown'),  # Fixed: use actual filename from AST
                'line': exfil.get('line', 0),
                'context': exfil.get('evidence', ''),
                'evidence': exfil.get('evidence', ''),  # Add evidence field for code snippet
                'destination': exfil.get('destination'),  # IMPORTANT: exact URL
                'method': exfil.get('method'),
                'data_source': exfil.get('data_source')
            })
        
        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
                
                # Check for malicious patterns
                patterns_found = self.scan_code(code, str(js_file.relative_to(extension_dir)))
                results['malicious_patterns'].extend(patterns_found)
                
                # Check for external scripts
                external = self.find_external_scripts(code, str(js_file.relative_to(extension_dir)))
                results['external_scripts'].extend(external)
                
                # Check for obfuscation
                obfuscation = self.detect_obfuscation(code)
                if obfuscation['is_obfuscated']:
                    results['obfuscation_indicators'][str(js_file.relative_to(extension_dir))] = obfuscation
                    
            except Exception as e:
                print(f"[!] Error scanning {js_file.name}: {e}")
        
        # Check for known campaign membership
        results['campaign_attribution'] = self.detect_campaign_membership(
            manifest, 
            results['settings_overrides'],
            results['domain_analysis']
        )
        
        # Calculate risk score (ENHANCED - will be updated after VT check)
        results['risk_score'] = self.calculate_enhanced_risk_score(results)
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        print(f"[+] Initial Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")
        
        if results['campaign_attribution']:
            campaign = results['campaign_attribution']
            print(f"[!] CAMPAIGN DETECTED: {campaign['name']} (Confidence: {campaign['confidence']})")
        
        return results
    
    def analyze_permissions(self, manifest):
        """Analyze extension permissions with detailed explanations"""
        permissions = manifest.get('permissions', [])
        host_permissions = manifest.get('host_permissions', [])
        optional_permissions = manifest.get('optional_permissions', [])
        
        all_permissions = permissions + host_permissions + optional_permissions
        
        print(f"[+] Permissions: {len(all_permissions)} found")
        
        permission_analysis = {
            'total': len(all_permissions),
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'all': all_permissions,
            'details': {}  # NEW: Detailed info for each permission
        }
        
        for perm in all_permissions:
            # Get permission details
            perm_info = self.dangerous_permissions.get(perm, None)
            
            if perm_info:
                risk_score = perm_info['score']
                permission_analysis['details'][perm] = perm_info
            elif perm.startswith('http'):
                # Host permission
                if perm in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']:
                    risk_score = 9
                    permission_analysis['details'][perm] = {
                        'score': 9,
                        'description': f'Access to all websites',
                        'risk': 'CRITICAL - Can read/modify all web pages'
                    }
                else:
                    risk_score = 3
                    permission_analysis['details'][perm] = {
                        'score': 3,
                        'description': f'Access to {perm}',
                        'risk': 'MEDIUM - Limited site access'
                    }
            else:
                risk_score = 0
                permission_analysis['details'][perm] = {
                    'score': 0,
                    'description': perm,
                    'risk': 'LOW - Standard permission'
                }
            
            if risk_score >= 7:
                permission_analysis['high_risk'].append(perm)
                print(f"  🚩 HIGH RISK: {perm}")
            elif risk_score >= 4:
                permission_analysis['medium_risk'].append(perm)
                print(f"  ⚠️  MEDIUM: {perm}")
            else:
                permission_analysis['low_risk'].append(perm)
        
        return permission_analysis
    
    def analyze_settings_overrides(self, manifest):
        """Analyze chrome_settings_overrides for hijacking"""
        overrides = manifest.get('chrome_settings_overrides', {})
        url_overrides = manifest.get('chrome_url_overrides', {})
        
        findings = {
            'has_overrides': False,
            'search_hijacking': None,
            'homepage_hijacking': None,
            'startup_hijacking': None,
            'newtab_hijacking': None,
            'severity': 'NONE'
        }
        
        if 'search_provider' in overrides:
            findings['has_overrides'] = True
            search_provider = overrides['search_provider']
            search_url = search_provider.get('search_url', '')
            
            affiliate_params = self._detect_affiliate_params(search_url)
            
            findings['search_hijacking'] = {
                'search_url': search_url,
                'name': search_provider.get('name', 'Unknown'),
                'has_affiliate_params': bool(affiliate_params),
                'affiliate_params': affiliate_params,
                'severity': 'CRITICAL' if affiliate_params else 'HIGH'
            }
            
            print(f"  🚨 SEARCH HIJACKING DETECTED: {search_url}")
            if affiliate_params:
                print(f"     Affiliate params: {', '.join(affiliate_params)}")
        
        if 'homepage' in overrides:
            findings['has_overrides'] = True
            findings['homepage_hijacking'] = {
                'url': overrides['homepage'],
                'severity': 'HIGH'
            }
            print(f"  🚨 HOMEPAGE HIJACKING: {overrides['homepage']}")
        
        if 'startup_pages' in overrides:
            findings['has_overrides'] = True
            findings['startup_hijacking'] = {
                'urls': overrides['startup_pages'],
                'severity': 'HIGH'
            }
            print(f"  🚨 STARTUP HIJACKING: {len(overrides['startup_pages'])} pages")
        
        if 'newtab' in url_overrides:
            findings['has_overrides'] = True
            findings['newtab_hijacking'] = {
                'url': url_overrides['newtab'],
                'severity': 'MEDIUM'
            }
            print(f"  ⚠️  NEW TAB OVERRIDE: {url_overrides['newtab']}")
        
        if findings['search_hijacking']:
            findings['severity'] = findings['search_hijacking']['severity']
        elif findings['homepage_hijacking'] or findings['startup_hijacking']:
            findings['severity'] = 'HIGH'
        elif findings['newtab_hijacking']:
            findings['severity'] = 'MEDIUM'
        
        return findings
    
    def _detect_affiliate_params(self, url):
        """Detect affiliate/tracking parameters in URL"""
        found_params = []
        for marker in self.affiliate_markers:
            if marker in url:
                found_params.append(marker.rstrip('='))
        return found_params
    
    def scan_code(self, code, file_path):
        """Scan code for malicious patterns"""
        found_patterns = []
        
        for pattern_def in self.malicious_patterns:
            matches = re.finditer(pattern_def['pattern'], code, re.IGNORECASE)
            
            for match in matches:
                line_num = code[:match.start()].count('\n') + 1
                lines = code.split('\n')
                context_start = max(0, line_num - 2)
                context_end = min(len(lines), line_num + 1)
                context = '\n'.join(lines[context_start:context_end])
                
                found_patterns.append({
                    'name': pattern_def['name'],
                    'severity': pattern_def['severity'],
                    'description': pattern_def['description'],
                    'technique': pattern_def.get('technique', 'Unknown'),
                    'file': file_path,
                    'line': line_num,
                    'context': context[:200]
                })
        
        return found_patterns
    
    def find_external_scripts(self, code, file_path):
        """Find external script URLs"""
        external = []
        url_pattern = r'https?://[^\s\'"<>]+'
        matches = re.finditer(url_pattern, code)
        
        for match in matches:
            url = match.group(0)
            if any(cdn in url for cdn in ['googleapis.com', 'cdnjs.cloudflare.com', 'unpkg.com']):
                continue
            
            external.append({
                'url': url,
                'file': file_path,
                'line': code[:match.start()].count('\n') + 1
            })
        
        return external
    
    def detect_obfuscation(self, code):
        """Detect if code is obfuscated"""
        entropy = self.calculate_entropy(code)
        hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', code))
        unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', code))
        long_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]{50,}\b', code))
        single_letters = len(re.findall(r'\b[a-zA-Z_$]\b', code))
        total_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b', code))
        single_letter_ratio = single_letters / max(total_vars, 1)
        
        is_obfuscated = (
            entropy > 4.5 or
            hex_escapes > 50 or
            unicode_escapes > 50 or
            long_vars > 10 or
            single_letter_ratio > 0.3
        )
        
        return {
            'is_obfuscated': is_obfuscated,
            'entropy': entropy,
            'hex_escapes': hex_escapes,
            'unicode_escapes': unicode_escapes,
            'long_variables': long_vars,
            'single_letter_ratio': single_letter_ratio
        }
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(chr(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
    def detect_campaign_membership(self, manifest, settings_overrides, domain_analysis):
        """Check if extension matches known malicious campaigns"""
        
        if settings_overrides.get('search_hijacking'):
            search_info = settings_overrides['search_hijacking']
            search_url = search_info['search_url'].lower()
            
            if ('yahoo.com/search' in search_url and 'fr=' in search_url):
                return {
                    'name': 'DarkSpectre / ZoomStealer',
                    'confidence': 'HIGH',
                    'indicators': [
                        'Yahoo search hijacking with affiliate parameter (fr=)',
                        'Known DarkSpectre campaign pattern'
                    ],
                    'description': 'Part of campaign that infected 7.8M+ browsers',
                    'reference': 'https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers',
                    'severity': 'CRITICAL'
                }
            
            if ('bing.com/search' in search_url and 'pc=' in search_url.lower()):
                return {
                    'name': 'DarkSpectre / ZoomStealer',
                    'confidence': 'HIGH',
                    'indicators': [
                        'Bing search hijacking with affiliate parameter (PC=)',
                        'Known DarkSpectre campaign pattern'
                    ],
                    'description': 'Part of campaign that infected 7.8M+ browsers',
                    'reference': 'https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers',
                    'severity': 'CRITICAL'
                }
        
        if settings_overrides.get('has_overrides'):
            affiliate_params = []
            if settings_overrides.get('search_hijacking'):
                affiliate_params = settings_overrides['search_hijacking'].get('affiliate_params', [])
            
            if affiliate_params:
                return {
                    'name': 'Search Hijacking Campaign (Generic)',
                    'confidence': 'MEDIUM',
                    'indicators': [
                        f'Search hijacking with affiliate tracking ({", ".join(affiliate_params)})',
                        'Monetization through search redirection'
                    ],
                    'description': 'Affiliate fraud via search engine override',
                    'severity': 'HIGH'
                }
        
        return None
    
    def calculate_enhanced_risk_score(self, results):
        """Enhanced risk calculation (will be updated after VT check)"""
        score = 0
        
        # Settings Override = CRITICAL (0-5 points)
        settings = results.get('settings_overrides', {})
        if settings.get('search_hijacking'):
            if settings['search_hijacking'].get('has_affiliate_params'):
                score += 5
            else:
                score += 4
        elif settings.get('homepage_hijacking') or settings.get('startup_hijacking'):
            score += 3
        elif settings.get('newtab_hijacking'):
            score += 2
        
        # Campaign Attribution (0-2 points)
        if results.get('campaign_attribution'):
            campaign = results['campaign_attribution']
            if campaign['confidence'] == 'HIGH':
                score += 2
            else:
                score += 1
        
        # Permission risk (0-2 points)
        perm_score = (
            len(results['permissions']['high_risk']) * 0.5 +
            len(results['permissions']['medium_risk']) * 0.2
        )
        score += min(perm_score, 2)
        
        # Malicious patterns (0-1 point)
        pattern_score = sum(
            2 if p['severity'] == 'high' else 1 if p['severity'] == 'medium' else 0.5
            for p in results['malicious_patterns']
        ) / 10
        score += min(pattern_score, 1)
        
        return min(score, 10)
    
    def get_risk_level(self, score):
        """Convert risk score to level"""
        if score >= 8:
            return 'CRITICAL'
        elif score >= 6:
            return 'HIGH'
        elif score >= 4:
            return 'MEDIUM'
        elif score >= 2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def update_risk_with_virustotal(self, results, vt_results):
        """Update risk score based on VirusTotal results"""
        
        # Add VT results to analysis
        results['virustotal_results'] = vt_results
        
        # Recalculate risk based on VT findings
        vt_penalty = 0
        
        for vt_result in vt_results:
            if not vt_result.get('available') or not vt_result.get('known'):
                continue
            
            threat_level = vt_result.get('threat_level', 'CLEAN')
            
            if threat_level == 'MALICIOUS':
                vt_penalty += 3  # CRITICAL penalty
            elif threat_level == 'SUSPICIOUS':
                vt_penalty += 1.5
        
        # Update risk score
        results['risk_score'] = min(results['risk_score'] + vt_penalty, 10)
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        return results
    
    def save_report(self, results, output_dir='reports'):
        """Save analysis report to JSON"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        report_path = output_dir / f"{results['extension_id']}_analysis.json"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Report saved: {report_path}")
        return report_path