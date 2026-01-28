"""
Main Analyzer CLI - Professional Edition with VirusTotal Integration
Enhanced with domain intelligence and professional reporting
"""

import argparse
import sys
from pathlib import Path

from downloader import ExtensionDownloader
from unpacker import ExtensionUnpacker
from static_analyzer import EnhancedStaticAnalyzer
from domain_intelligence import DomainIntelligence
from professional_report import ProfessionalReportGenerator
from virustotal_checker import VirusTotalChecker
from pii_classifier import PIIClassifier
from ioc_manager import IOCManager
from advanced_detection import AdvancedDetector
from cuckoo_sandbox import CuckooSandbox
from store_metadata import StoreMetadata
from threat_attribution import ThreatAttribution
from false_positive_filter import FalsePositiveFilter
from host_permissions_analyzer import HostPermissionsAnalyzer

class ChromeExtensionAnalyzer:
    """Main analyzer orchestrator with professional-grade analysis"""
    
    def __init__(self):
        self.downloader = ExtensionDownloader()
        self.unpacker = ExtensionUnpacker()
        self.analyzer = EnhancedStaticAnalyzer()
        self.domain_intel = DomainIntelligence()
        self.reporter = ProfessionalReportGenerator()
        self.vt_checker = VirusTotalChecker()
        self.pii_classifier = PIIClassifier()
        self.ioc_manager = IOCManager()
        self.advanced_detector = AdvancedDetector()
        self.cuckoo = CuckooSandbox()
        self.store_metadata = StoreMetadata()
        self.threat_attribution = ThreatAttribution()
        self.false_positive_filter = FalsePositiveFilter()
        self.host_permissions_analyzer = HostPermissionsAnalyzer()
    
    def analyze_extension(self, extension_id):
        """
        Complete analysis pipeline with professional threat intelligence
        
        Args:
            extension_id (str): Chrome extension ID
            
        Returns:
            dict: Comprehensive analysis results
        """
        print("=" * 80)
        print("[SCAN] CHROME EXTENSION SECURITY ANALYZER")
        print("    Professional Threat Intelligence Edition with VirusTotal")
        print("=" * 80)
        print(f"\n[+] Target Extension ID: {extension_id}\n")

        # Step 0: Fetch Chrome Web Store Metadata
        print("[STORE] STEP 0: Fetching Chrome Web Store metadata...")
        print("-" * 80)
        store_metadata = self.store_metadata.fetch_metadata(extension_id)

        if store_metadata.get('available'):
            print(f"[+] Extension: {store_metadata.get('name', 'Unknown')}")
            print(f"    Author: {store_metadata.get('author', 'Unknown')} {'(verified)' if store_metadata.get('author_verified') else '(unverified)'}")
            print(f"    Users: {store_metadata.get('user_count_text', 'Unknown')}")
            print(f"    Rating: {store_metadata.get('rating', 'N/A')}")
            print(f"    Last Updated: {store_metadata.get('last_updated_text', 'Unknown')}")

            # Check for Chrome warnings (policy violations)
            if store_metadata.get('has_chrome_warning'):
                print(f"\n[!] CHROME POLICY WARNING: {store_metadata.get('chrome_warning')}")
                print(f"    Note: This is a policy violation, not necessarily malware")

            # Check risk signals
            risk_signals = store_metadata.get('risk_signals', {})
            if risk_signals.get('low_adoption'):
                print(f"[i] Low adoption: <100 users (increased risk)")
            if risk_signals.get('no_privacy_policy'):
                print(f"[i] No privacy policy found")
        else:
            print(f"[!] Could not fetch store metadata: {store_metadata.get('error', 'Unknown error')}")
            print(f"    Continuing with analysis...")

        # Step 1: Download
        print("[DOWNLOAD] STEP 1: Downloading extension...")
        print("-" * 80)
        crx_path = self.downloader.download_extension(extension_id)
        
        if not crx_path:
            print("\n[[X]] Download failed. Extension may not exist or be unavailable.")
            return None
        
        # Step 2: Unpack
        print("\n[UNPACK] STEP 2: Unpacking extension...")
        print("-" * 80)
        extension_dir = self.unpacker.unpack(crx_path)
        
        if not extension_dir:
            print("\n[[X]] Unpacking failed.")
            return None
        
        # Read manifest
        manifest = self.unpacker.read_manifest(extension_dir)

        if not manifest:
            print("\n[[X]] Failed to read manifest.json")
            return None

        # Step 2.5: Host Permissions Analysis
        print("\n[PERMISSIONS] STEP 2.5: Analyzing host permissions...")
        print("-" * 80)
        manifest_path = extension_dir / 'manifest.json'
        host_permissions = self.host_permissions_analyzer.analyze_manifest(manifest_path)

        print(f"[+] Permission Scope: {host_permissions['permission_scope']}")
        print(f"[+] Risk Assessment: {host_permissions['risk_assessment']['overall_risk']}")

        stats = host_permissions['statistics']
        print(f"    • Host Permissions: {stats['total_host_permissions']}")
        print(f"    • Content Scripts: {stats['total_content_scripts']}")

        if host_permissions['all_urls_access']:
            print(f"[!] CRITICAL: Extension has <all_urls> access - can read/modify ALL websites!")

        if host_permissions['sensitive_access']:
            print(f"[!] Accesses {stats['total_sensitive_domains']} sensitive domain(s) across {stats['total_sensitive_categories']} categories")
            for category, domains in list(host_permissions['sensitive_access'].items())[:2]:
                print(f"    • {category.replace('_', ' ').title()}: {len(domains)} domain(s)")

        # Step 3: Static Analysis
        print("\n[SCAN] STEP 3: Performing static analysis...")
        print("-" * 80)
        results = self.analyzer.analyze_extension(extension_dir)

        if not results:
            print("\n[[X]] Analysis failed.")
            return None

        # Add store metadata and host permissions to results
        results['store_metadata'] = store_metadata
        results['host_permissions'] = host_permissions
        
        # Step 4: Domain Intelligence Analysis
        print("\n[DOMAIN] STEP 4: Domain intelligence analysis...")
        print("-" * 80)
        domain_intelligence = self._analyze_domain_intelligence(results)
        results['domain_intelligence'] = domain_intelligence
        
        # Print domain analysis summary
        threats = [d for d in domain_intelligence if d['threat_level'] in ['CRITICAL', 'HIGH']]
        if threats:
            print(f"[!] {len(threats)} suspicious domains detected (before VirusTotal):")
            for domain in threats[:5]:
                print(f"    • {domain['domain']} - {domain['classification']} ({domain['threat_level']})")
            if len(threats) > 5:
                print(f"    ... and {len(threats) - 5} more")
        else:
            print("[[OK]] No obviously malicious domains detected")
        
        # Step 5: VirusTotal Domain Reputation Check
        print("\n[VT]  STEP 5: VirusTotal domain reputation check...")
        print("-" * 80)
        vt_results = self._check_virustotal(results)

        # Update risk score based on VT results
        results = self.analyzer.update_risk_with_virustotal(results, vt_results)

        print(f"\n[+] Updated Risk Score (with VirusTotal): {results['risk_score']:.1f}/10 ({results['risk_level']})")

        # Step 5.5: Dynamic Analysis with Cuckoo Sandbox
        print("\n[CUCKOO] STEP 5.5: Dynamic analysis (Cuckoo Sandbox)...")
        print("-" * 80)
        dynamic_evidence = self._run_cuckoo_analysis(extension_dir, extension_id)

        if dynamic_evidence and dynamic_evidence.get('available'):
            print(f"[+] Dynamic analysis complete: {dynamic_evidence.get('verdict', 'Unknown')}")
            print(f"    Risk Score: {dynamic_evidence.get('dynamic_risk_score', 0)}/10")

            if dynamic_evidence.get('malicious_indicators'):
                print(f"[!] {len(dynamic_evidence['malicious_indicators'])} malicious behavior(s) detected:")
                for indicator in dynamic_evidence['malicious_indicators'][:3]:
                    print(f"    • {indicator.get('description', 'Unknown')}")

            # Update risk score based on dynamic analysis
            dynamic_risk = dynamic_evidence.get('dynamic_risk_score', 0)
            if dynamic_risk >= 8:
                results['risk_score'] = min(10.0, results['risk_score'] + 2.5)
            elif dynamic_risk >= 5:
                results['risk_score'] = min(10.0, results['risk_score'] + 1.5)

            results['dynamic_analysis'] = dynamic_evidence
        else:
            print("[i] Cuckoo Sandbox not available or disabled")
            dynamic_evidence = None

        # Step 6: Advanced Malware Detection (with dynamic evidence)
        print("\n[ADVANCED] STEP 6: Advanced malware detection...")
        print("-" * 80)
        advanced_findings = self.advanced_detector.run_all_detections(extension_dir, dynamic_evidence=dynamic_evidence)
        results['advanced_detection'] = advanced_findings

        # Update risk score based on advanced detection
        if advanced_findings['summary']['critical_findings'] > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
            print(f"[!] CRITICAL: {advanced_findings['summary']['critical_findings']} confirmed malware technique(s) detected!")
        elif advanced_findings['summary']['high_findings'] > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 1.5)
            print(f"[!] HIGH: {advanced_findings['summary']['high_findings']} suspicious technique(s) detected")
        else:
            print("[[OK]] No advanced malware techniques detected")

        # Step 7: PII/Data Classification
        print("\n[PII] STEP 7: PII/data classification...")
        print("-" * 80)
        pii_analysis = self._classify_pii_exfiltration(results)
        results['pii_classification'] = pii_analysis

        if pii_analysis.get('overall_risk') == 'CRITICAL':
            print(f"[!] CRITICAL: Exfiltrates {pii_analysis['data_types_count']} type(s) of sensitive data")
            print(f"    Action: {pii_analysis['recommendation']['action']}")
        elif pii_analysis.get('data_types_count', 0) > 0:
            print(f"[!] Accesses {pii_analysis['data_types_count']} type(s) of user data")
        else:
            print("[[OK]] No sensitive data exfiltration detected")

        # Step 8: IOC Management
        print("\n[IOC] STEP 8: Updating IOC database...")
        print("-" * 80)
        self._update_ioc_database(results, vt_results, extension_id)

        # Step 8.5: Threat Attribution
        print("\n[ATTRIBUTION] STEP 8.5: Threat campaign attribution...")
        print("-" * 80)
        attribution = self._check_threat_attribution(extension_id, results.get('name', 'Unknown'))

        if attribution:
            results['threat_attribution'] = attribution

            # Elevate risk score based on attribution findings
            confidence = attribution.get('confidence', 'NONE')
            attribution_found = attribution.get('attribution_found', False)

            if confidence == 'CONFIRMED':
                # Database match - CRITICAL
                print(f"[!] CRITICAL: Extension found in known malicious database!")
                print(f"    Campaign: {attribution.get('campaign_name', 'Unknown')}")
                print(f"    Threat Actor: {attribution.get('threat_actor', 'Unknown')}")
                results['risk_score'] = min(10.0, results['risk_score'] + 4.0)
                results['risk_level'] = 'CRITICAL'
            elif confidence == 'HIGH' and attribution_found:
                # Campaign detected via web search
                print(f"[!] HIGH: Campaign detected via OSINT web search!")
                print(f"    Campaign: {attribution.get('campaign_name', 'Unknown')}")
                results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
                if results['risk_level'] not in ['CRITICAL']:
                    results['risk_level'] = 'HIGH'
            elif confidence == 'MEDIUM' and attribution_found:
                # Malicious indicators found via web search
                print(f"[!] MEDIUM: Malicious indicators found in web search results")
                results['risk_score'] = min(10.0, results['risk_score'] + 2.0)
                if results['risk_level'] not in ['CRITICAL', 'HIGH']:
                    results['risk_level'] = 'HIGH'
            elif confidence == 'LOW':
                # Mentions found but no clear malicious indicators
                print(f"[i] LOW: Extension mentioned in web searches (no clear malicious indicators)")
            else:
                print(f"[i] No threat attribution found - checking search queries...")
                if attribution.get('search_queries'):
                    first_query = attribution['search_queries'][0]
                    print(f"    Search: {first_query['search_url']}")

        # Step 9: Generate Reports
        print("\n[REPORT] STEP 9: Generating professional reports...")
        print("-" * 80)
        
        # Save JSON report (detailed data)
        json_report = self.analyzer.save_report(results)
        
        # Generate professional HTML report
        html_report = self.reporter.save_professional_report(results)
        
        # Print Summary
        self._print_analysis_summary(results)
        
        print(f"\n[FILES] Reports generated:")
        print(f"   • JSON (Technical): {json_report}")
        print(f"   • HTML (Professional): {html_report}")
        
        # Print Verdict
        self._print_verdict(results)
        
        return results
    def _analyze_domain_intelligence(self, results):
        """Analyze all external domains with threat intelligence"""
        
        external_scripts = results.get('external_scripts', [])
        domain_intelligence = []
        
        # Analyze each unique domain
        seen_domains = set()
        
        for script in external_scripts:
            url = script.get('url', '')
            
            # Parse domain
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                
                if not domain or domain in seen_domains:
                    continue
                
                seen_domains.add(domain)
                
                # Perform domain intelligence analysis
                assessment = self.domain_intel.analyze_domain(
                    domain=domain,
                    url=url,
                    context={'file': script.get('file'), 'line': script.get('line')}
                )
                
                domain_intelligence.append(assessment)
                
            except Exception as e:
                continue
        
        return domain_intelligence
    
    def _check_virustotal(self, results):
        """Check all domains against VirusTotal"""
        
        # Extract unique domains from external scripts
        external_scripts = results.get('external_scripts', [])
        unique_domains = set()
        
        for script in external_scripts:
            url = script.get('url', '')
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    unique_domains.add(domain)
            except:
                pass
        
        if not unique_domains:
            print("[i] No external domains to check")
            return []
        
        # Check domains with VirusTotal
        vt_results = self.vt_checker.check_multiple_domains(
            list(unique_domains),
            max_checks=10  # Limit to 10 to avoid rate limits
        )

        # Apply false positive filtering
        filtered = self.false_positive_filter.filter_virustotal_results(vt_results)
        vt_results = filtered['filtered_results']

        # Print suppression info
        if filtered['suppression_count'] > 0:
            print(f"[i] Suppressed {filtered['suppression_count']} known benign domain(s):")
            for suppressed in filtered['suppressed_false_positives'][:3]:
                print(f"    • {suppressed['domain']} - {suppressed['reason']}")
            if filtered['suppression_count'] > 3:
                print(f"    ... and {filtered['suppression_count'] - 3} more")

        # Print summary of malicious findings
        malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        suspicious = [r for r in vt_results if r.get('threat_level') == 'SUSPICIOUS']
        
        if malicious:
            print(f"\n[!]  VIRUSTOTAL ALERT: {len(malicious)} MALICIOUS domain(s) detected!")
            for result in malicious:
                print(f"    [ALERT] {result['domain']}")
                print(f"       • Detections: {result['stats']['malicious']} vendors")
                print(f"       • Community: {result['votes']['malicious']} malicious votes")
                if result.get('malicious_vendors'):
                    vendors = [v['vendor'] for v in result['malicious_vendors'][:3]]
                    print(f"       • Flagged by: {', '.join(vendors)}")
        
        if suspicious:
            print(f"\n[!]  VirusTotal: {len(suspicious)} suspicious domain(s)")
            for result in suspicious:
                print(f"    • {result['domain']} - {result['stats']['suspicious']} flags")
        
        return vt_results
    
    def _print_analysis_summary(self, results):
        """Print analysis summary"""
        
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        
        print("\n" + "=" * 80)
        print("[IOC] ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"\n[TARGET] Extension: {results['name']}")
        print(f"[INFO] Version: {results['version']}")
        print(f"[!]  Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")
        
        # VirusTotal Results
        malicious_domains = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        if malicious_domains:
            print(f"\n[ALERT] VIRUSTOTAL: {len(malicious_domains)} MALICIOUS DOMAIN(S) DETECTED")
            for result in malicious_domains[:3]:
                print(f"   +- {result['domain']}: {result['stats']['malicious']} detections")
        
        # Campaign Attribution
        if campaign:
            print(f"\n[ALERT] CAMPAIGN DETECTED: {campaign['name']}")
            print(f"   +- Confidence: {campaign['confidence']} | Severity: {campaign['severity']}")
            print(f"   +- Description: {campaign.get('description', 'N/A')}")
            for indicator in campaign.get('indicators', [])[:3]:
                print(f"      • {indicator}")
            if campaign.get('reference'):
                print(f"   +- Reference: {campaign['reference']}")
        
        # Settings Overrides
        if settings.get('has_overrides'):
            print(f"\n[!]  BROWSER HIJACKING DETECTED:")
            
            if settings.get('search_hijacking'):
                search = settings['search_hijacking']
                print(f"   +- Search Engine: {search['search_url']}")
                if search.get('affiliate_params'):
                    print(f"      • Affiliate Fraud: {', '.join(search['affiliate_params'])}")
            
            if settings.get('homepage_hijacking'):
                print(f"   +- Homepage Override: {settings['homepage_hijacking']['url']}")
            
            if settings.get('startup_hijacking'):
                urls = settings['startup_hijacking']['urls']
                print(f"   +- Startup Pages: {len(urls)} page(s)")
        
        # Statistics
        permissions = results.get('permissions', {})
        patterns = results.get('malicious_patterns', [])
        domain_intel = results.get('domain_intelligence', [])
        advanced = results.get('advanced_detection', {}).get('summary', {})
        pii = results.get('pii_classification', {})

        print(f"\n[STATS] Statistics:")
        print(f"   • High-Risk Permissions: {len(permissions.get('high_risk', []))}")
        print(f"   • Critical Code Patterns: {len([p for p in patterns if p['severity'] == 'high'])}")
        print(f"   • Suspicious Domains: {len([d for d in domain_intel if d['threat_level'] in ['CRITICAL', 'HIGH']])}")
        print(f"   • VirusTotal Malicious: {len(malicious_domains)}")
        print(f"   • Advanced Techniques: {advanced.get('critical_findings', 0)} critical, {advanced.get('high_findings', 0)} high")
        print(f"   • PII Data Types: {pii.get('data_types_count', 0)} ({pii.get('overall_risk', 'NONE')} risk)")
    def _print_verdict(self, results):
        """Print final verdict"""

        campaign = results.get('campaign_attribution')
        risk_level = results.get('risk_level')
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        advanced = results.get('advanced_detection', {})
        advanced_critical = advanced.get('summary', {}).get('critical_findings', 0)
        pii = results.get('pii_classification', {})

        print(f"\n{'=' * 80}")

        if advanced_critical > 0:
            print(f"[BLOCK] VERDICT: CONFIRMED MALWARE - ADVANCED TECHNIQUES DETECTED")
            print(f"   +- {advanced_critical} confirmed malware technique(s) found")
            # Show specific techniques
            if advanced.get('csp_manipulation'):
                print(f"   +- CSP Manipulation: Removes security headers (RCE capability)")
            if advanced.get('dom_event_injection'):
                print(f"   +- DOM Event Injection: Remote code execution bypass")
            print(f"   +- IMMEDIATE ACTION: Block and quarantine immediately")
            print(f"   +- This is confirmed malicious behavior per industry research")
        elif vt_malicious:
            print(f"[BLOCK] VERDICT: CRITICAL THREAT - VIRUSTOTAL CONFIRMED MALICIOUS")
            print(f"   +- {len(vt_malicious)} domain(s) flagged as malicious by security vendors")
            print(f"   +- IMMEDIATE ACTION: Block this extension immediately")
            print(f"   +- Investigate data compromise on affected systems")
        elif pii.get('overall_risk') == 'CRITICAL':
            print(f"[BLOCK] VERDICT: CRITICAL THREAT - EXFILTRATES SENSITIVE DATA")
            print(f"   +- Exfiltrates {pii.get('data_types_count', 0)} type(s) of critical data")
            print(f"   +- {pii.get('recommendation', {}).get('action', 'BLOCK IMMEDIATELY')}")
            print(f"   +- IMMEDIATE ACTION: Remove and investigate data access")
        elif campaign:
            print(f"[BLOCK] VERDICT: CRITICAL THREAT - KNOWN MALICIOUS CAMPAIGN")
            print(f"   +- Campaign: {campaign['name']}")
            print(f"   +- IMMEDIATE ACTION: Block across all enterprise devices")
            print(f"   +- Investigate potential data compromise")
        elif risk_level == 'CRITICAL':
            print(f"[BLOCK] VERDICT: CRITICAL RISK - BLOCK IMMEDIATELY")
            print(f"   +- This extension poses a severe security threat")
            print(f"   +- Do NOT deploy under any circumstances")
        elif risk_level == 'HIGH':
            print(f"[ALERT] VERDICT: HIGH RISK - BLOCK THIS EXTENSION")
            print(f"   +- Significant security concerns detected")
            print(f"   +- Not recommended for deployment")
        elif risk_level == 'MEDIUM':
            print(f"[!]  VERDICT: MEDIUM RISK - MANUAL REVIEW REQUIRED")
            print(f"   +- Security review recommended before deployment")
            print(f"   +- Test in isolated environment first")
        elif risk_level == 'LOW':
            print(f"[WARN] VERDICT: LOW RISK - MONITOR")
            print(f"   +- Extension appears relatively safe")
            print(f"   +- Monitor for updates and behavioral changes")
        else:
            print(f"[OK] VERDICT: MINIMAL RISK")
            print(f"   +- No significant threats detected")
            print(f"   +- Safe for deployment with standard monitoring")
        
        print(f"{'=' * 80}\n")

    def _classify_pii_exfiltration(self, results):
        """Classify PII/sensitive data being accessed or exfiltrated"""

        # Gather evidence for classification
        evidence = {
            'chrome_apis': [],
            'code_snippets': [],
            'destination': 'Unknown',
            'method': 'Unknown'
        }

        # Extract Chrome API usage from permissions
        permissions = results.get('permissions', {})
        all_permissions = (
            permissions.get('high_risk', []) +
            permissions.get('medium_risk', []) +
            permissions.get('low_risk', [])
        )

        for perm_data in all_permissions:
            # Handle both string and dict formats
            if isinstance(perm_data, str):
                perm = perm_data
            else:
                perm = perm_data.get('permission', '')

            # Add Chrome API equivalents
            if perm in ['cookies', 'webRequest', 'history', 'tabs', 'clipboardRead', 'geolocation']:
                evidence['chrome_apis'].append(f'chrome.{perm}')

        # Extract code evidence from malicious patterns
        patterns = results.get('malicious_patterns', [])
        for pattern in patterns:
            if pattern.get('evidence'):
                evidence['code_snippets'].append(pattern['evidence'])

        # Get AST analysis for better destination info
        ast_analysis = results.get('ast_analysis', {})
        data_flows = ast_analysis.get('data_flows', [])

        if data_flows:
            # Use first POST destination
            for flow in data_flows:
                if flow.get('destination') != 'Unknown':
                    evidence['destination'] = flow['destination']
                    evidence['method'] = flow.get('method', 'POST')
                    break

        # Also check external scripts for destinations
        if evidence['destination'] == 'Unknown':
            external_scripts = results.get('external_scripts', [])
            if external_scripts:
                evidence['destination'] = external_scripts[0].get('url', 'Unknown')

        # Perform classification
        classification = self.pii_classifier.classify_exfiltration(evidence)

        return classification

    def _update_ioc_database(self, results, vt_results, extension_id):
        """Update IOC database with findings"""

        # Add domains to IOC database if they're malicious
        pii_classifications = results.get('pii_classification', {}).get('classifications', [])

        for vt_result in vt_results:
            if vt_result.get('available') and vt_result.get('known'):
                added = self.ioc_manager.add_domain_ioc(
                    vt_result,
                    extension_id,
                    pii_classifications
                )

                if added:
                    domain = vt_result.get('domain')
                    # Check if domain was already in IOC database
                    ioc_entry = self.ioc_manager.check_domain(domain)
                    if ioc_entry and ioc_entry.get('total_observations', 1) > 1:
                        print(f"[!] Domain {domain} was previously flagged (observation #{ioc_entry['total_observations']})")

        # Add extension to IOC database if high risk
        risk_score = results.get('risk_score', 0)
        if risk_score >= 6.0:
            malicious_domains = [
                r['domain'] for r in vt_results
                if r.get('threat_level') == 'MALICIOUS'
            ]

            suspicious_patterns = [
                p.get('name', p.get('pattern', 'Unknown'))
                for p in results.get('malicious_patterns', [])
                if p.get('severity') == 'high'
            ]

            # Handle both string and dict formats for permissions
            high_risk_perms = results.get('permissions', {}).get('high_risk', [])
            dangerous_permissions = [
                p if isinstance(p, str) else p.get('permission', '')
                for p in high_risk_perms
            ]

            extension_data = {
                'extension_id': extension_id,
                'name': results.get('name', 'Unknown'),
                'version': results.get('version', 'Unknown'),
                'risk_score': risk_score,
                'malicious_domains': malicious_domains,
                'suspicious_patterns': suspicious_patterns[:10],  # Top 10
                'dangerous_permissions': dangerous_permissions
            }

            self.ioc_manager.add_extension_ioc(extension_data)

        # Print IOC stats
        stats = self.ioc_manager.get_statistics()
        print(f"[IOC] Database now contains {stats['total_domains']} domains, {stats['total_extensions']} extensions")

    def _run_cuckoo_analysis(self, extension_dir, extension_id):
        """Run dynamic analysis with Cuckoo Sandbox"""
        try:
            # Submit extension to Cuckoo for analysis
            result = self.cuckoo.submit_extension(extension_dir, extension_id, timeout=300)
            return result
        except Exception as e:
            # Cuckoo might not be available - that's OK
            print(f"[i] Cuckoo analysis skipped: {str(e)}")
            return None

    def _check_threat_attribution(self, extension_id, extension_name):
        """Check if extension mentioned in known threat campaigns"""
        try:
            # Extract domains from results for campaign matching
            attribution = self.threat_attribution.search_threat_campaigns(extension_id, extension_name)
            return attribution
        except Exception as e:
            print(f"[!] Threat attribution failed: {str(e)}")
            return None


def main():
    """CLI entry point"""
    
    parser = argparse.ArgumentParser(
        description='Professional Chrome Extension Security Analyzer with VirusTotal',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze uBlock Origin
  python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm
  
  # Analyze a suspicious extension
  python src/analyzer.py eebihieclccoidddmjcencomodomdoei
  
Features:
  [OK] Chrome Web Store metadata collection
  [OK] Cuckoo Sandbox dynamic analysis
  [OK] False positive suppression (Firebase, jQuery, CDNs)
  [OK] Threat campaign attribution via web search
  [OK] VirusTotal domain reputation checking
  [OK] Campaign attribution (DarkSpectre, ZoomStealer, SpyVPN, etc.)
  [OK] Domain intelligence (C2, DGA, typosquatting detection)
  [OK] Professional threat intelligence reports
  [OK] PII/data classification analysis
  [OK] Advanced malware detection (CSP manipulation, DOM injection, etc.)
  [OK] IOC database management
  [OK] Permission combination risk analysis
  [OK] 64+ malicious code pattern detection
        """
    )
    
    parser.add_argument(
        'extension_id',
        help='Chrome extension ID (32-character string from Chrome Web Store URL)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports/)'
    )
    
    args = parser.parse_args()
    
    # Validate extension ID format
    if len(args.extension_id) != 32:
        print(f"[!] Warning: Extension ID should be 32 characters long.")
        print(f"[!] Provided ID: {args.extension_id} ({len(args.extension_id)} characters)")
        response = input("[?] Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("[[X]] Aborted.")
            sys.exit(1)
    
    # Run analysis
    print("""
    ========================================================================
       CHROME EXTENSION SECURITY ANALYZER - PROFESSIONAL EDITION
       Threat Intelligence Platform with VirusTotal Integration
    ========================================================================
    """)
    
    analyzer = ChromeExtensionAnalyzer()
    results = analyzer.analyze_extension(args.extension_id)
    
    if results:
        # Exit code based on risk level
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        
        if vt_malicious or results.get('campaign_attribution') or results['risk_level'] == 'CRITICAL':
            sys.exit(3)  # Critical threat
        elif results['risk_level'] == 'HIGH':
            sys.exit(2)  # High risk
        elif results['risk_level'] == 'MEDIUM':
            sys.exit(1)  # Medium risk
        else:
            sys.exit(0)  # Low/Minimal risk
    else:
        sys.exit(4)  # Analysis failed


if __name__ == "__main__":
    main()
