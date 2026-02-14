"""
Main Analyzer CLI - Professional Edition with VirusTotal Integration
Enhanced with domain intelligence and professional reporting
Supports Chrome, Edge, and VSCode extension analysis
"""

import argparse
import sys
from pathlib import Path

from downloader import ExtensionDownloader, BrowserType
from unpacker import ExtensionUnpacker
from static_analyzer import EnhancedStaticAnalyzer
from domain_intelligence import DomainIntelligence
from professional_report import ProfessionalReportGenerator
from virustotal_checker import VirusTotalChecker
from pii_classifier import PIIClassifier
from ioc_manager import IOCManager
from advanced_detection import AdvancedDetector
from store_metadata import StoreMetadata
from enhanced_detection import EnhancedDetectionEngine, WalletHijackDetector, PhishingDetector
from taint_analyzer import TaintAnalyzer
from threat_attribution import ThreatAttribution
from false_positive_filter import FalsePositiveFilter
from host_permissions_analyzer import HostPermissionsAnalyzer
from behavioral_engine import BrowserBehavioralEngine
from version_diff import VersionDiffAnalyzer
from sensitive_target_detector import SensitiveTargetDetector
from campaign_detector import CampaignFingerprinter

try:
    from network_capture import NetworkCaptureAnalyzer
    NETWORK_CAPTURE_AVAILABLE = True
except ImportError:
    NETWORK_CAPTURE_AVAILABLE = False

# VSCode extension analysis modules
try:
    from vscode_downloader import VSCodeExtensionDownloader
    from vscode_unpacker import VSCodeExtensionUnpacker
    from vscode_analyzer import VSCodeStaticAnalyzer
    VSCODE_AVAILABLE = True
except ImportError:
    VSCODE_AVAILABLE = False

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
        self.store_metadata = StoreMetadata()
        self.threat_attribution = ThreatAttribution()
        self.false_positive_filter = FalsePositiveFilter()
        self.host_permissions_analyzer = HostPermissionsAnalyzer()
        self.network_capture = NetworkCaptureAnalyzer() if NETWORK_CAPTURE_AVAILABLE else None
        self.enhanced_detector = EnhancedDetectionEngine()
        self.taint_analyzer = TaintAnalyzer()
        self.wallet_detector = WalletHijackDetector()
        self.phishing_detector = PhishingDetector()
        self.behavioral_engine = BrowserBehavioralEngine()
        self.version_diff = VersionDiffAnalyzer()
        self.sensitive_target_detector = SensitiveTargetDetector()
        self.campaign_fingerprinter = CampaignFingerprinter()

        # Runtime flags (can be overridden after construction)
        self.skip_vt = False
        self.skip_osint = False
        self.run_dynamic = False
        self.dynamic_timeout = 30
    
    def analyze_extension(self, extension_id, browser=BrowserType.CHROME):
        """
        Complete analysis pipeline with professional threat analysis

        Args:
            extension_id (str): Browser extension ID
            browser (BrowserType): Browser store (CHROME or EDGE)

        Returns:
            dict: Comprehensive analysis results
        """
        browser_name = browser.value.upper()
        print("=" * 80)
        print(f"[SCAN] {browser_name} EXTENSION SECURITY ANALYZER")
        print("    Professional Threat Analysis Edition with VirusTotal")
        print("=" * 80)
        print(f"\n[+] Target Extension ID: {extension_id}")
        print(f"[+] Extension Store: {browser_name}\n")

        # Step 0: Fetch Store Metadata
        store_name = "Edge Add-ons" if browser == BrowserType.EDGE else "Chrome Web Store"
        print(f"[STORE] STEP 0: Fetching {store_name} metadata...")
        print("-" * 80)

        if browser == BrowserType.EDGE:
            # For Edge, use edge-specific metadata fetcher
            store_metadata = self._fetch_edge_metadata(extension_id)
        else:
            store_metadata = self.store_metadata.fetch_metadata(extension_id)

        if store_metadata.get('available'):
            print(f"[+] Extension: {store_metadata.get('name', 'Unknown')}")
            print(f"    Author: {store_metadata.get('author', 'Unknown')} {'(verified)' if store_metadata.get('author_verified') else '(unverified)'}")
            print(f"    Users: {store_metadata.get('user_count_text', 'Unknown')}")
            print(f"    Rating: {store_metadata.get('rating', 'N/A')}")
            print(f"    Last Updated: {store_metadata.get('last_updated_text', 'Unknown')}")

            # Check for store warnings (policy violations)
            if store_metadata.get('has_chrome_warning') or store_metadata.get('has_warning'):
                warning = store_metadata.get('chrome_warning') or store_metadata.get('warning')
                print(f"\n[!] STORE WARNING: {warning}")
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
        print(f"[DOWNLOAD] STEP 1: Downloading {browser_name} extension...")
        print("-" * 80)
        crx_path = self.downloader.download_extension(extension_id, browser=browser)
        
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

        # Step 2.6: Sensitive Target Detection
        sensitive_results = self.sensitive_target_detector.analyze(manifest, extension_dir)
        if sensitive_results.get('targets'):
            cats = sensitive_results.get('categories', [])
            print(f"\n[SENSITIVE] {len(sensitive_results['targets'])} sensitive target(s) detected: "
                  f"{', '.join(cats)}")
            for t in sensitive_results['targets'][:5]:
                print(f"    [{t['severity']}] {t['category']}: {t['domain']}")
        if sensitive_results.get('gmail_module'):
            for gm in sensitive_results['gmail_module']:
                print(f"    [CRITICAL] Gmail surveillance module: {gm['file']} "
                      f"({gm['indicator_count']} indicators)")

        # Step 3: Static Analysis
        print("\n[SCAN] STEP 3: Performing static analysis...")
        print("-" * 80)
        results = self.analyzer.analyze_extension(extension_dir)

        if not results:
            print("\n[[X]] Analysis failed.")
            return None

        # Add store metadata, host permissions, and sensitive targets to results
        results['store_metadata'] = store_metadata
        results['host_permissions'] = host_permissions
        results['sensitive_targets'] = sensitive_results

        # Apply false positive filtering to malicious pattern detections
        raw_patterns = results.get('malicious_patterns', [])
        if raw_patterns:
            # Detect Firebase usage to provide context
            uses_firebase = self._detect_firebase_usage(results)
            fp_context = {'uses_firebase': uses_firebase}
            fp_result = self.false_positive_filter.filter_malicious_patterns(raw_patterns, context=fp_context)
            results['malicious_patterns'] = fp_result['filtered_patterns']
            if fp_result['suppression_count'] > 0:
                print(f"[i] Suppressed {fp_result['suppression_count']} false positive pattern(s)")

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

        # Step 5.5: Dynamic Network Capture (optional, --dynamic flag)
        if getattr(self, 'run_dynamic', False) and self.network_capture:
            print("\n[NETWORK] STEP 5.5: Dynamic network capture analysis...")
            print("-" * 80)

            # Extract domains from host_permissions and content_scripts
            hp_domains = []
            hp_data = results.get('host_permissions', {})
            if isinstance(hp_data, dict):
                for entry in hp_data.get('host_permissions', []):
                    host = entry.get('host', '')
                    if host:
                        hp_domains.append(host)
                for cs in hp_data.get('content_scripts', []):
                    for match in cs.get('matches', []):
                        # Parse match patterns like *://*.zoom.us/*
                        try:
                            from urllib.parse import urlparse
                            # Strip scheme wildcards for parsing
                            clean = match.replace('*://', 'https://').replace('/*', '/')
                            parsed = urlparse(clean)
                            if parsed.netloc:
                                hp_domains.append(parsed.netloc)
                        except Exception:
                            pass

            network_results = self.network_capture.analyze(
                extension_dir=str(extension_dir),
                extension_id=extension_id,
                timeout=getattr(self, 'dynamic_timeout', 30),
                host_permission_domains=hp_domains
            )
            results['network_capture'] = network_results

            if network_results.get('available'):
                summary = network_results.get('summary', {})
                verdict = network_results.get('verdict', 'CLEAN')
                print(f"[+] Captured {summary.get('total_requests', 0)} total requests")
                print(f"[+] Extension-initiated: {summary.get('extension_requests', 0)}")
                print(f"[+] Scored suspicious: {summary.get('suspicious_count', 0)} "
                      f"(high-score: {summary.get('high_score_count', 0)})")

                if summary.get('beaconing_detected'):
                    beacons = network_results.get('beaconing', [])
                    print(f"[!] BEACONING: {len(beacons)} endpoint(s) hit repeatedly (periodic communication detected)")

                if summary.get('post_nav_exfil_detected'):
                    pn = network_results.get('post_nav_exfil', [])
                    print(f"[!] POST-NAV EXFIL: {len(pn)} request(s) fired within 3s of navigation")

                if summary.get('websocket_suspicious', 0) > 0:
                    print(f"[!] WEBSOCKET: {summary['websocket_suspicious']} suspicious WebSocket connection(s)")

                # Risk score adjustments based on aggregated verdict
                if verdict == 'MALICIOUS':
                    print(f"[!] VERDICT: MALICIOUS - multiple converging threat signals detected!")
                    results['risk_score'] = min(10.0, results['risk_score'] + 4.0)
                elif verdict == 'SUSPICIOUS':
                    print(f"[!] VERDICT: SUSPICIOUS - threat signals detected, review recommended")
                    results['risk_score'] = min(10.0, results['risk_score'] + 2.0)
                elif verdict == 'LOW_RISK':
                    print(f"[+] VERDICT: LOW_RISK - minor signals, likely benign")
                else:
                    print(f"[+] VERDICT: CLEAN - no suspicious network behavior observed")

                # Feed newly discovered domains into VT
                new_domains = network_results.get('new_domains', [])
                if new_domains and not getattr(self, 'skip_vt', False):
                    print(f"[+] Checking {len(new_domains)} runtime-discovered domain(s) against VirusTotal...")
                    new_vt = self.vt_checker.check_multiple_domains(new_domains, max_checks=5)
                    vt_results.extend(new_vt)
                    results = self.analyzer.update_risk_with_virustotal(results, new_vt)
            else:
                error = network_results.get('error', 'Unknown error')
                print(f"[i] Dynamic analysis unavailable: {error}")
        elif getattr(self, 'run_dynamic', False) and not self.network_capture:
            print("\n[NETWORK] STEP 5.5: Dynamic network capture analysis...")
            print("-" * 80)
            print("[i] Network capture module not available. Install: pip install playwright && playwright install chromium")
            results['network_capture'] = {'available': False, 'skipped': True}
        else:
            results['network_capture'] = {'available': False, 'skipped': True}

        # Step 6: Advanced Malware Detection
        print("\n[ADVANCED] STEP 6: Advanced technique detection...")
        print("-" * 80)
        advanced_findings = self.advanced_detector.run_all_detections(extension_dir)
        results['advanced_detection'] = advanced_findings

        # Update risk score based on advanced detection
        if advanced_findings['summary']['critical_findings'] > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
            print(f"[!] CRITICAL: {advanced_findings['summary']['critical_findings']} high-risk technique(s) detected!")
        elif advanced_findings['summary']['high_findings'] > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 1.5)
            print(f"[!] HIGH: {advanced_findings['summary']['high_findings']} suspicious technique(s) detected")
        else:
            print("[OK] No advanced suspicious techniques detected")

        # Step 6.5: Enhanced Detection (Taint Analysis, Crypto Theft, Phishing)
        print("\n[ENHANCED] STEP 6.5: Enhanced detection (taint analysis, crypto, phishing)...")
        print("-" * 80)
        enhanced_results = self._run_enhanced_detection(extension_dir)
        results['enhanced_detection'] = enhanced_results

        # Update risk based on enhanced detection findings
        summary = enhanced_results.get('summary', {})
        if summary.get('critical', 0) > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
            print(f"[!] CRITICAL: {summary['critical']} critical finding(s) from enhanced detection!")
        elif summary.get('high', 0) > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 1.5)
            print(f"[!] HIGH: {summary['high']} high-risk finding(s)")
        else:
            print("[[OK]] No additional threats from enhanced detection")

        # Print taint flow summary if any
        taint_flows = enhanced_results.get('taint_flows', [])
        if taint_flows:
            print(f"[!] TAINT: {len(taint_flows)} data flow(s) from sensitive sources to network sinks")
            for flow in taint_flows[:3]:
                src = flow.get('source', {})
                sink = flow.get('sink', {})
                print(f"    -> {src.get('api', 'Unknown')} -> {sink.get('function', 'Unknown')}")

        # Print crypto findings
        crypto_findings = enhanced_results.get('crypto_findings', [])
        if crypto_findings:
            print(f"[!] CRYPTO: {len(crypto_findings)} cryptocurrency-related pattern(s) detected")

        # Step 6.7: Behavioral Correlation Engine
        print("\n[BEHAVIORAL] STEP 6.7: Behavioral threat correlation...")
        print("-" * 80)
        behavioral_results = self.behavioral_engine.correlate(results)
        results['behavioral_correlations'] = behavioral_results

        bc_summary = behavioral_results.get('summary', {})
        if bc_summary.get('critical', 0) > 0:
            print(f"[!] CRITICAL: {bc_summary['critical']} critical threat chain(s) detected!")
            for corr in behavioral_results.get('correlations', []):
                if corr['severity'] == 'critical':
                    print(f"    -> {corr['name']}: {corr['evidence'][:80]}")
        elif bc_summary.get('high', 0) > 0:
            print(f"[!] HIGH: {bc_summary['high']} high-risk behavioral pattern(s)")
            for corr in behavioral_results.get('correlations', []):
                if corr['severity'] == 'high':
                    print(f"    -> {corr['name']}")
        elif bc_summary.get('total_correlations', 0) > 0:
            print(f"[i] {bc_summary['total_correlations']} behavioral pattern(s) detected")
        else:
            print("[[OK]] No compound threat patterns detected")

        # Update risk score based on behavioral correlations
        if bc_summary.get('critical', 0) > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
        elif bc_summary.get('high', 0) > 0:
            results['risk_score'] = min(10.0, results['risk_score'] + 1.5)

        # Step 6.8: Attack Narrative
        narrative = self.analyzer.generate_attack_narrative(results)
        results['attack_narrative'] = narrative
        if narrative.get('confidence') in ('high', 'medium'):
            print(f"\n[NARRATIVE] Attack chain confidence: {narrative['confidence'].upper()}")
            for stage in narrative.get('attack_chain', []):
                print(f"    [{stage['risk']}] {stage['stage']}: {stage['capability'][:80]}")
            if narrative.get('impact_summary'):
                print(f"    IMPACT: {narrative['impact_summary'][:100]}")

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
        print("\n[DB] STEP 8: Updating local analysis database...")
        print("-" * 80)
        self._update_ioc_database(results, vt_results, extension_id)

        # Step 8.5: Threat Attribution
        print("\n[ATTRIBUTION] STEP 8.5: Threat campaign attribution...")
        print("-" * 80)
        if getattr(self, 'skip_osint', False):
            print("[i] OSINT threat attribution skipped (--fast or --skip-osint mode)")
            attribution = None
        else:
            attribution = self._check_threat_attribution(extension_id, results.get('name', 'Unknown'))

        if attribution:
            results['threat_attribution'] = attribution

            # Elevate risk score based on attribution findings
            confidence = attribution.get('confidence', 'NONE')
            attribution_found = attribution.get('attribution_found', False)

            if confidence == 'CONFIRMED':
                # Database match - external source confirmed
                print(f"[!] CRITICAL: Extension found in known threat database!")
                print(f"    Campaign: {attribution.get('campaign_name', 'Unknown')}")
                print(f"    Threat Actor: {attribution.get('threat_actor', 'Unknown')}")
                results['risk_score'] = min(10.0, results['risk_score'] + 4.0)
                results['risk_level'] = 'CRITICAL'
            elif confidence == 'HIGH' and attribution_found:
                # Campaign detected via web search
                print(f"[!] HIGH: Campaign attribution detected via OSINT web search")
                print(f"    Campaign: {attribution.get('campaign_name', 'Unknown')}")
                results['risk_score'] = min(10.0, results['risk_score'] + 3.0)
                if results['risk_level'] not in ['CRITICAL']:
                    results['risk_level'] = 'HIGH'
            elif confidence == 'MEDIUM' and attribution_found:
                # Suspicious indicators found via web search
                print(f"[!] MEDIUM: Suspicious indicators found in web search results")
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

        # Step 8.7: Final Risk Recalculation with all signals
        # Recalculate with behavioral correlations now included
        results['risk_score'] = self.analyzer.calculate_enhanced_risk_score(results)
        results['risk_level'] = self.analyzer.get_risk_level(results['risk_score'])
        results['threat_classification'] = self.analyzer.classify_threat(results)

        # OSINT / threat attribution should act as a *floor* on risk:
        # if external threat intelligence says the extension is malicious,
        # never downgrade below HIGH/CRITICAL even if local signals are weaker.
        attribution = results.get('threat_attribution') or {}
        if attribution.get('attribution_found'):
            conf = attribution.get('confidence', 'NONE')
            if conf == 'CONFIRMED':
                # Known malicious in our database → always CRITICAL, high score floor
                results['risk_score'] = max(results['risk_score'], 9.0)
                results['risk_level'] = 'CRITICAL'
            elif conf in ('HIGH', 'MEDIUM'):
                # Strong OSINT evidence → at least HIGH risk
                results['risk_score'] = max(results['risk_score'], 7.5)
                if results['risk_level'] not in ('CRITICAL', 'HIGH'):
                    results['risk_level'] = 'HIGH'

        print(f"\n[SCORE] Final Risk: {results['risk_score']:.1f}/10 ({results['risk_level']})")
        tc = results['threat_classification']
        if tc['classification'] in ('MALICIOUS_INDICATORS', 'HIGH_RISK_SUSPICIOUS'):
            print(f"[!] Classification: {tc['classification']}")
            print(f"    {tc['summary']}")
        elif tc['classification'] == 'ELEVATED_RISK':
            print(f"[i] Classification: {tc['classification']}")
            print(f"    {tc['summary']}")

        # Step 8.8: Campaign Fingerprinting
        campaign_fp = self.campaign_fingerprinter.fingerprint_extension(
            extension_dir, results)
        results['campaign_fingerprint'] = campaign_fp
        if campaign_fp.get('matched_campaigns'):
            print(f"\n[CAMPAIGN] Campaign matches detected!")
            for mc in campaign_fp['matched_campaigns']:
                print(f"    [{mc['confidence']}] {mc['name']}")
                if mc.get('description'):
                    print(f"        {mc['description'][:80]}")
        elif campaign_fp.get('infra_fingerprint'):
            print(f"\n[CAMPAIGN] Infra fingerprint: {campaign_fp['infra_fingerprint']} "
                  f"(no known campaign match)")

        # Step 8.9: Supply Chain Version Diff
        print("\n[VERSION] STEP 8.9: Supply chain version comparison...")
        print("-" * 80)
        version_diff = self.version_diff.compare(extension_id, results)
        results['version_diff'] = version_diff

        if version_diff.get('has_baseline'):
            print(f"[+] Comparing v{version_diff.get('old_version', '?')} -> "
                  f"v{version_diff.get('new_version', '?')}")
            print(f"    Baseline from: {version_diff.get('baseline_date', '?')}")

            if version_diff.get('change_count', 0) > 0:
                sc_level = version_diff.get('supply_chain_level', 'LOW')
                print(f"[!] {version_diff['change_count']} change(s) detected "
                      f"(Supply chain risk: {sc_level})")
                for change in version_diff['changes']:
                    print(f"    [{change['severity'].upper()}] {change['description']}")

                # Boost risk score for supply chain issues
                sc_risk = version_diff.get('supply_chain_risk', 0)
                if sc_risk >= 2.5:
                    results['risk_score'] = min(10.0, results['risk_score'] + sc_risk * 0.5)
                    results['risk_level'] = self.analyzer.get_risk_level(results['risk_score'])
            else:
                print("[[OK]] No concerning changes from previous version")
        else:
            print("[i] No previous baseline found - storing current as baseline")

        # Always store current analysis as baseline for next comparison
        self.version_diff.store_baseline(extension_id, results)

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
    def analyze_vscode_extension(self, extension_identifier):
        """
        Complete analysis pipeline for VSCode extensions.

        Args:
            extension_identifier: Publisher.extensionName or marketplace URL

        Returns:
            dict: Comprehensive analysis results
        """
        if not VSCODE_AVAILABLE:
            print("[!] VSCode analysis modules not available.")
            print("    Ensure vscode_downloader.py, vscode_unpacker.py, vscode_analyzer.py are in src/")
            return None

        print("=" * 80)
        print("[SCAN] VSCODE EXTENSION SECURITY ANALYZER")
        print("    Four-Layer Security Assessment")
        print("=" * 80)
        print(f"\n[+] Target: {extension_identifier}\n")

        vscode_downloader = VSCodeExtensionDownloader()
        vscode_unpacker = VSCodeExtensionUnpacker()
        vscode_analyzer = VSCodeStaticAnalyzer()

        # Step 0: Parse identifier and fetch metadata
        print("[MARKETPLACE] STEP 0: Fetching VS Marketplace metadata...")
        print("-" * 80)

        parsed = vscode_downloader.parse_identifier(extension_identifier)
        if not parsed:
            print(f"[!] Invalid extension identifier: {extension_identifier}")
            print(f"    Expected: publisher.extensionName (e.g., ms-python.python)")
            return None

        publisher, extension_name = parsed
        metadata = vscode_downloader.fetch_metadata(publisher, extension_name)

        if metadata.get('available'):
            print(f"[+] Extension: {metadata.get('name', 'Unknown')}")
            print(f"    Publisher: {metadata.get('publisher', 'Unknown')} "
                  f"{'(verified)' if metadata.get('publisher_verified') else '(unverified)'}")
            print(f"    Installs: {metadata.get('install_count', 0):,}")
            print(f"    Rating: {metadata.get('rating_value', 'N/A')} "
                  f"({metadata.get('rating_count', 0)} ratings)")
            print(f"    Version: {metadata.get('version', 'Unknown')}")

            risk_signals = metadata.get('risk_signals', {})
            if risk_signals.get('low_adoption'):
                print(f"[i] Low adoption: <500 installs (increased risk)")
            if risk_signals.get('unverified_publisher'):
                print(f"[i] Publisher domain not verified")
        else:
            print(f"[!] Could not fetch metadata: {metadata.get('error', 'Unknown error')}")
            print(f"    Continuing with analysis...")

        # Step 1: Download VSIX
        print(f"\n[DOWNLOAD] STEP 1: Downloading VSIX package...")
        print("-" * 80)
        vsix_path = vscode_downloader.download_extension(
            publisher, extension_name,
            version=metadata.get('version') if metadata.get('available') else None
        )

        if not vsix_path:
            print("\n[!] Download failed.")
            return None

        # Step 2: Unpack VSIX
        print("\n[UNPACK] STEP 2: Extracting VSIX package...")
        print("-" * 80)
        extension_dir = vscode_unpacker.unpack(vsix_path)

        if not extension_dir:
            print("\n[!] Extraction failed.")
            return None

        # Get file inventory
        inventory = vscode_unpacker.get_file_inventory(extension_dir)
        print(f"[+] Files: {inventory['total_files']} "
              f"({inventory['total_size'] / 1024:.1f} KB)")
        print(f"    JS: {len(inventory['javascript'])}, "
              f"TS: {len(inventory['typescript'])}, "
              f"JSON: {len(inventory['json'])}")
        if inventory['has_node_modules']:
            print(f"    node_modules: {inventory['node_modules_size'] / (1024*1024):.1f} MB")

        # Step 3: Enhanced Five-Layer Static Analysis
        print("\n[ANALYZE] STEP 3: Enhanced five-layer security analysis...")
        print("-" * 80)
        results = vscode_analyzer.analyze_extension(extension_dir, metadata=metadata)

        if not results:
            print("\n[!] Analysis failed.")
            return None

        # Print Layer summaries
        meta_risk = results.get('metadata_risk', {})
        if meta_risk.get('findings'):
            print(f"\n[Layer 1] {len(meta_risk['findings'])} metadata finding(s)")
            for f in meta_risk['findings'][:3]:
                print(f"    [{f['severity'].upper()}] {f['detail']}")

        supply = results.get('supply_chain', {})
        if supply.get('findings'):
            print(f"\n[Layer 2] {supply['dependency_count']} dependencies, "
                  f"{len(supply['findings'])} supply chain finding(s)")
            for f in supply['findings'][:3]:
                if f['severity'] != 'info':
                    print(f"    [{f['severity'].upper()}] {f['detail']}")

        code = results.get('code_analysis', {})
        findings_by_sev = code.get('findings_by_severity', {})
        print(f"\n[Layer 3] Code analysis: {code.get('files_scanned', 0)} files scanned")
        print(f"    Critical: {findings_by_sev.get('critical', 0)}, "
              f"High: {findings_by_sev.get('high', 0)}, "
              f"Medium: {findings_by_sev.get('medium', 0)}, "
              f"Low: {findings_by_sev.get('low', 0)}")

        # Print notable categories
        findings_by_cat = code.get('findings_by_category', {})
        notable_cats = [
            'command_injection', 'credential_theft', 'behavioral_correlation',
            'terminal_hijack', 'network_exfil',
            'workspace_harvesting', 'base64_exfil', 'document_monitoring',
            'insecure_endpoint', 'telemetry_abuse', 'hidden_iframe',
            'analytics_injection',
        ]
        for cat in notable_cats:
            if cat in findings_by_cat:
                count = len(findings_by_cat[cat])
                print(f"    [{cat.replace('_', ' ').upper()}] {count} finding(s)")

        suppressed = code.get('suppressed_false_positives', 0)
        if suppressed:
            print(f"    False positives suppressed: {suppressed}")

        # HTML/webview findings
        html = results.get('html_analysis', {})
        if html.get('findings'):
            print(f"\n[Layer 3.5] HTML/webview: {len(html['findings'])} finding(s) in {html.get('files_scanned', 0)} file(s)")

        # Package.json deep inspection
        pkg_deep = results.get('package_json_deep', {})
        if pkg_deep.get('findings'):
            print(f"\n[Layer 1.5] Package.json deep: {len(pkg_deep['findings'])} finding(s)")

        print(f"\n[Layer 4] Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")

        # Step 4: Domain Intelligence on extracted URLs
        print("\n[DOMAIN] STEP 4: Domain intelligence on extracted URLs...")
        print("-" * 80)
        external_urls = results.get('external_urls', [])
        domain_intelligence = []

        if external_urls:
            seen_domains = set()
            from urllib.parse import urlparse
            for url_entry in external_urls:
                try:
                    parsed_url = urlparse(url_entry['url'])
                    domain = parsed_url.netloc
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        assessment = self.domain_intel.analyze_domain(
                            domain=domain,
                            url=url_entry['url'],
                            context={'file': url_entry.get('file'), 'line': url_entry.get('line')}
                        )
                        domain_intelligence.append(assessment)
                except Exception:
                    continue

            threats = [d for d in domain_intelligence if d['threat_level'] in ['CRITICAL', 'HIGH']]
            if threats:
                print(f"[!] {len(threats)} suspicious domain(s) detected:")
                for d in threats[:5]:
                    print(f"    {d['domain']} - {d['classification']} ({d['threat_level']})")
            else:
                print(f"[+] {len(seen_domains)} domain(s) checked - no obvious threats")
        else:
            print("[+] No external URLs found in source code")

        results['domain_intelligence'] = domain_intelligence

        # Step 5: VirusTotal check on extracted domains
        print("\n[VT] STEP 5: VirusTotal domain reputation check...")
        print("-" * 80)

        vt_results = []
        if not getattr(self, 'skip_vt', False) and external_urls:
            from urllib.parse import urlparse
            unique_domains = set()
            for url_entry in external_urls:
                try:
                    parsed_url = urlparse(url_entry['url'])
                    if parsed_url.netloc:
                        unique_domains.add(parsed_url.netloc)
                except Exception:
                    pass

            if unique_domains:
                vt_results = self.vt_checker.check_multiple_domains(
                    list(unique_domains), max_checks=10
                )
                # Apply false positive filtering
                filtered = self.false_positive_filter.filter_virustotal_results(vt_results)
                vt_results = filtered['filtered_results']

                malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
                if malicious:
                    print(f"[!] VIRUSTOTAL: {len(malicious)} MALICIOUS domain(s)!")
                    for r in malicious:
                        print(f"    {r['domain']}: {r['stats']['malicious']} detections")
                else:
                    print(f"[+] {len(unique_domains)} domain(s) checked - clean")
            else:
                print("[i] No external domains to check")
        else:
            if getattr(self, 'skip_vt', False):
                print("[i] VirusTotal checks skipped (--skip-vt or --fast)")
            else:
                print("[i] No external domains to check")

        results['virustotal_results'] = vt_results
        results = vscode_analyzer.update_risk_with_virustotal(results, vt_results)

        # Step 6: IOC Management
        print("\n[DB] STEP 6: Updating local analysis database...")
        print("-" * 80)
        self._update_ioc_database(results, vt_results, results.get('identifier', 'unknown'))

        # Step 7: Generate Reports
        print("\n[REPORT] STEP 7: Generating professional reports...")
        print("-" * 80)

        json_report = vscode_analyzer.save_report(results)
        html_report = self.reporter.save_professional_report(results)

        # Print Summary
        self._print_vscode_summary(results)

        print(f"\n[FILES] Reports generated:")
        print(f"   JSON (Technical): {json_report}")
        print(f"   HTML (Professional): {html_report}")

        # Print Verdict
        self._print_verdict(results)

        return results

    def _print_vscode_summary(self, results):
        """Print VSCode analysis summary"""
        print("\n" + "=" * 80)
        print("[RESULT] VSCODE ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"\n[TARGET] Extension: {results.get('name', 'Unknown')}")
        print(f"[INFO] Identifier: {results.get('identifier', 'Unknown')}")
        print(f"[INFO] Version: {results.get('version', 'Unknown')}")
        print(f"[!]  Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")

        # Risk breakdown (5-component model)
        breakdown = results.get('risk_breakdown', {})
        if breakdown:
            print(f"\n[BREAKDOWN] Risk Components:")
            print(f"   Metadata & Publisher:    {breakdown.get('metadata_publisher', 0)}/2")
            print(f"   Supply Chain:            {breakdown.get('supply_chain', 0)}/2")
            print(f"   Code Analysis:           {breakdown.get('code_analysis', 0)}/3")
            print(f"   Behavioral Correlations: {breakdown.get('behavioral_correlations', 0)}/2")
            print(f"   Infrastructure:          {breakdown.get('infrastructure', 0)}/1")

        # Statistics
        code = results.get('code_analysis', {})
        supply = results.get('supply_chain', {})
        permissions = results.get('permissions', {})
        vt_results = results.get('virustotal_results', [])
        malicious_domains = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']

        html = results.get('html_analysis', {})
        correlations = [f for f in results.get('malicious_patterns', []) if f.get('category') == 'behavioral_correlation']

        print(f"\n[STATS] Statistics:")
        print(f"   Files Scanned: {code.get('files_scanned', 0)} JS/TS + {html.get('files_scanned', 0)} HTML")
        print(f"   High-Risk APIs: {len(permissions.get('high_risk', []))}")
        print(f"   Code Findings: {len(results.get('malicious_patterns', []))}")
        print(f"   Behavioral Correlations: {len(correlations)}")
        print(f"   Dependencies: {supply.get('dependency_count', 0)}")
        print(f"   Supply Chain Issues: {len([f for f in supply.get('findings', []) if f.get('severity') in ('critical', 'high')])}")
        print(f"   FP Suppressed: {code.get('suppressed_false_positives', 0)}")
        print(f"   VirusTotal Malicious: {len(malicious_domains)}")

        # Module usage
        module_usage = results.get('module_usage', {})
        if module_usage:
            print(f"\n[MODULES] Sensitive Module Usage:")
            for category, usages in module_usage.items():
                modules = set(u['module'] for u in usages)
                print(f"   {category}: {', '.join(modules)}")

    def _analyze_domain_intelligence(self, results):
        """Analyze all external domains with threat analysis"""
        
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
        
        # Skip VirusTotal checks if requested
        if getattr(self, 'skip_vt', False):
            print("[i] Skipping VirusTotal checks (--skip-vt enabled)")
            return []

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

    def _run_enhanced_detection(self, extension_dir):
        """
        Run enhanced detection including taint analysis, crypto theft, and phishing detection.

        Returns:
            dict: Enhanced detection results with taint flows, crypto findings, etc.
        """
        from pathlib import Path
        extension_dir = Path(extension_dir)

        results = {
            'taint_flows': [],
            'crypto_findings': [],
            'phishing_findings': [],
            'wallet_hijack': [],
            'obfuscation': [],
            'sensitive_data': [],
            'summary': {
                'critical': 0,
                'high': 0,
                'medium': 0,
                'low': 0,
                'total': 0
            }
        }

        js_files = list(extension_dir.rglob('*.js'))

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                relative_path = str(js_file.relative_to(extension_dir))

                # 1. Taint analysis
                taint_results = self.taint_analyzer.analyze_file(relative_path, content)
                results['taint_flows'].extend(taint_results)

                # 2. Wallet hijack detection
                wallet_findings = self.wallet_detector.analyze(content, relative_path)
                results['wallet_hijack'].extend(wallet_findings)

                # 3. Phishing detection
                phishing_findings = self.phishing_detector.analyze(content, relative_path)
                results['phishing_findings'].extend(phishing_findings)

            except Exception as e:
                continue

        # Calculate summary
        all_findings = (
            results['taint_flows'] +
            results['wallet_hijack'] +
            results['phishing_findings']
        )

        results['summary']['total'] = len(all_findings)

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

        # Also add wallet hijack to crypto_findings for report
        results['crypto_findings'] = results['wallet_hijack']

        return results

    def _print_analysis_summary(self, results):
        """Print analysis summary"""
        
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        
        print("\n" + "=" * 80)
        print("[RESULT] ANALYSIS COMPLETE")
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

        network = results.get('network_capture', {})
        if network.get('available'):
            net_sum = network.get('summary', {})
            print(f"   • Dynamic Requests: {net_sum.get('extension_requests', 0)} extension-initiated")
            print(f"   • Scored Suspicious: {net_sum.get('suspicious_count', 0)} "
                  f"(high-score: {net_sum.get('high_score_count', 0)})")
            if net_sum.get('beaconing_detected'):
                print(f"   • Beaconing: DETECTED")
            if net_sum.get('post_nav_exfil_detected'):
                print(f"   • Post-Navigation Exfil: DETECTED")
            print(f"   • Network Verdict: {net_sum.get('verdict', 'N/A')}")

    def _print_verdict(self, results):
        """Print final verdict"""

        campaign = results.get('campaign_attribution')
        risk_level = results.get('risk_level')
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        advanced = results.get('advanced_detection', {})
        advanced_critical = advanced.get('summary', {}).get('critical_findings', 0)
        pii = results.get('pii_classification', {})

        print(f"\n{'=' * 80}")

        if vt_malicious and advanced_critical > 0:
            # External confirmation (VT) + advanced techniques = high confidence
            print(f"[BLOCK] VERDICT: CONFIRMED MALICIOUS - VENDOR-VERIFIED + ADVANCED TECHNIQUES")
            print(f"   +- {len(vt_malicious)} domain(s) flagged by VirusTotal security vendors")
            print(f"   +- {advanced_critical} advanced technique(s) detected (CSP manipulation, DOM injection, etc.)")
            print(f"   +- IMMEDIATE ACTION: Block and investigate data compromise")
        elif vt_malicious:
            print(f"[BLOCK] VERDICT: LIKELY MALICIOUS - VIRUSTOTAL VENDOR DETECTIONS")
            print(f"   +- {len(vt_malicious)} domain(s) flagged as malicious by security vendors")
            print(f"   +- Recommend blocking and investigating affected systems")
        elif advanced_critical > 0:
            # Advanced techniques but no VT confirmation = high risk, not confirmed malware
            print(f"[BLOCK] VERDICT: HIGH RISK - SUSPICIOUS TECHNIQUES DETECTED")
            print(f"   +- {advanced_critical} advanced technique(s) found (per industry research)")
            if advanced.get('csp_manipulation'):
                print(f"   +- CSP Manipulation: Removes security headers (RCE capability)")
            if advanced.get('dom_event_injection'):
                print(f"   +- DOM Event Injection: Remote code execution bypass")
            print(f"   +- Recommend blocking pending manual review")
        elif pii.get('overall_risk') == 'CRITICAL':
            print(f"[BLOCK] VERDICT: HIGH RISK - SENSITIVE DATA ACCESS DETECTED")
            print(f"   +- Accesses {pii.get('data_types_count', 0)} type(s) of sensitive data")
            print(f"   +- {pii.get('recommendation', {}).get('action', 'Review and restrict')}")
            print(f"   +- Investigate what data is collected and where it is sent")
        elif campaign:
            print(f"[BLOCK] VERDICT: HIGH RISK - MATCHES KNOWN CAMPAIGN PATTERN")
            print(f"   +- Campaign: {campaign['name']}")
            print(f"   +- Recommend blocking across enterprise devices")
            print(f"   +- Investigate potential data exposure")
        elif risk_level == 'CRITICAL':
            print(f"[BLOCK] VERDICT: HIGH RISK / UNTRUSTED - REVIEW REQUIRED")
            print(f"   +- Multiple high-severity heuristic findings detected")
            print(f"   +- Not recommended for deployment without manual review")
        elif risk_level == 'HIGH':
            print(f"[ALERT] VERDICT: HIGH RISK - NOT RECOMMENDED")
            print(f"   +- Significant security concerns detected")
            print(f"   +- Manual review required before deployment")
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

        # Print local analysis database stats
        stats = self.ioc_manager.get_statistics()
        print(f"[DB] Local analysis database: {stats['total_domains']} domains, {stats['total_extensions']} extensions tracked")

    def _detect_firebase_usage(self, results):
        """Check if extension uses Firebase as its backend"""
        external_scripts = results.get('external_scripts', [])
        for script in external_scripts:
            url = (script.get('url') or '').lower()
            if 'firebaseio.com' in url or 'firebaseapp.com' in url or 'firebase' in url:
                return True
        # Also check code patterns for firebase imports
        patterns = results.get('malicious_patterns', [])
        for p in patterns:
            evidence = (p.get('evidence') or '').lower()
            if 'firebase' in evidence:
                return True
        return False

    def _check_threat_attribution(self, extension_id, extension_name):
        """Check if extension mentioned in known threat campaigns"""
        try:
            # Extract domains from results for campaign matching
            attribution = self.threat_attribution.search_threat_campaigns(extension_id, extension_name)
            return attribution
        except Exception as e:
            print(f"[!] Threat attribution failed: {str(e)}")
            return None

    def _fetch_edge_metadata(self, extension_id):
        """
        Fetch metadata from Microsoft Edge Add-ons store

        Args:
            extension_id: Edge extension ID

        Returns:
            dict: Extension metadata
        """
        import requests
        from bs4 import BeautifulSoup

        store_url = f"https://microsoftedge.microsoft.com/addons/detail/{extension_id}"

        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0'
            }
            response = requests.get(store_url, headers=headers, timeout=15)

            if response.status_code != 200:
                return {'available': False, 'error': f'HTTP {response.status_code}'}

            soup = BeautifulSoup(response.text, 'html.parser')

            # Extract metadata from Edge Add-ons page
            metadata = {
                'available': True,
                'store': 'edge',
                'store_url': store_url
            }

            # Try to extract extension name
            title_elem = soup.find('h1') or soup.find('title')
            if title_elem:
                name = title_elem.get_text().strip()
                # Clean up title (remove " - Microsoft Edge Addons" suffix)
                if ' - Microsoft Edge' in name:
                    name = name.split(' - Microsoft Edge')[0].strip()
                metadata['name'] = name

            # Try to extract author
            author_elem = soup.find('a', {'aria-label': lambda x: x and 'publisher' in x.lower() if x else False})
            if not author_elem:
                author_elem = soup.find('span', class_=lambda x: x and 'author' in x.lower() if x else False)
            if author_elem:
                metadata['author'] = author_elem.get_text().strip()
            else:
                metadata['author'] = 'Unknown'

            metadata['author_verified'] = False  # Edge doesn't show verification the same way

            # Try to extract user count
            users_elem = soup.find(string=lambda x: x and ('users' in x.lower() or 'downloads' in x.lower()) if x else False)
            if users_elem:
                metadata['user_count_text'] = users_elem.strip()
            else:
                metadata['user_count_text'] = 'Unknown'

            # Try to extract rating
            rating_elem = soup.find('span', {'aria-label': lambda x: x and 'rating' in x.lower() if x else False})
            if rating_elem:
                metadata['rating'] = rating_elem.get_text().strip()
            else:
                metadata['rating'] = 'N/A'

            metadata['last_updated_text'] = 'Unknown'
            metadata['risk_signals'] = {}

            return metadata

        except Exception as e:
            return {'available': False, 'error': str(e)}


def parse_cli_args(argv=None):
    """Parse CLI arguments (exposed for tests). Accepts optional argv list."""
    parser = argparse.ArgumentParser(
        description='Professional Extension Security Analyzer - Chrome, Edge & VSCode',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Analyze Chrome extension (uBlock Origin)
  python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm

  # Analyze Edge extension
  python src/analyzer.py odfafepnkmbhccpbejgmiehpchacaeak --edge

  # Analyze VSCode extension
  python src/analyzer.py ms-python.python --vscode
  python src/analyzer.py dbaeumer.vscode-eslint --vscode --fast

  # Analyze a suspicious extension
  python src/analyzer.py eebihieclccoidddmjcencomodomdoei

Features:
  [OK] Chrome Web Store & Edge Add-ons support
  [OK] VSCode Marketplace extension analysis (--vscode)
  [OK] Four-layer security assessment for VSCode extensions
  [OK] Supply chain analysis (dependency scanning)
  [OK] False positive suppression (Firebase, jQuery, CDNs)
  [OK] Threat campaign attribution via web search
  [OK] VirusTotal domain reputation checking
  [OK] Campaign attribution (DarkSpectre, ZoomStealer, SpyVPN, etc.)
  [OK] Domain intelligence (C2, DGA, typosquatting detection)
  [OK] Professional threat analysis reports
  [OK] PII/data classification analysis
  [OK] Advanced malware detection (CSP manipulation, DOM injection, etc.)
  [OK] Dynamic network capture via Playwright + CDP (--dynamic flag)
  [OK] IOC database management
  [OK] Permission combination risk analysis
  [OK] 150+ malicious code pattern detection
  [OK] Taint analysis (source-sink tracking)
  [OK] Cryptocurrency theft detection
        """
    )

    parser.add_argument(
        'extension_id',
        help='Extension ID (Chrome/Edge: 32-char ID) or VSCode identifier (publisher.name)'
    )
    
    parser.add_argument(
        '--output-dir',
        default='reports',
        help='Output directory for reports (default: reports/)'
    )

    parser.add_argument(
        '--skip-vt',
        action='store_true',
        help='Skip VirusTotal checks (useful for offline debugging)'
    )

    parser.add_argument(
        '--fast',
        action='store_true',
        help='Enable fast mode (skip VirusTotal and OSINT checks)'
    )

    parser.add_argument(
        '--skip-osint',
        action='store_true',
        help='Skip OSINT threat attribution web searches'
    )

    parser.add_argument(
        '--dynamic',
        action='store_true',
        help='Enable dynamic network capture analysis (requires playwright)'
    )

    parser.add_argument(
        '--dynamic-timeout',
        type=int,
        default=30,
        help='Timeout in seconds for dynamic analysis (default: 30)'
    )

    parser.add_argument(
        '--edge',
        action='store_true',
        help='Analyze extension from Microsoft Edge Add-ons store instead of Chrome Web Store'
    )

    parser.add_argument(
        '--auto-detect',
        action='store_true',
        help='Auto-detect which store the extension belongs to'
    )

    parser.add_argument(
        '--vscode',
        action='store_true',
        help='Analyze a VSCode extension from VS Marketplace (identifier: publisher.name)'
    )

    return parser.parse_args(argv)


def main():
    """CLI entry point"""

    # Use centralized parser (tests and CLI both use this)
    args = parse_cli_args()

    # ── VSCode mode ──
    if getattr(args, 'vscode', False):
        print("""
    ========================================================================
       VSCODE EXTENSION SECURITY ANALYZER - PROFESSIONAL EDITION
       Four-Layer Security Assessment with VirusTotal Integration
    ========================================================================
        """)

        analyzer = ChromeExtensionAnalyzer()
        fast_mode = getattr(args, 'fast', False)
        analyzer.skip_vt = getattr(args, 'skip_vt', False) or fast_mode
        analyzer.skip_osint = getattr(args, 'skip_osint', False) or fast_mode

        results = analyzer.analyze_vscode_extension(args.extension_id)

        if results:
            risk_level = results.get('risk_level', 'MINIMAL')
            if risk_level == 'CRITICAL':
                sys.exit(3)
            elif risk_level == 'HIGH':
                sys.exit(2)
            elif risk_level == 'MEDIUM':
                sys.exit(1)
            else:
                sys.exit(0)
        else:
            sys.exit(4)
        return

    # ── Chrome / Edge mode ──
    # Validate extension ID format
    if len(args.extension_id) != 32:
        print(f"[!] Warning: Extension ID should be 32 characters long.")
        print(f"[!] Provided ID: {args.extension_id} ({len(args.extension_id)} characters)")
        response = input("[?] Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("[[X]] Aborted.")
            sys.exit(1)

    # Determine browser type
    browser = BrowserType.CHROME
    if getattr(args, 'edge', False):
        browser = BrowserType.EDGE
    elif getattr(args, 'auto_detect', False):
        print("[+] Auto-detecting extension store...")
        from downloader import ExtensionDownloader
        downloader = ExtensionDownloader()
        detected = downloader.detect_browser_store(args.extension_id)
        if detected:
            browser = detected
            print(f"[+] Detected: {browser.value.upper()} store")
        else:
            print("[!] Could not detect store, defaulting to Chrome")

    browser_name = browser.value.upper()

    # Run analysis
    print(f"""
    ========================================================================
       {browser_name} EXTENSION SECURITY ANALYZER - PROFESSIONAL EDITION
       Threat Analysis Platform with VirusTotal Integration
    ========================================================================
    """)

    analyzer = ChromeExtensionAnalyzer()
    # Honor CLI options for skipping external services - support --fast shortcut
    fast_mode = getattr(args, 'fast', False)
    analyzer.skip_vt = getattr(args, 'skip_vt', False) or fast_mode
    analyzer.skip_osint = getattr(args, 'skip_osint', False) or fast_mode
    analyzer.run_dynamic = getattr(args, 'dynamic', False) and not fast_mode
    analyzer.dynamic_timeout = getattr(args, 'dynamic_timeout', 30)

    results = analyzer.analyze_extension(args.extension_id, browser=browser)

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
