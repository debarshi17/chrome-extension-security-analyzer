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

class ChromeExtensionAnalyzer:
    """Main analyzer orchestrator with professional-grade analysis"""
    
    def __init__(self):
        self.downloader = ExtensionDownloader()
        self.unpacker = ExtensionUnpacker()
        self.analyzer = EnhancedStaticAnalyzer()
        self.domain_intel = DomainIntelligence()
        self.reporter = ProfessionalReportGenerator()
        self.vt_checker = VirusTotalChecker()
    
    def analyze_extension(self, extension_id):
        """
        Complete analysis pipeline with professional threat intelligence
        
        Args:
            extension_id (str): Chrome extension ID
            
        Returns:
            dict: Comprehensive analysis results
        """
        print("=" * 80)
        print("🔍 CHROME EXTENSION SECURITY ANALYZER")
        print("    Professional Threat Intelligence Edition with VirusTotal")
        print("=" * 80)
        print(f"\n[+] Target Extension ID: {extension_id}\n")
        
        # Step 1: Download
        print("📥 STEP 1: Downloading extension...")
        print("-" * 80)
        crx_path = self.downloader.download_extension(extension_id)
        
        if not crx_path:
            print("\n[✗] Download failed. Extension may not exist or be unavailable.")
            return None
        
        # Step 2: Unpack
        print("\n📦 STEP 2: Unpacking extension...")
        print("-" * 80)
        extension_dir = self.unpacker.unpack(crx_path)
        
        if not extension_dir:
            print("\n[✗] Unpacking failed.")
            return None
        
        # Read manifest
        manifest = self.unpacker.read_manifest(extension_dir)
        
        if not manifest:
            print("\n[✗] Failed to read manifest.json")
            return None
        
        # Step 3: Static Analysis
        print("\n🔍 STEP 3: Performing static analysis...")
        print("-" * 80)
        results = self.analyzer.analyze_extension(extension_dir)
        
        if not results:
            print("\n[✗] Analysis failed.")
            return None
        
        # Step 4: Domain Intelligence Analysis
        print("\n🌐 STEP 4: Domain intelligence analysis...")
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
            print("[✓] No obviously malicious domains detected")
        
        # Step 5: VirusTotal Domain Reputation Check
        print("\n🛡️  STEP 5: VirusTotal domain reputation check...")
        print("-" * 80)
        vt_results = self._check_virustotal(results)
        
        # Update risk score based on VT results
        results = self.analyzer.update_risk_with_virustotal(results, vt_results)
        
        print(f"\n[+] Updated Risk Score (with VirusTotal): {results['risk_score']:.1f}/10 ({results['risk_level']})")
        
        # Step 6: Generate Reports
        print("\n📄 STEP 6: Generating professional reports...")
        print("-" * 80)
        
        # Save JSON report (detailed data)
        json_report = self.analyzer.save_report(results)
        
        # Generate professional HTML report
        html_report = self.reporter.save_professional_report(results)
        
        # Print Summary
        self._print_analysis_summary(results)
        
        print(f"\n📁 Reports generated:")
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
        
        # Print summary of malicious findings
        malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        suspicious = [r for r in vt_results if r.get('threat_level') == 'SUSPICIOUS']
        
        if malicious:
            print(f"\n⚠️  VIRUSTOTAL ALERT: {len(malicious)} MALICIOUS domain(s) detected!")
            for result in malicious:
                print(f"    🚨 {result['domain']}")
                print(f"       • Detections: {result['stats']['malicious']} vendors")
                print(f"       • Community: {result['votes']['malicious']} malicious votes")
                if result.get('malicious_vendors'):
                    vendors = [v['vendor'] for v in result['malicious_vendors'][:3]]
                    print(f"       • Flagged by: {', '.join(vendors)}")
        
        if suspicious:
            print(f"\n⚠️  VirusTotal: {len(suspicious)} suspicious domain(s)")
            for result in suspicious:
                print(f"    • {result['domain']} - {result['stats']['suspicious']} flags")
        
        return vt_results
    
    def _print_analysis_summary(self, results):
        """Print analysis summary"""
        
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        
        print("\n" + "=" * 80)
        print("📊 ANALYSIS COMPLETE")
        print("=" * 80)
        print(f"\n🎯 Extension: {results['name']}")
        print(f"📌 Version: {results['version']}")
        print(f"⚠️  Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")
        
        # VirusTotal Results
        malicious_domains = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        if malicious_domains:
            print(f"\n🚨 VIRUSTOTAL: {len(malicious_domains)} MALICIOUS DOMAIN(S) DETECTED")
            for result in malicious_domains[:3]:
                print(f"   └─ {result['domain']}: {result['stats']['malicious']} detections")
        
        # Campaign Attribution
        if campaign:
            print(f"\n🚨 CAMPAIGN DETECTED: {campaign['name']}")
            print(f"   └─ Confidence: {campaign['confidence']} | Severity: {campaign['severity']}")
            print(f"   └─ Description: {campaign.get('description', 'N/A')}")
            for indicator in campaign.get('indicators', [])[:3]:
                print(f"      • {indicator}")
            if campaign.get('reference'):
                print(f"   └─ Reference: {campaign['reference']}")
        
        # Settings Overrides
        if settings.get('has_overrides'):
            print(f"\n⚠️  BROWSER HIJACKING DETECTED:")
            
            if settings.get('search_hijacking'):
                search = settings['search_hijacking']
                print(f"   └─ Search Engine: {search['search_url']}")
                if search.get('affiliate_params'):
                    print(f"      • Affiliate Fraud: {', '.join(search['affiliate_params'])}")
            
            if settings.get('homepage_hijacking'):
                print(f"   └─ Homepage Override: {settings['homepage_hijacking']['url']}")
            
            if settings.get('startup_hijacking'):
                urls = settings['startup_hijacking']['urls']
                print(f"   └─ Startup Pages: {len(urls)} page(s)")
        
        # Statistics
        permissions = results.get('permissions', {})
        patterns = results.get('malicious_patterns', [])
        domain_intel = results.get('domain_intelligence', [])
        
        print(f"\n📈 Statistics:")
        print(f"   • High-Risk Permissions: {len(permissions.get('high_risk', []))}")
        print(f"   • Critical Code Patterns: {len([p for p in patterns if p['severity'] == 'high'])}")
        print(f"   • Suspicious Domains: {len([d for d in domain_intel if d['threat_level'] in ['CRITICAL', 'HIGH']])}")
        print(f"   • VirusTotal Malicious: {len(malicious_domains)}")
    def _print_verdict(self, results):
        """Print final verdict"""
        
        campaign = results.get('campaign_attribution')
        risk_level = results.get('risk_level')
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        
        print(f"\n{'=' * 80}")
        
        if vt_malicious:
            print(f"⛔ VERDICT: CRITICAL THREAT - VIRUSTOTAL CONFIRMED MALICIOUS")
            print(f"   └─ {len(vt_malicious)} domain(s) flagged as malicious by security vendors")
            print(f"   └─ IMMEDIATE ACTION: Block this extension immediately")
            print(f"   └─ Investigate data compromise on affected systems")
        elif campaign:
            print(f"⛔ VERDICT: CRITICAL THREAT - KNOWN MALICIOUS CAMPAIGN")
            print(f"   └─ Campaign: {campaign['name']}")
            print(f"   └─ IMMEDIATE ACTION: Block across all enterprise devices")
            print(f"   └─ Investigate potential data compromise")
        elif risk_level == 'CRITICAL':
            print(f"⛔ VERDICT: CRITICAL RISK - BLOCK IMMEDIATELY")
            print(f"   └─ This extension poses a severe security threat")
            print(f"   └─ Do NOT deploy under any circumstances")
        elif risk_level == 'HIGH':
            print(f"🚨 VERDICT: HIGH RISK - BLOCK THIS EXTENSION")
            print(f"   └─ Significant security concerns detected")
            print(f"   └─ Not recommended for deployment")
        elif risk_level == 'MEDIUM':
            print(f"⚠️  VERDICT: MEDIUM RISK - MANUAL REVIEW REQUIRED")
            print(f"   └─ Security review recommended before deployment")
            print(f"   └─ Test in isolated environment first")
        elif risk_level == 'LOW':
            print(f"⚡ VERDICT: LOW RISK - MONITOR")
            print(f"   └─ Extension appears relatively safe")
            print(f"   └─ Monitor for updates and behavioral changes")
        else:
            print(f"✅ VERDICT: MINIMAL RISK")
            print(f"   └─ No significant threats detected")
            print(f"   └─ Safe for deployment with standard monitoring")
        
        print(f"{'=' * 80}\n")


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
  ✓ VirusTotal domain reputation checking
  ✓ Campaign attribution (DarkSpectre, ZoomStealer, etc.)
  ✓ Domain intelligence (C2, DGA, typosquatting detection)
  ✓ Professional threat intelligence reports
  ✓ Detailed permission analysis
  ✓ Deep code pattern detection
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
            print("[✗] Aborted.")
            sys.exit(1)
    
    # Run analysis
    print("""
    ╔════════════════════════════════════════════════════════════════════╗
    ║   CHROME EXTENSION SECURITY ANALYZER - PROFESSIONAL EDITION       ║
    ║   Threat Intelligence Platform with VirusTotal Integration        ║
    ╚════════════════════════════════════════════════════════════════════╝
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
