"""
VirusTotal Domain Reputation Checker
Securely checks domains against VirusTotal API
"""

import json
import requests
import time
from pathlib import Path
from datetime import datetime, timezone

class VirusTotalChecker:
    """Check domain reputation using VirusTotal API"""

    # High-risk TLDs commonly used for malware/phishing
    HIGH_RISK_TLDS = [
        '.top', '.xyz', '.club', '.work', '.loan', '.men',
        '.gq', '.ml', '.cf', '.tk', '.ga', '.online',
        '.site', '.live', '.website', '.bid', '.win',
        '.download', '.stream', '.science', '.faith'
    ]

    def __init__(self):
        self.api_key = self._load_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "x-apikey": self.api_key
            })
        self.rate_limit_delay = 15  # Free API: 4 requests/minute
    
    def _load_api_key(self):
        """Load API key from config file"""
        config_path = Path("config.json")

        if not config_path.exists():
            print("[!] Warning: config.json not found. VirusTotal checks disabled.")
            return None

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                api_key = config.get('virustotal', {}).get('api_key')

                if not api_key:
                    print("[!] Warning: VirusTotal API key not configured.")
                    return None

                return api_key
        except Exception as e:
            print(f"[!] Error loading config: {e}")
            return None

    def _calculate_domain_age(self, creation_timestamp):
        """
        Calculate domain age in days from Unix timestamp

        Args:
            creation_timestamp: Unix timestamp of domain creation

        Returns:
            dict: Domain age info with days, risk level, and risk score
        """
        if not creation_timestamp:
            return None

        try:
            creation_date = datetime.fromtimestamp(creation_timestamp, tz=timezone.utc)
            now = datetime.now(timezone.utc)
            age_days = (now - creation_date).days

            # Risk scoring based on age
            if age_days < 30:
                risk_level = 'CRITICAL'
                risk_score = 4
                description = 'Domain created < 30 days ago (newly registered)'
            elif age_days < 90:
                risk_level = 'HIGH'
                risk_score = 3
                description = 'Domain created < 90 days ago (very recent)'
            elif age_days < 180:
                risk_level = 'MEDIUM'
                risk_score = 2
                description = 'Domain created < 180 days ago (recent)'
            elif age_days < 365:
                risk_level = 'LOW'
                risk_score = 1
                description = 'Domain created < 1 year ago'
            else:
                risk_level = 'SAFE'
                risk_score = 0
                description = 'Established domain'

            return {
                'creation_date': creation_date.strftime('%Y-%m-%d'),
                'age_days': age_days,
                'age_human': self._format_age(age_days),
                'risk_level': risk_level,
                'risk_score': risk_score,
                'description': description
            }
        except Exception:
            return None

    def _format_age(self, days):
        """Format age in human-readable format"""
        if days < 30:
            return f"{days} days"
        elif days < 365:
            months = days // 30
            return f"{months} month{'s' if months != 1 else ''}"
        else:
            years = days // 365
            return f"{years} year{'s' if years != 1 else ''}"

    def _check_high_risk_tld(self, domain):
        """
        Check if domain uses a high-risk TLD

        Args:
            domain: Domain name to check

        Returns:
            dict: TLD risk info with risk level and score
        """
        domain_lower = domain.lower()

        for tld in self.HIGH_RISK_TLDS:
            if domain_lower.endswith(tld):
                return {
                    'is_high_risk': True,
                    'tld': tld,
                    'risk_score': 2,
                    'description': f'High-risk TLD commonly used for malware/phishing'
                }

        return {
            'is_high_risk': False,
            'tld': '.' + domain.split('.')[-1] if '.' in domain else 'unknown',
            'risk_score': 0,
            'description': 'Standard TLD'
        }
    
    def check_domain(self, domain):
        """
        Check domain reputation on VirusTotal
        
        Returns:
            dict: Reputation data with scores, verdicts, and community votes
        """
        
        if not self.api_key:
            return {
                'available': False,
                'error': 'VirusTotal API key not configured'
            }
        
        try:
            # VT API endpoint for domain reports
            url = f"{self.base_url}/domains/{domain}"
            
            print(f"[VT] Checking {domain}...")
            
            response = self.session.get(url, timeout=30)
            
            # Rate limiting (free tier: 4 requests/min)
            time.sleep(self.rate_limit_delay)
            
            if response.status_code == 404:
                return {
                    'available': True,
                    'domain': domain,
                    'known': False,
                    'message': 'Domain not found in VirusTotal database'
                }
            
            if response.status_code != 200:
                return {
                    'available': False,
                    'error': f'VirusTotal API error: {response.status_code}'
                }
            
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            # Parse reputation data
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            reputation = attributes.get('reputation', 0)

            # Extract domain age information
            creation_date_timestamp = attributes.get('creation_date')
            domain_age_info = self._calculate_domain_age(creation_date_timestamp)

            # Check TLD risk
            tld_risk_info = self._check_high_risk_tld(domain)
            
            # Get community votes
            votes = attributes.get('total_votes', {})
            
            # Get categories from vendors
            categories = attributes.get('categories', {})
            
            # Parse last analysis results (vendor detections)
            last_analysis = attributes.get('last_analysis_results', {})
            malicious_vendors = []
            suspicious_vendors = []
            
            for vendor, result in last_analysis.items():
                category = result.get('category', '')
                if category == 'malicious':
                    malicious_vendors.append({
                        'vendor': vendor,
                        'result': result.get('result', 'malicious')
                    })
                elif category == 'suspicious':
                    suspicious_vendors.append({
                        'vendor': vendor,
                        'result': result.get('result', 'suspicious')
                    })
            
            # Calculate threat level with enhanced logic
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)

            # Calculate combined risk score
            combined_risk_score = 0

            if malicious_count > 0:
                threat_level = 'MALICIOUS'
            elif suspicious_count > 5:
                threat_level = 'SUSPICIOUS'
            elif reputation < -50:
                threat_level = 'SUSPICIOUS'
            elif votes.get('malicious', 0) > votes.get('harmless', 0):
                threat_level = 'SUSPICIOUS'
            else:
                threat_level = 'CLEAN'

            # Add domain age risk
            if domain_age_info:
                combined_risk_score += domain_age_info['risk_score']
                # Escalate threat level if new domain
                if domain_age_info['risk_level'] in ['CRITICAL', 'HIGH'] and threat_level == 'CLEAN':
                    threat_level = 'SUSPICIOUS'

            # Add TLD risk
            if tld_risk_info['is_high_risk']:
                combined_risk_score += tld_risk_info['risk_score']
                # Escalate if high-risk TLD on suspicious domain
                if threat_level == 'SUSPICIOUS' and combined_risk_score >= 5:
                    threat_level = 'MALICIOUS'
            
            return {
                'available': True,
                'domain': domain,
                'known': True,
                'threat_level': threat_level,
                'reputation': reputation,
                'stats': {
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'harmless': last_analysis_stats.get('harmless', 0),
                    'undetected': last_analysis_stats.get('undetected', 0)
                },
                'votes': {
                    'malicious': votes.get('malicious', 0),
                    'harmless': votes.get('harmless', 0)
                },
                'categories': categories,
                'malicious_vendors': malicious_vendors[:10],  # Top 10
                'suspicious_vendors': suspicious_vendors[:10],
                'domain_age': domain_age_info,
                'tld_risk': tld_risk_info,
                'combined_risk_score': combined_risk_score,
                'url': f"https://www.virustotal.com/gui/domain/{domain}"
            }
            
        except requests.exceptions.Timeout:
            return {
                'available': False,
                'error': 'VirusTotal API timeout'
            }
        except Exception as e:
            return {
                'available': False,
                'error': f'Error: {str(e)}'
            }
    
    def check_multiple_domains(self, domains, max_checks=50):
        """
        Check multiple domains (respecting rate limits)
        
        Args:
            domains: List of domain strings
            max_checks: Maximum number of domains to check (default 50)
        
        Returns:
            list: Reputation data for each domain
        """
        
        results = []
        
        print(f"\n[VT] Checking {min(len(domains), max_checks)} domains against VirusTotal...")
        print(f"[VT] Rate limit: {self.rate_limit_delay}s between requests")
        
        for i, domain in enumerate(domains[:max_checks]):
            print(f"[VT] Progress: {i+1}/{min(len(domains), max_checks)}")
            
            result = self.check_domain(domain)
            results.append(result)
        
        # Summary
        malicious = sum(1 for r in results if r.get('threat_level') == 'MALICIOUS')
        suspicious = sum(1 for r in results if r.get('threat_level') == 'SUSPICIOUS')
        
        print(f"\n[VT] Summary: {malicious} malicious, {suspicious} suspicious, {len(results) - malicious - suspicious} clean/unknown")
        
        return results


def test_virustotal():
    """Test VirusTotal checker"""
    
    checker = VirusTotalChecker()
    
    # Test domains
    test_domains = [
        'google.com',  # Should be clean
        'api.gosupersonic.email'  # The extension domain
    ]
    
    for domain in test_domains:
        print(f"\n{'='*60}")
        print(f"Testing: {domain}")
        print('='*60)
        
        result = checker.check_domain(domain)
        
        if result.get('available'):
            if result.get('known'):
                print(f"Threat Level: {result['threat_level']}")
                print(f"Reputation: {result.get('reputation', 'N/A')}")
                print(f"Malicious detections: {result['stats']['malicious']}")
                print(f"Community votes: {result['votes']}")
                
                if result['malicious_vendors']:
                    print(f"\nMalicious vendors ({len(result['malicious_vendors'])}):")
                    for vendor in result['malicious_vendors'][:5]:
                        print(f"  • {vendor['vendor']}: {vendor['result']}")
            else:
                print("Domain not found in VirusTotal database")
        else:
            print(f"Error: {result.get('error')}")


if __name__ == "__main__":
    test_virustotal()