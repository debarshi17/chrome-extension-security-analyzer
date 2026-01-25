"""
VirusTotal Domain Reputation Checker
Securely checks domains against VirusTotal API
"""

import json
import requests
import time
from pathlib import Path

class VirusTotalChecker:
    """Check domain reputation using VirusTotal API"""
    
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
            
            # Calculate threat level
            malicious_count = last_analysis_stats.get('malicious', 0)
            suspicious_count = last_analysis_stats.get('suspicious', 0)
            
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