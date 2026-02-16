"""
VirusTotal Domain Reputation Checker
Securely checks domains against VirusTotal API

PERFORMANCE OPTIMIZATIONS:
- Results caching: Stores VT results to avoid re-checking same domains
- Cache validity: 24 hours for clean domains, 1 hour for suspicious/malicious
- Safe domain whitelist: Skips checking well-known legitimate domains
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

    # Safe domains - skip VT checking (standards bodies, CDNs, well-known legitimate services)
    SAFE_DOMAINS = {
        # Web standards organizations
        'w3.org', 'www.w3.org', 'w3c.org', 'whatwg.org',
        'ecma-international.org', 'ietf.org', 'rfc-editor.org',

        # Major CDNs
        'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com',
        'ajax.googleapis.com', 'fonts.googleapis.com', 'fonts.gstatic.com',

        # Google services
        'google.com', 'www.google.com', 'apis.google.com',
        'accounts.google.com', 'docs.google.com', 'drive.google.com',
        'chrome.google.com', 'clients2.google.com',

        # Mozilla
        'mozilla.org', 'www.mozilla.org', 'developer.mozilla.org', 'addons.mozilla.org',

        # Microsoft
        'microsoft.com', 'www.microsoft.com', 'docs.microsoft.com',
        'login.microsoftonline.com', 'graph.microsoft.com',

        # Apple
        'apple.com', 'www.apple.com', 'developer.apple.com',

        # GitHub
        'github.com', 'raw.githubusercontent.com', 'api.github.com',
        'gist.github.com', 'github.io',

        # Common legitimate extension infrastructure
        'chrome-extension-api.com', 'extension.dev',

        # RFC 2606 reserved (documentation/examples — never malicious)
        'example.com', 'example.org', 'example.net', 'example.edu', 'www.example.com',
    }

    def __init__(self):
        self.api_key = self._load_api_key()
        self.base_url = "https://www.virustotal.com/api/v3"
        self.session = requests.Session()
        if self.api_key:
            self.session.headers.update({
                "x-apikey": self.api_key
            })
        self.rate_limit_delay = 15  # Free API: 4 requests/minute

        # PERFORMANCE: Load results cache to avoid re-checking domains
        self._cache = self._load_cache()
        self._cache_path = Path(__file__).parent.parent / 'data' / 'vt_cache.json'

        # Cache validity periods (in hours)
        self._cache_ttl_clean = 24  # Clean domains cached for 24 hours
        self._cache_ttl_suspicious = 1  # Suspicious/malicious rechecked hourly
    
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

    def _load_cache(self):
        """Load VT results cache from disk"""
        cache_path = Path(__file__).parent.parent / 'data' / 'vt_cache.json'
        try:
            if cache_path.exists():
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            print(f"[i] VT cache load failed: {e}")
        return {'domains': {}, 'metadata': {'created': datetime.now(timezone.utc).isoformat()}}

    def _save_cache(self):
        """Save VT results cache to disk"""
        try:
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            self._cache['metadata']['updated'] = datetime.now(timezone.utc).isoformat()
            with open(self._cache_path, 'w', encoding='utf-8') as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            print(f"[i] VT cache save failed: {e}")

    def _get_cached_result(self, domain):
        """Get cached VT result if valid

        Returns cached result if:
        - Domain is in cache AND
        - Cache entry is not expired based on threat level

        Cache TTL:
        - CLEAN: 24 hours (safe domains change rarely)
        - SUSPICIOUS/MALICIOUS: 1 hour (re-check frequently)
        """
        if domain not in self._cache.get('domains', {}):
            return None

        cached = self._cache['domains'][domain]
        cached_time = cached.get('cached_at')

        if not cached_time:
            return None

        try:
            cache_dt = datetime.fromisoformat(cached_time.replace('Z', '+00:00'))
            now = datetime.now(timezone.utc)
            age_hours = (now - cache_dt).total_seconds() / 3600

            threat_level = cached.get('result', {}).get('threat_level', 'CLEAN')

            # Check if cache is still valid
            if threat_level in ['MALICIOUS', 'SUSPICIOUS']:
                if age_hours < self._cache_ttl_suspicious:
                    print(f"[VT] Cache hit: {domain} ({threat_level}, {age_hours:.1f}h old)")
                    return cached['result']
            else:
                if age_hours < self._cache_ttl_clean:
                    print(f"[VT] Cache hit: {domain} (clean, {age_hours:.1f}h old)")
                    return cached['result']

        except Exception:
            pass

        return None

    def _cache_result(self, domain, result):
        """Cache a VT result"""
        if 'domains' not in self._cache:
            self._cache['domains'] = {}

        self._cache['domains'][domain] = {
            'cached_at': datetime.now(timezone.utc).isoformat(),
            'result': result
        }
        # Save to disk periodically (every 5 domains cached)
        if len(self._cache['domains']) % 5 == 0:
            self._save_cache()

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

        PERFORMANCE: Checks cache first, then safe domain whitelist,
        then makes API call only if necessary.

        Returns:
            dict: Reputation data with scores, verdicts, and community votes
        """
        domain_lower = domain.lower()

        # OPTIMIZATION 1: Check cache first (fastest)
        cached_result = self._get_cached_result(domain_lower)
        if cached_result:
            return cached_result

        # OPTIMIZATION 2: Skip safe domains - no need to check well-known legitimate services
        if domain_lower in self.SAFE_DOMAINS or any(domain_lower.endswith('.' + safe) for safe in self.SAFE_DOMAINS):
            result = {
                'available': True,
                'domain': domain,
                'known': True,
                'skipped': True,
                'threat_level': 'CLEAN',
                'message': 'Known safe domain (skipped VT check)',
                'malicious': 0,
                'suspicious': 0,
                'harmless': 1,
                'undetected': 0,
                'reputation': 100,
                'malicious_vendors': [],
                'suspicious_vendors': []
            }
            # Cache safe domain result (with long TTL)
            self._cache_result(domain_lower, result)
            return result

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
            
            result = {
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

            # OPTIMIZATION: Cache result for future lookups
            self._cache_result(domain_lower, result)
            return result

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
        cached = sum(1 for r in results if r.get('skipped') or 'Cache hit' in str(r.get('message', '')))

        print(f"\n[VT] Summary: {malicious} malicious, {suspicious} suspicious, {len(results) - malicious - suspicious} clean/unknown")
        if cached > 0:
            print(f"[VT] Performance: {cached} domains from cache (saved {cached * 15}s)")

        # Save cache to disk at end of batch
        self._save_cache()

        return results


    # ── File hash lookup ─────────────────────────────────────────────

    def check_file_hash(self, sha256_hash, filename=None):
        """
        Look up a file SHA-256 hash on VirusTotal (GET /files/{hash}).
        No file upload – only checks if VT already has a report for this hash.

        Args:
            sha256_hash: SHA-256 hex string
            filename: Optional display name (e.g. 'background.js')

        Returns:
            dict with keys: available, hash, filename, threat_level, stats,
                            malicious_vendors, vt_url
        """
        sha256_lower = sha256_hash.lower().strip()
        label = filename or sha256_lower[:16]

        # Cache check (reuse the domains bucket with a "file:" prefix)
        cache_key = f"file:{sha256_lower}"
        cached = self._get_cached_result(cache_key)
        if cached:
            return cached

        if not self.api_key:
            return {
                'available': False,
                'hash': sha256_lower,
                'filename': filename,
                'error': 'VirusTotal API key not configured',
            }

        try:
            url = f"{self.base_url}/files/{sha256_lower}"
            print(f"[VT] Checking file hash for {label}...")

            response = self.session.get(url, timeout=30)
            time.sleep(self.rate_limit_delay)

            if response.status_code == 404:
                result = {
                    'available': True,
                    'hash': sha256_lower,
                    'filename': filename,
                    'known': False,
                    'threat_level': 'UNKNOWN',
                    'message': 'File hash not found in VirusTotal database',
                }
                self._cache_result(cache_key, result)
                return result

            if response.status_code != 200:
                return {
                    'available': False,
                    'hash': sha256_lower,
                    'filename': filename,
                    'error': f'VirusTotal API error: {response.status_code}',
                }

            data = response.json()
            attrs = data.get('data', {}).get('attributes', {})
            stats = attrs.get('last_analysis_stats', {})
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)

            # Vendor details
            last_analysis = attrs.get('last_analysis_results', {})
            malicious_vendors = []
            for vendor, res in last_analysis.items():
                if res.get('category') == 'malicious':
                    malicious_vendors.append({
                        'vendor': vendor,
                        'result': res.get('result', 'malicious'),
                    })

            if malicious_count > 0:
                threat_level = 'MALICIOUS'
            elif suspicious_count > 3:
                threat_level = 'SUSPICIOUS'
            else:
                threat_level = 'CLEAN'

            result = {
                'available': True,
                'hash': sha256_lower,
                'filename': filename,
                'known': True,
                'threat_level': threat_level,
                'stats': {
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'harmless': stats.get('harmless', 0),
                    'undetected': stats.get('undetected', 0),
                },
                'malicious_vendors': malicious_vendors[:10],
                'vt_url': f"https://www.virustotal.com/gui/file/{sha256_lower}",
                'file_type': attrs.get('type_description', ''),
                'file_name_vt': attrs.get('meaningful_name', ''),
            }
            self._cache_result(cache_key, result)
            return result

        except requests.exceptions.Timeout:
            return {'available': False, 'hash': sha256_lower, 'filename': filename, 'error': 'VT API timeout'}
        except Exception as e:
            return {'available': False, 'hash': sha256_lower, 'filename': filename, 'error': f'Error: {str(e)}'}

    def check_multiple_file_hashes(self, hashes, max_checks=10):
        """
        Check multiple file hashes against VirusTotal (respecting rate limits).

        Args:
            hashes: list of dicts with keys 'sha256' and optional 'filename'
            max_checks: max API calls (default 10)

        Returns:
            list of result dicts from check_file_hash()
        """
        if not hashes:
            return []

        results = []
        to_check = hashes[:max_checks]
        print(f"\n[VT] Checking {len(to_check)} file hash(es) against VirusTotal...")

        for i, entry in enumerate(to_check):
            sha = entry.get('sha256', '')
            fname = entry.get('filename', '')
            print(f"[VT] File hash {i + 1}/{len(to_check)}: {fname or sha[:16]}")
            result = self.check_file_hash(sha, filename=fname)
            results.append(result)

        malicious = sum(1 for r in results if r.get('threat_level') == 'MALICIOUS')
        if malicious:
            print(f"[VT] FILE HASH ALERT: {malicious} file(s) flagged as MALICIOUS!")
        else:
            print(f"[VT] File hash summary: {len(results)} checked, none flagged")

        self._save_cache()
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