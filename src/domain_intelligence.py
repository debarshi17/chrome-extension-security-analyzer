"""
Domain Intelligence Module
Professional domain analysis for threat intelligence
Based on real C2, DGA, and malware infrastructure research
"""

import re
import math
from urllib.parse import urlparse
from collections import Counter
import hashlib

class DomainIntelligence:
    """
    Professional domain analysis engine
    Distinguishes between legitimate APIs, suspicious domains, and real threats
    """
    
    def __init__(self):
        # Legitimate infrastructure (CDNs, APIs, services)
        self.legitimate_infrastructure = {
            # Web standards organizations (ALWAYS SAFE)
            'w3.org', 'w3c.org', 'whatwg.org', 'ecma-international.org',
            'ietf.org', 'rfc-editor.org', 'json-schema.org', 'schema.org',

            # Major cloud providers
            'amazonaws.com', 'cloudfront.net', 'awsstatic.com',
            'azure.com', 'azurewebsites.net', 'windows.net',
            'googleusercontent.com', 'googleapis.com', 'gstatic.com',
            'cloudflare.com', 'cloudflare.net', 'cf-ipfs.com',

            # Google Cloud Platform (GCP)
            'cloudfunctions.net',      # Cloud Functions (serverless)
            'run.app',                  # Cloud Run (containers)
            'appspot.com',              # App Engine
            'firebaseio.com',           # Firebase Realtime Database
            'firebase.io',              # Firebase (alternative domain)
            'firebaseapp.com',          # Firebase Hosting
            'googleplex.com',           # Google internal

            # AWS Services
            'elasticbeanstalk.com',     # AWS Elastic Beanstalk
            'lambda-url.amazonaws.com', # AWS Lambda Function URLs
            's3.amazonaws.com',         # S3 storage

            # Azure Services
            'azurefd.net',              # Azure Front Door
            'azureedge.net',            # Azure CDN
            'core.windows.net',         # Azure Storage

            # Platform-as-a-Service (PaaS)
            'herokuapp.com',            # Heroku
            'vercel.app',               # Vercel
            'netlify.app',              # Netlify
            'pages.dev',                # Cloudflare Pages
            'railway.app',              # Railway
            'render.com',               # Render
            'fly.dev',                  # Fly.io

            # CDNs
            'akamai.net', 'akamaitechnologies.com', 'akamaized.net',
            'fastly.net', 'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',

            # Email providers
            'gmail.com', 'outlook.com', 'yahoo.com', 'protonmail.com',
            'mail.google.com', 'mail.yahoo.com',

            # Social media
            'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
            'youtube.com', 'reddit.com', 'tiktok.com', 'pinterest.com',

            # Tech companies
            'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
            'github.com', 'gitlab.com', 'bitbucket.org',

            # Payment processors
            'stripe.com', 'paypal.com', 'square.com',

            # Analytics & monitoring
            'google-analytics.com', 'googletagmanager.com',
            'segment.com', 'mixpanel.com', 'amplitude.com',
        }
        
        # Known malicious TLDs (high-risk, low-cost, abuse-prone)
        self.high_risk_tlds = {
            '.xyz', '.top', '.club', '.online', '.site', '.work',
            '.uno', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq',
            '.icu', '.bid', '.win', '.review', '.download', '.stream',
            '.click', '.link', '.racing', '.cricket', '.webcam'
        }
        
        # Common DGA patterns (based on known malware families)
        self.dga_indicators = {
            'high_entropy': 4.5,  # Threshold for random-looking domains
            'consonant_ratio': 0.7,  # Too many consonants = suspicious
            'digit_ratio': 0.3,  # Too many numbers = suspicious
            'vowel_patterns': ['aeiou', 'ouaei'],  # Uncommon patterns
        }
    
    def analyze_domain(self, domain, url=None, context=None):
        """
        Comprehensive domain analysis
        Returns threat assessment with confidence scores
        
        Args:
            domain: Domain name to analyze
            url: Full URL for context analysis
            context: Additional context (request patterns, timing, etc.)
        
        Returns:
            dict: Detailed threat assessment
        """
        
        # Initialize assessment
        assessment = {
            'domain': domain,
            'url': url,
            'threat_level': 'UNKNOWN',
            'confidence': 0,
            'classification': None,
            'risk_score': 0,
            'indicators': [],
            'is_legitimate': False,
            'is_c2': False,
            'is_dga': False,
            'is_typosquat': False,
            'reputation': 'UNKNOWN'
        }
        
        # Step 1: Check if it's legitimate infrastructure
        if self._is_legitimate_infrastructure(domain):
            assessment['is_legitimate'] = True
            assessment['threat_level'] = 'BENIGN'
            assessment['classification'] = 'Legitimate Infrastructure'
            assessment['confidence'] = 95
            return assessment
        
        # Step 2: Check for typosquatting
        typosquat_result = self._check_typosquatting(domain)
        if typosquat_result:
            assessment['is_typosquat'] = True
            assessment['threat_level'] = 'HIGH'
            assessment['classification'] = 'Typosquatting'
            assessment['risk_score'] += 8
            assessment['indicators'].append({
                'type': 'TYPOSQUATTING',
                'description': f'Typosquatting attempt of {typosquat_result}',
                'severity': 'HIGH'
            })
            assessment['confidence'] = 85
        
        # Step 3: Check for DGA characteristics
        dga_result = self._detect_dga(domain)
        if dga_result['is_dga']:
            assessment['is_dga'] = True
            assessment['threat_level'] = 'HIGH'
            assessment['classification'] = 'DGA (Domain Generation Algorithm)'
            assessment['risk_score'] += 7
            assessment['indicators'].append({
                'type': 'DGA',
                'description': f"DGA characteristics detected: {', '.join(dga_result['reasons'])}",
                'severity': 'HIGH',
                'details': dga_result
            })
            assessment['confidence'] = 80
        
        # Step 4: Check for suspicious TLD
        if self._has_suspicious_tld(domain):
            assessment['risk_score'] += 3
            tld = domain.split('.')[-1]
            assessment['indicators'].append({
                'type': 'SUSPICIOUS_TLD',
                'description': f'High-risk TLD: .{tld}',
                'severity': 'MEDIUM'
            })
        
        # Step 5: Check for newly registered domain indicators
        nrd_indicators = self._check_nrd_indicators(domain)
        if nrd_indicators:
            assessment['risk_score'] += 4
            assessment['indicators'].append({
                'type': 'NRD_INDICATORS',
                'description': 'Possible newly registered domain',
                'severity': 'MEDIUM',
                'reasons': nrd_indicators
            })
        
        # Step 6: Analyze URL patterns for C2 indicators (if URL provided)
        if url:
            c2_result = self._analyze_c2_patterns(url, context)
            if c2_result['is_c2']:
                assessment['is_c2'] = True
                assessment['threat_level'] = 'CRITICAL'
                assessment['classification'] = 'Command & Control Infrastructure'
                assessment['risk_score'] += 10
                assessment['indicators'].append({
                    'type': 'C2_PATTERN',
                    'description': 'C2 communication pattern detected',
                    'severity': 'CRITICAL',
                    'details': c2_result
                })
                assessment['confidence'] = 90
        
        # Final classification
        if assessment['risk_score'] == 0:
            assessment['threat_level'] = 'BENIGN'
            assessment['classification'] = 'Unknown but no indicators'
        elif assessment['risk_score'] >= 8:
            assessment['threat_level'] = 'CRITICAL' if not assessment['threat_level'] == 'CRITICAL' else 'CRITICAL'
        elif assessment['risk_score'] >= 5:
            assessment['threat_level'] = 'HIGH' if assessment['threat_level'] == 'UNKNOWN' else assessment['threat_level']
        elif assessment['risk_score'] >= 3:
            assessment['threat_level'] = 'MEDIUM' if assessment['threat_level'] == 'UNKNOWN' else assessment['threat_level']
        else:
            assessment['threat_level'] = 'LOW' if assessment['threat_level'] == 'UNKNOWN' else assessment['threat_level']
        
        # Set default confidence if not set
        if assessment['confidence'] == 0:
            assessment['confidence'] = min(assessment['risk_score'] * 10, 75)
        
        return assessment
    
    def _is_legitimate_infrastructure(self, domain):
        """Check if domain is part of legitimate infrastructure"""
        domain_lower = domain.lower()
        
        for legit in self.legitimate_infrastructure:
            if domain_lower == legit or domain_lower.endswith('.' + legit):
                return True
        
        return False
    
    def _check_typosquatting(self, domain):
        """
        Check for typosquatting of popular brands
        Returns the legitimate domain if typosquatting detected
        """
        
        # Extract base domain
        parts = domain.split('.')
        if len(parts) < 2:
            return None
        
        base = parts[-2].lower()
        tld = parts[-1].lower()
        
        # Popular brands to check
        brands = {
            'google': ['google.com', 'googleapis.com'],
            'facebook': ['facebook.com'],
            'amazon': ['amazon.com'],
            'microsoft': ['microsoft.com'],
            'apple': ['apple.com', 'icloud.com'],
            'paypal': ['paypal.com'],
            'netflix': ['netflix.com'],
            'instagram': ['instagram.com'],
            'twitter': ['twitter.com'],
            'linkedin': ['linkedin.com'],
            'github': ['github.com'],
            'dropbox': ['dropbox.com'],
        }
        
        # Check for homograph attacks (visual similarity)
        substitutions = {
            '0': 'o', '1': 'l', '3': 'e', '5': 's',
            'vv': 'w', 'rn': 'm', 'cl': 'd'
        }
        
        for brand, legit_domains in brands.items():
            # Check exact typo (1-2 char difference)
            if self._levenshtein_distance(base, brand) in [1, 2]:
                return legit_domains[0]
            
            # Check homograph (character substitution)
            normalized_base = base
            for fake, real in substitutions.items():
                normalized_base = normalized_base.replace(fake, real)
            
            if normalized_base == brand:
                return legit_domains[0]
        
        return None
    
    def _levenshtein_distance(self, s1, s2):
        """Calculate edit distance between two strings"""
        if len(s1) < len(s2):
            return self._levenshtein_distance(s2, s1)
        
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]
    
    def _detect_dga(self, domain):
        """
        Detect Domain Generation Algorithm (DGA) patterns
        Based on research from Alexa, Cisco Umbrella, and academic papers
        """
        
        # Extract base domain
        parts = domain.split('.')
        if len(parts) < 2:
            return {'is_dga': False, 'reasons': []}
        
        base = parts[-2]
        
        # Skip short domains (not enough data)
        if len(base) < 8:
            return {'is_dga': False, 'reasons': []}
        
        reasons = []
        dga_score = 0
        
        # 1. Calculate entropy (randomness)
        entropy = self._calculate_entropy(base)
        if entropy > self.dga_indicators['high_entropy']:
            dga_score += 3
            reasons.append(f'High entropy ({entropy:.2f}) indicates randomness')
        
        # 2. Check consonant/vowel ratio
        consonants = sum(1 for c in base if c in 'bcdfghjklmnpqrstvwxyz')
        vowels = sum(1 for c in base if c in 'aeiou')
        total_letters = consonants + vowels
        
        if total_letters > 0:
            consonant_ratio = consonants / total_letters
            if consonant_ratio > self.dga_indicators['consonant_ratio']:
                dga_score += 2
                reasons.append(f'Unusually high consonant ratio ({consonant_ratio:.2f})')
        
        # 3. Check digit ratio
        digits = sum(1 for c in base if c.isdigit())
        if len(base) > 0:
            digit_ratio = digits / len(base)
            if digit_ratio > self.dga_indicators['digit_ratio']:
                dga_score += 2
                reasons.append(f'High digit ratio ({digit_ratio:.2f})')
        
        # 4. Check for pronounceability (n-gram analysis)
        if not self._is_pronounceable(base):
            dga_score += 2
            reasons.append('Domain is not pronounceable (unlikely to be human-generated)')
        
        # 5. Check for repeating patterns (often in DGA)
        if self._has_repeating_patterns(base):
            dga_score += 1
            reasons.append('Contains repeating character patterns')
        
        # 6. Check for dictionary words
        if not self._contains_dictionary_words(base):
            dga_score += 1
            reasons.append('No recognizable dictionary words')
        
        is_dga = dga_score >= 5
        
        return {
            'is_dga': is_dga,
            'reasons': reasons,
            'score': dga_score,
            'entropy': entropy
        }
    
    def _calculate_entropy(self, s):
        """Calculate Shannon entropy"""
        if not s:
            return 0
        
        prob = [s.count(c) / len(s) for c in set(s)]
        entropy = -sum(p * math.log2(p) for p in prob)
        return entropy
    
    def _is_pronounceable(self, s):
        """Check if domain contains pronounceable patterns"""
        # Check for common bigrams (two-letter combinations)
        common_bigrams = [
            'th', 'he', 'in', 'er', 'an', 're', 'on', 'at', 'en', 'nd',
            'ti', 'es', 'or', 'te', 'of', 'ed', 'is', 'it', 'al', 'ar'
        ]
        
        s_lower = s.lower()
        found_bigrams = sum(1 for bigram in common_bigrams if bigram in s_lower)
        
        # If less than 10% of common bigrams found, likely not pronounceable
        return found_bigrams >= len(s) * 0.1
    
    def _has_repeating_patterns(self, s):
        """Check for repeating character patterns"""
        # Check for 2-char and 3-char repeating patterns
        for length in [2, 3]:
            for i in range(len(s) - length * 2 + 1):
                pattern = s[i:i+length]
                if s.count(pattern) >= 3:
                    return True
        return False
    
    def _contains_dictionary_words(self, s):
        """Check if domain contains common English words"""
        # Common words that might appear in legitimate domains
        common_words = [
            'app', 'api', 'web', 'net', 'mail', 'blog', 'shop', 'store',
            'cloud', 'data', 'tech', 'digital', 'online', 'service',
            'secure', 'pay', 'login', 'account', 'user', 'admin'
        ]
        
        s_lower = s.lower()
        return any(word in s_lower for word in common_words)
    
    def _has_suspicious_tld(self, domain):
        """Check if domain uses a high-risk TLD"""
        return any(domain.endswith(tld) for tld in self.high_risk_tlds)
    
    def _check_nrd_indicators(self, domain):
        """
        Check for Newly Registered Domain indicators
        (Without API access, we check for patterns common in NRDs)
        """
        indicators = []

        # Pattern 1: Very long domains (often used to avoid detection)
        # Exception: Cloud provider domains can be long (e.g., AWS)
        if len(domain) > 50:  # Increased threshold
            # Check if it's a cloud provider (already validated as legitimate above)
            if not self._is_cloud_provider_subdomain(domain):
                indicators.append('Unusually long domain name')

        # Pattern 2: Mixed case or numbers in unusual positions
        parts = domain.split('.')
        if len(parts) >= 2:
            base = parts[-2]
            # Exception: Cloud providers use region codes (us-central1, eu-west-1)
            if any(c.isdigit() for c in base[:3]) and not self._is_cloud_provider_subdomain(domain):
                indicators.append('Numbers in unusual positions')

        # Pattern 3: Suspicious subdomain structure
        # Cloud providers commonly use subdomains: <region>-<project>.cloudfunctions.net
        # Only flag if >4 parts AND not a known cloud pattern
        if len(parts) > 4:  # More lenient threshold
            if not self._is_cloud_provider_subdomain(domain):
                indicators.append('Complex subdomain structure')

        return indicators

    def _is_cloud_provider_subdomain(self, domain):
        """Check if domain follows cloud provider subdomain patterns"""
        # Check if it's already in legitimate infrastructure
        for legit in self.legitimate_infrastructure:
            if domain.endswith('.' + legit):
                return True

        # Check for common cloud provider patterns
        cloud_patterns = [
            # GCP patterns
            r'\.cloudfunctions\.net$',
            r'\.run\.app$',
            r'\.appspot\.com$',
            r'\.firebaseio\.com$',
            r'\.firebaseapp\.com$',

            # AWS patterns
            r'\.amazonaws\.com$',
            r'\.elasticbeanstalk\.com$',

            # Azure patterns
            r'\.azurewebsites\.net$',
            r'\.azurefd\.net$',
            r'\.core\.windows\.net$',

            # PaaS patterns
            r'\.herokuapp\.com$',
            r'\.vercel\.app$',
            r'\.netlify\.app$',
            r'\.pages\.dev$',
        ]

        import re
        for pattern in cloud_patterns:
            if re.search(pattern, domain):
                return True

        return False
    
    def _analyze_c2_patterns(self, url, context):
        """
        Analyze URL for C2 (Command & Control) patterns
        Real C2 detection requires behavioral analysis, not just URL patterns
        """
        
        c2_indicators = {
            'is_c2': False,
            'confidence': 0,
            'indicators': []
        }
        
        parsed = urlparse(url)
        path = parsed.path.lower()
        query = parsed.query.lower()
        
        # Pattern 1: Common C2 endpoints
        c2_endpoints = [
            '/api/v1/beacon', '/c2/', '/cmd/', '/exec/',
            '/update', '/config', '/task', '/job',
            '/gate.php', '/panel/', '/admin/api/'
        ]
        
        for endpoint in c2_endpoints:
            if endpoint in path:
                c2_indicators['indicators'].append(f'Suspicious endpoint: {endpoint}')
                c2_indicators['confidence'] += 30
        
        # Pattern 2: Base64 encoded parameters (often used in C2)
        if 'data=' in query or 'payload=' in query or 'cmd=' in query:
            c2_indicators['indicators'].append('Suspicious query parameters')
            c2_indicators['confidence'] += 20
        
        # Pattern 3: Unusual ports
        if parsed.port and parsed.port not in [80, 443, 8080]:
            c2_indicators['indicators'].append(f'Non-standard port: {parsed.port}')
            c2_indicators['confidence'] += 15
        
        c2_indicators['is_c2'] = c2_indicators['confidence'] >= 40
        
        return c2_indicators