"""
Host Permissions Analyzer
Deep analysis of Chrome extension host permissions and content script access
"""

import json
import re
from pathlib import Path
from urllib.parse import urlparse


class HostPermissionsAnalyzer:
    """Analyze host permissions and content script access patterns"""

    # Categories of sensitive websites
    SENSITIVE_CATEGORIES = {
        'banking': [
            'bank', 'banking', 'paypal', 'venmo', 'chase', 'wellsfargo',
            'bofa', 'citi', 'capitalone', 'discover', 'amex', 'stripe'
        ],
        'social_media': [
            'facebook', 'twitter', 'x.com', 'instagram', 'linkedin', 'tiktok',
            'snapchat', 'reddit', 'pinterest', 'whatsapp', 'telegram'
        ],
        'email': [
            'gmail', 'outlook', 'yahoo', 'protonmail', 'mail.google',
            'mail.yahoo', 'hotmail'
        ],
        'video_conferencing': [
            'zoom', 'teams.microsoft', 'meet.google', 'webex', 'goto',
            'gotowebinar', 'gotomeeting', 'skype'
        ],
        'productivity': [
            'google.com/drive', 'docs.google', 'sheets.google', 'slides.google',
            'office.com', 'onedrive', 'dropbox', 'notion', 'slack'
        ],
        'shopping': [
            'amazon', 'ebay', 'walmart', 'target', 'bestbuy', 'etsy'
        ],
        'healthcare': [
            'health', 'medical', 'doctor', 'pharmacy', 'cvs', 'walgreens'
        ],
        'government': [
            '.gov', 'irs.gov', 'ssa.gov', 'usps.com'
        ]
    }

    def __init__(self):
        """Initialize host permissions analyzer"""
        pass

    def analyze_manifest(self, manifest_path):
        """
        Deep analysis of host permissions from manifest.json

        Args:
            manifest_path: Path to manifest.json

        Returns:
            dict: Comprehensive host permissions analysis
        """
        try:
            with open(manifest_path, 'r', encoding='utf-8') as f:
                manifest = json.load(f)
        except Exception as e:
            return {'error': f'Failed to read manifest: {str(e)}'}

        analysis = {
            'host_permissions': [],
            'content_scripts': [],
            'web_accessible_resources': [],
            'all_urls_access': False,
            'sensitive_access': {},
            'risk_assessment': {},
            'permission_scope': 'UNKNOWN'
        }

        # Analyze host_permissions
        if 'host_permissions' in manifest:
            analysis['host_permissions'] = self._analyze_host_permissions(
                manifest['host_permissions']
            )

        # Analyze content_scripts
        if 'content_scripts' in manifest:
            analysis['content_scripts'] = self._analyze_content_scripts(
                manifest['content_scripts']
            )

        # Analyze web_accessible_resources
        if 'web_accessible_resources' in manifest:
            analysis['web_accessible_resources'] = self._analyze_web_accessible_resources(
                manifest['web_accessible_resources']
            )

        # Check for <all_urls> access
        analysis['all_urls_access'] = self._check_all_urls_access(manifest)

        # Categorize sensitive access
        all_domains = self._extract_all_domains(manifest)
        analysis['sensitive_access'] = self._categorize_sensitive_access(all_domains)

        # Risk assessment
        analysis['risk_assessment'] = self._assess_permission_risk(analysis)

        # Determine permission scope
        analysis['permission_scope'] = self._determine_scope(analysis)

        # Add statistics
        analysis['statistics'] = self._calculate_statistics(analysis)

        return analysis

    def _analyze_host_permissions(self, host_permissions):
        """Analyze host_permissions array"""
        results = []

        for permission in host_permissions:
            parsed = self._parse_permission_pattern(permission)
            results.append(parsed)

        return results

    def _analyze_content_scripts(self, content_scripts):
        """Analyze content_scripts array"""
        results = []

        for script in content_scripts:
            matches = script.get('matches', [])
            js_files = script.get('js', [])
            css_files = script.get('css', [])

            for match in matches:
                parsed = self._parse_permission_pattern(match)
                parsed['injected_js'] = js_files
                parsed['injected_css'] = css_files
                parsed['run_at'] = script.get('run_at', 'document_idle')
                results.append(parsed)

        return results

    def _analyze_web_accessible_resources(self, resources):
        """Analyze web_accessible_resources"""
        results = []

        # Handle both Manifest V2 and V3 formats
        if isinstance(resources, list):
            if resources and isinstance(resources[0], dict):
                # Manifest V3 format
                for resource_group in resources:
                    matches = resource_group.get('matches', [])
                    resource_list = resource_group.get('resources', [])

                    for match in matches:
                        parsed = self._parse_permission_pattern(match)
                        parsed['accessible_resources'] = resource_list
                        results.append(parsed)
            else:
                # Manifest V2 format - just a list of files
                results = resources

        return results

    def _parse_permission_pattern(self, pattern):
        """Parse a permission pattern like https://*.zoom.us/*"""
        result = {
            'pattern': pattern,
            'scheme': 'unknown',
            'host': 'unknown',
            'path': '/*',
            'wildcard_subdomain': False,
            'wildcard_path': False,
            'risk_level': 'UNKNOWN',
            'description': '',
            'category': 'uncategorized'
        }

        # Check for <all_urls>
        if pattern == '<all_urls>':
            result['scheme'] = 'all'
            result['host'] = 'all'
            result['path'] = 'all'
            result['wildcard_subdomain'] = True
            result['wildcard_path'] = True
            result['risk_level'] = 'CRITICAL'
            result['description'] = 'Full access to ALL websites on the internet'
            result['category'] = 'all_urls'
            return result

        # Parse URL pattern
        # Pattern format: <scheme>://<host><path>
        match = re.match(r'(\*|https?|file|ftp)://([^/]+)(.*)', pattern)

        if match:
            result['scheme'] = match.group(1)
            result['host'] = match.group(2)
            result['path'] = match.group(3) or '/*'

            # Check for wildcard subdomain
            if result['host'].startswith('*.'):
                result['wildcard_subdomain'] = True
                result['host'] = result['host'][2:]  # Remove *.

            # Check for wildcard path
            if '*' in result['path']:
                result['wildcard_path'] = True

            # Determine risk level
            result['risk_level'] = self._determine_permission_risk(result)

            # Add description
            result['description'] = self._generate_permission_description(result)

            # Categorize
            result['category'] = self._categorize_domain(result['host'])

        return result

    def _determine_permission_risk(self, parsed):
        """Determine risk level of a permission"""
        host = parsed['host']
        wildcard_subdomain = parsed['wildcard_subdomain']

        # Check if sensitive domain
        for category, keywords in self.SENSITIVE_CATEGORIES.items():
            for keyword in keywords:
                if keyword in host.lower():
                    if wildcard_subdomain:
                        return 'HIGH'
                    return 'MEDIUM'

        # Wildcard subdomain to any domain
        if wildcard_subdomain:
            return 'MEDIUM'

        # Specific domain
        return 'LOW'

    def _generate_permission_description(self, parsed):
        """Generate human-readable description"""
        host = parsed['host']
        scheme = parsed['scheme']
        wildcard_subdomain = parsed['wildcard_subdomain']
        wildcard_path = parsed['wildcard_path']

        desc = f"Access to "

        if wildcard_subdomain:
            desc += f"all subdomains of {host}"
        else:
            desc += host

        if wildcard_path:
            desc += " (all pages)"
        else:
            desc += f" (path: {parsed['path']})"

        return desc

    def _categorize_domain(self, host):
        """Categorize domain by type"""
        host_lower = host.lower()

        for category, keywords in self.SENSITIVE_CATEGORIES.items():
            for keyword in keywords:
                if keyword in host_lower:
                    return category

        return 'other'

    def _check_all_urls_access(self, manifest):
        """Check if extension has <all_urls> access anywhere"""
        # Check host_permissions
        if 'host_permissions' in manifest:
            if '<all_urls>' in manifest['host_permissions']:
                return True

        # Check content_scripts
        if 'content_scripts' in manifest:
            for script in manifest['content_scripts']:
                matches = script.get('matches', [])
                if '<all_urls>' in matches:
                    return True

        # Check web_accessible_resources
        if 'web_accessible_resources' in manifest:
            resources = manifest['web_accessible_resources']
            if isinstance(resources, list):
                for resource_group in resources:
                    if isinstance(resource_group, dict):
                        matches = resource_group.get('matches', [])
                        if '<all_urls>' in matches:
                            return True

        return False

    def _extract_all_domains(self, manifest):
        """Extract all unique domains from manifest"""
        domains = set()

        # From host_permissions
        if 'host_permissions' in manifest:
            for perm in manifest['host_permissions']:
                domain = self._extract_domain_from_pattern(perm)
                if domain:
                    domains.add(domain)

        # From content_scripts
        if 'content_scripts' in manifest:
            for script in manifest['content_scripts']:
                for match in script.get('matches', []):
                    domain = self._extract_domain_from_pattern(match)
                    if domain:
                        domains.add(domain)

        return list(domains)

    def _extract_domain_from_pattern(self, pattern):
        """Extract base domain from permission pattern"""
        if pattern == '<all_urls>':
            return None

        match = re.match(r'(\*|https?|file|ftp)://([^/]+)', pattern)
        if match:
            host = match.group(2)
            # Remove wildcard prefix
            if host.startswith('*.'):
                host = host[2:]
            return host

        return None

    def _categorize_sensitive_access(self, domains):
        """Categorize which sensitive sites extension can access"""
        categorized = {}

        for domain in domains:
            domain_lower = domain.lower()

            for category, keywords in self.SENSITIVE_CATEGORIES.items():
                for keyword in keywords:
                    if keyword in domain_lower:
                        if category not in categorized:
                            categorized[category] = []
                        categorized[category].append(domain)
                        break

        return categorized

    def _assess_permission_risk(self, analysis):
        """Assess overall risk of permissions"""
        risk = {
            'overall_risk': 'LOW',
            'risk_factors': [],
            'risk_score': 0
        }

        # Check for <all_urls>
        if analysis['all_urls_access']:
            risk['risk_factors'].append('Has <all_urls> access - can read/modify ALL websites')
            risk['risk_score'] += 10
            risk['overall_risk'] = 'CRITICAL'

        # Check sensitive access
        sensitive = analysis['sensitive_access']
        if sensitive:
            for category, domains in sensitive.items():
                risk['risk_factors'].append(
                    f"Accesses {len(domains)} {category.replace('_', ' ')} site(s): {', '.join(domains[:3])}"
                )
                risk['risk_score'] += len(domains) * 2

        # Check number of domains
        total_host_perms = len(analysis['host_permissions'])
        total_content_scripts = len(analysis['content_scripts'])

        if total_host_perms > 20:
            risk['risk_factors'].append(f'Requests access to {total_host_perms} different domains (very broad)')
            risk['risk_score'] += 5
        elif total_host_perms > 10:
            risk['risk_factors'].append(f'Requests access to {total_host_perms} different domains (broad)')
            risk['risk_score'] += 3

        # Determine overall risk
        if risk['risk_score'] >= 15:
            risk['overall_risk'] = 'CRITICAL'
        elif risk['risk_score'] >= 10:
            risk['overall_risk'] = 'HIGH'
        elif risk['risk_score'] >= 5:
            risk['overall_risk'] = 'MEDIUM'
        else:
            risk['overall_risk'] = 'LOW'

        return risk

    def _determine_scope(self, analysis):
        """Determine the scope of permissions"""
        if analysis['all_urls_access']:
            return 'ALL_WEBSITES'

        total_domains = len(analysis['host_permissions'])

        if total_domains > 50:
            return 'VERY_BROAD'
        elif total_domains > 20:
            return 'BROAD'
        elif total_domains > 5:
            return 'MODERATE'
        elif total_domains > 1:
            return 'LIMITED'
        else:
            return 'MINIMAL'

    def _calculate_statistics(self, analysis):
        """Calculate statistics"""
        return {
            'total_host_permissions': len(analysis['host_permissions']),
            'total_content_scripts': len(analysis['content_scripts']),
            'total_sensitive_categories': len(analysis['sensitive_access']),
            'total_sensitive_domains': sum(len(domains) for domains in analysis['sensitive_access'].values()),
            'has_all_urls': analysis['all_urls_access']
        }


def test_host_permissions_analyzer():
    """Test host permissions analyzer"""
    print("=" * 80)
    print("HOST PERMISSIONS ANALYZER TEST")
    print("=" * 80)

    analyzer = HostPermissionsAnalyzer()

    # Test with a sample manifest path
    test_manifest = Path("data/extensions/pdadlkbckhinonakkfkdaadceojbekep/manifest.json")

    if test_manifest.exists():
        print(f"\nAnalyzing: {test_manifest}")
        print("-" * 80)

        result = analyzer.analyze_manifest(test_manifest)

        print(f"\n[Permission Scope] {result['permission_scope']}")
        print(f"[Overall Risk] {result['risk_assessment']['overall_risk']}")
        print(f"[Risk Score] {result['risk_assessment']['risk_score']}/20")

        # Print statistics
        stats = result['statistics']
        print(f"\n[Statistics]")
        print(f"  • Host Permissions: {stats['total_host_permissions']}")
        print(f"  • Content Scripts: {stats['total_content_scripts']}")
        print(f"  • Sensitive Categories: {stats['total_sensitive_categories']}")
        print(f"  • Sensitive Domains: {stats['total_sensitive_domains']}")
        print(f"  • <all_urls> Access: {stats['has_all_urls']}")

        # Print sensitive access
        if result['sensitive_access']:
            print(f"\n[Sensitive Site Access]")
            for category, domains in result['sensitive_access'].items():
                print(f"  • {category.replace('_', ' ').title()}: {len(domains)} domain(s)")
                for domain in domains[:5]:
                    print(f"      - {domain}")
                if len(domains) > 5:
                    print(f"      ... and {len(domains) - 5} more")

        # Print risk factors
        if result['risk_assessment']['risk_factors']:
            print(f"\n[Risk Factors]")
            for factor in result['risk_assessment']['risk_factors']:
                print(f"  • {factor}")

        # Print some host permissions
        print(f"\n[Sample Host Permissions] (showing first 10)")
        for i, perm in enumerate(result['host_permissions'][:10]):
            print(f"  {i+1}. {perm['pattern']}")
            print(f"      Category: {perm['category']}")
            print(f"      Risk: {perm['risk_level']}")
            print(f"      {perm['description']}")

    else:
        print(f"[!] Test manifest not found: {test_manifest}")


if __name__ == "__main__":
    test_host_permissions_analyzer()
