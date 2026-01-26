"""
IOC (Indicators of Compromise) Manager
Dynamically generates and maintains IOC database from validated VirusTotal results
"""

import json
from datetime import datetime, timezone
from pathlib import Path


class IOCManager:
    """Manage IOC database with dynamic updates from validated threats"""

    def __init__(self, ioc_file='iocs.json'):
        """
        Initialize IOC manager

        Args:
            ioc_file: Path to IOC database file (default: iocs.json in repo root)
        """
        self.ioc_file = Path(ioc_file)
        self.iocs = self._load_iocs()

    def _load_iocs(self):
        """Load IOC database from file"""
        if not self.ioc_file.exists():
            return {'domains': {}, 'extensions': {}, 'metadata': {
                'created': datetime.now(timezone.utc).isoformat(),
                'last_updated': datetime.now(timezone.utc).isoformat(),
                'total_domains': 0,
                'total_extensions': 0
            }}

        try:
            with open(self.ioc_file, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            print(f"[IOC] Error loading IOC database: {e}")
            return {'domains': {}, 'extensions': {}, 'metadata': {}}

    def _save_iocs(self):
        """Save IOC database to file"""
        try:
            # Update metadata
            self.iocs['metadata']['last_updated'] = datetime.now(timezone.utc).isoformat()
            self.iocs['metadata']['total_domains'] = len(self.iocs.get('domains', {}))
            self.iocs['metadata']['total_extensions'] = len(self.iocs.get('extensions', {}))

            with open(self.ioc_file, 'w', encoding='utf-8') as f:
                json.dump(self.iocs, f, indent=2, ensure_ascii=False)

            print(f"[IOC] Database updated: {self.iocs['metadata']['total_domains']} domains, "
                  f"{self.iocs['metadata']['total_extensions']} extensions")
        except Exception as e:
            print(f"[IOC] Error saving IOC database: {e}")

    def add_domain_ioc(self, domain_data, extension_id, pii_classifications=None):
        """
        Add or update domain IOC from VirusTotal validation

        Args:
            domain_data: Dictionary with VirusTotal results
            extension_id: Extension ID using this domain
            pii_classifications: List of PII classifications detected

        Returns:
            bool: True if IOC was added/updated
        """
        # Only add if VirusTotal flagged it (2+ vendors or other strong signals)
        vt_detections = domain_data.get('stats', {}).get('malicious', 0)
        threat_level = domain_data.get('threat_level', 'CLEAN')

        if vt_detections < 2 and threat_level not in ['MALICIOUS', 'SUSPICIOUS']:
            return False

        domain = domain_data.get('domain')

        if not domain:
            return False

        # Initialize domains dict if needed
        if 'domains' not in self.iocs:
            self.iocs['domains'] = {}

        # Check if domain already exists
        if domain in self.iocs['domains']:
            ioc_entry = self.iocs['domains'][domain]
            # Update extension list
            if extension_id not in ioc_entry['extensions_using']:
                ioc_entry['extensions_using'].append(extension_id)
            # Update detection count if increased
            if vt_detections > ioc_entry.get('vt_detections', 0):
                ioc_entry['vt_detections'] = vt_detections
                ioc_entry['vt_vendors'] = [
                    v['vendor'] for v in domain_data.get('malicious_vendors', [])
                ]
            ioc_entry['last_seen'] = datetime.now(timezone.utc).isoformat()
            ioc_entry['total_observations'] = ioc_entry.get('total_observations', 1) + 1
        else:
            # Create new IOC entry
            ioc_entry = {
                'domain': domain,
                'first_seen': datetime.now(timezone.utc).isoformat(),
                'last_seen': datetime.now(timezone.utc).isoformat(),
                'vt_detections': vt_detections,
                'vt_vendors': [v['vendor'] for v in domain_data.get('malicious_vendors', [])],
                'threat_level': threat_level,
                'reputation': domain_data.get('reputation', 0),
                'extensions_using': [extension_id],
                'total_observations': 1
            }

            # Add domain age if available
            if domain_data.get('domain_age'):
                ioc_entry['domain_age_days'] = domain_data['domain_age']['age_days']
                ioc_entry['creation_date'] = domain_data['domain_age']['creation_date']

            # Add TLD risk if available
            if domain_data.get('tld_risk'):
                ioc_entry['high_risk_tld'] = domain_data['tld_risk']['is_high_risk']
                ioc_entry['tld'] = domain_data['tld_risk']['tld']

            # Add combined risk score
            if domain_data.get('combined_risk_score') is not None:
                ioc_entry['combined_risk_score'] = domain_data['combined_risk_score']

        # Add PII classifications if provided
        if pii_classifications:
            data_types = list(set([
                classification['category']
                for classification in pii_classifications
            ]))
            ioc_entry['data_exfiltrated'] = data_types

            # Calculate max severity
            max_severity = max([
                classification['severity_score']
                for classification in pii_classifications
            ], default=0)
            ioc_entry['max_pii_severity'] = max_severity

        self.iocs['domains'][domain] = ioc_entry
        self._save_iocs()

        return True

    def add_extension_ioc(self, extension_data):
        """
        Add or update extension IOC

        Args:
            extension_data: Dictionary with extension analysis results

        Returns:
            bool: True if IOC was added/updated
        """
        extension_id = extension_data.get('extension_id')
        risk_score = extension_data.get('risk_score', 0)

        # Only add if risk score is concerning (>= 6.0)
        if risk_score < 6.0:
            return False

        if not extension_id:
            return False

        # Initialize extensions dict if needed
        if 'extensions' not in self.iocs:
            self.iocs['extensions'] = {}

        ioc_entry = {
            'extension_id': extension_id,
            'name': extension_data.get('name', 'Unknown'),
            'version': extension_data.get('version', 'Unknown'),
            'risk_score': risk_score,
            'malicious_domains': extension_data.get('malicious_domains', []),
            'suspicious_patterns': extension_data.get('suspicious_patterns', []),
            'dangerous_permissions': extension_data.get('dangerous_permissions', []),
            'first_analyzed': extension_data.get('first_analyzed') or datetime.now(timezone.utc).isoformat(),
            'last_analyzed': datetime.now(timezone.utc).isoformat()
        }

        self.iocs['extensions'][extension_id] = ioc_entry
        self._save_iocs()

        return True

    def check_domain(self, domain):
        """
        Check if domain is in IOC database

        Args:
            domain: Domain to check

        Returns:
            dict: IOC entry if found, None otherwise
        """
        return self.iocs.get('domains', {}).get(domain)

    def check_extension(self, extension_id):
        """
        Check if extension is in IOC database

        Args:
            extension_id: Extension ID to check

        Returns:
            dict: IOC entry if found, None otherwise
        """
        return self.iocs.get('extensions', {}).get(extension_id)

    def get_related_extensions(self, domain):
        """
        Get all extensions using a specific domain

        Args:
            domain: Domain to check

        Returns:
            list: Extension IDs using this domain
        """
        domain_ioc = self.check_domain(domain)
        if domain_ioc:
            return domain_ioc.get('extensions_using', [])
        return []

    def get_statistics(self):
        """
        Get IOC database statistics

        Returns:
            dict: Statistics about IOC database
        """
        domains = self.iocs.get('domains', {})
        extensions = self.iocs.get('extensions', {})

        malicious_domains = sum(
            1 for d in domains.values()
            if d.get('threat_level') == 'MALICIOUS'
        )

        high_risk_extensions = sum(
            1 for e in extensions.values()
            if e.get('risk_score', 0) >= 8.0
        )

        critical_pii_domains = sum(
            1 for d in domains.values()
            if d.get('max_pii_severity', 0) >= 8
        )

        return {
            'total_domains': len(domains),
            'malicious_domains': malicious_domains,
            'total_extensions': len(extensions),
            'high_risk_extensions': high_risk_extensions,
            'critical_pii_domains': critical_pii_domains,
            'last_updated': self.iocs.get('metadata', {}).get('last_updated', 'Unknown')
        }

    def export_iocs_for_sharing(self, format='stix'):
        """
        Export IOCs in standard formats for sharing with security tools

        Args:
            format: Export format ('stix', 'csv', 'json')

        Returns:
            str: Exported IOCs in requested format
        """
        if format == 'csv':
            return self._export_csv()
        elif format == 'stix':
            return self._export_stix()
        else:
            return json.dumps(self.iocs, indent=2)

    def _export_csv(self):
        """Export IOCs as CSV"""
        lines = ['domain,threat_level,vt_detections,first_seen,extensions_count']

        for domain, data in self.iocs.get('domains', {}).items():
            lines.append(
                f"{domain},"
                f"{data.get('threat_level', 'UNKNOWN')},"
                f"{data.get('vt_detections', 0)},"
                f"{data.get('first_seen', 'N/A')},"
                f"{len(data.get('extensions_using', []))}"
            )

        return '\n'.join(lines)

    def _export_stix(self):
        """Export IOCs in STIX format (simplified)"""
        stix_objects = []

        for domain, data in self.iocs.get('domains', {}).items():
            stix_objects.append({
                'type': 'indicator',
                'pattern': f"[domain-name:value = '{domain}']",
                'labels': ['malicious-activity', 'malware'],
                'name': f'Malicious domain: {domain}',
                'description': f"Domain flagged by {data.get('vt_detections', 0)} VirusTotal vendors",
                'valid_from': data.get('first_seen', datetime.now(timezone.utc).isoformat())
            })

        return json.dumps({'type': 'bundle', 'objects': stix_objects}, indent=2)


def test_ioc_manager():
    """Test IOC manager"""
    print("=" * 80)
    print("IOC MANAGER TEST")
    print("=" * 80)

    # Create test manager
    manager = IOCManager('test_iocs.json')

    # Test adding domain IOC
    print("\n1. Testing Domain IOC Addition:")
    print("-" * 80)

    domain_data = {
        'domain': 'malicious-test.top',
        'threat_level': 'MALICIOUS',
        'stats': {'malicious': 5, 'suspicious': 2},
        'reputation': -80,
        'malicious_vendors': [
            {'vendor': 'CRDF', 'result': 'malware'},
            {'vendor': 'Seclookup', 'result': 'phishing'}
        ],
        'domain_age': {
            'age_days': 15,
            'creation_date': '2026-01-10',
            'risk_level': 'CRITICAL'
        },
        'tld_risk': {
            'is_high_risk': True,
            'tld': '.top'
        },
        'combined_risk_score': 9
    }

    pii_data = [
        {'category': 'CREDENTIALS', 'severity_score': 10},
        {'category': 'COOKIES_SESSIONS', 'severity_score': 8}
    ]

    added = manager.add_domain_ioc(domain_data, 'test_extension_id', pii_data)
    print(f"Domain IOC added: {added}")

    # Check domain
    print("\n2. Testing Domain Lookup:")
    print("-" * 80)
    ioc = manager.check_domain('malicious-test.top')
    if ioc:
        print(f"Domain found in IOC database:")
        print(f"  Threat Level: {ioc['threat_level']}")
        print(f"  VT Detections: {ioc['vt_detections']}")
        print(f"  Extensions Using: {ioc['extensions_using']}")
        print(f"  Data Exfiltrated: {ioc.get('data_exfiltrated', [])}")

    # Get statistics
    print("\n3. IOC Database Statistics:")
    print("-" * 80)
    stats = manager.get_statistics()
    for key, value in stats.items():
        print(f"  {key}: {value}")

    # Export
    print("\n4. Exporting IOCs (CSV):")
    print("-" * 80)
    csv_export = manager.export_iocs_for_sharing('csv')
    print(csv_export)

    # Cleanup test file
    Path('test_iocs.json').unlink(missing_ok=True)
    print("\n[Test completed and cleanup done]")


if __name__ == "__main__":
    test_ioc_manager()
