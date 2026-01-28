"""
Cuckoo Sandbox Integration
Submits Chrome extensions for dynamic analysis in Cuckoo Sandbox
"""

import requests
import time
import json
from pathlib import Path


class CuckooSandbox:
    """Interface to Cuckoo Sandbox for dynamic malware analysis"""

    def __init__(self, api_url=None, api_key=None):
        """
        Initialize Cuckoo Sandbox client

        Args:
            api_url: Cuckoo REST API URL (e.g., http://localhost:8090)
            api_key: API key if authentication is enabled (optional)
        """
        self.api_url = api_url or self._load_config().get('api_url')
        self.api_key = api_key or self._load_config().get('api_key')

        if not self.api_url:
            print("[!] Warning: Cuckoo Sandbox API URL not configured. Dynamic analysis disabled.")
            self.enabled = False
        else:
            self.enabled = True
            print(f"[CUCKOO] Connected to: {self.api_url}")

    def _load_config(self):
        """Load Cuckoo configuration from config.json"""
        config_path = Path("config.json")

        if not config_path.exists():
            return {}

        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
                return config.get('cuckoo', {})
        except Exception as e:
            print(f"[!] Error loading Cuckoo config: {e}")
            return {}

    def _get_headers(self):
        """Get request headers with optional API key"""
        headers = {}
        if self.api_key:
            headers['Authorization'] = f'Bearer {self.api_key}'
        return headers

    def _check_available_vms(self):
        """Check if Cuckoo has analysis VMs available"""
        try:
            response = requests.get(
                f"{self.api_url}/cuckoo/status",
                headers=self._get_headers(),
                timeout=5
            )

            if response.status_code == 200:
                status = response.json()
                machines = status.get('machines', {})
                total_vms = machines.get('total', 0)
                available_vms = machines.get('available', 0)

                if total_vms == 0:
                    return {
                        'has_vms': False,
                        'message': 'No analysis VMs configured. Skipping dynamic analysis.',
                        'total': 0,
                        'available': 0
                    }
                elif available_vms == 0:
                    return {
                        'has_vms': False,
                        'message': f'All {total_vms} VMs are busy. Skipping dynamic analysis.',
                        'total': total_vms,
                        'available': 0
                    }
                else:
                    return {
                        'has_vms': True,
                        'message': f'{available_vms}/{total_vms} VMs available',
                        'total': total_vms,
                        'available': available_vms
                    }
            else:
                return {
                    'has_vms': False,
                    'message': f'Cuckoo API error: {response.status_code}',
                    'total': 0,
                    'available': 0
                }

        except Exception as e:
            return {
                'has_vms': False,
                'message': f'Cannot check Cuckoo status: {e}',
                'total': 0,
                'available': 0
            }

    def submit_extension(self, extension_path, extension_id, timeout=300):
        """
        Submit Chrome extension to Cuckoo Sandbox for analysis

        Args:
            extension_path: Path to unpacked extension directory or CRX file
            extension_id: Chrome extension ID
            timeout: Maximum time to wait for analysis (seconds)

        Returns:
            dict: Analysis results or error info
        """
        if not self.enabled:
            return {
                'available': False,
                'error': 'Cuckoo Sandbox not configured'
            }

        try:
            # Check if Cuckoo has VMs available before submitting
            vm_check = self._check_available_vms()
            if not vm_check['has_vms']:
                print(f"[CUCKOO] {vm_check['message']}")
                return {
                    'available': False,
                    'error': vm_check['message'],
                    'vms_configured': False
                }

            # For extensions, we submit the CRX file or create a zip
            crx_path = Path(f"downloads/{extension_id}.crx")

            if not crx_path.exists():
                # Create zip from unpacked extension
                print("[CUCKOO] Creating submission package...")
                import zipfile
                zip_path = Path(f"downloads/{extension_id}_sandbox.zip")

                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for file in Path(extension_path).rglob('*'):
                        if file.is_file():
                            zipf.write(file, file.relative_to(extension_path))

                submit_file = zip_path
            else:
                submit_file = crx_path

            print(f"[CUCKOO] Submitting {submit_file.name} for analysis...")

            # Submit file to Cuckoo
            with open(submit_file, 'rb') as f:
                files = {'file': (submit_file.name, f)}
                data = {
                    'package': 'chrome',  # Use Chrome analysis package
                    'timeout': timeout,
                    'options': 'procmemdump=yes,enable-services=yes'
                }

                response = requests.post(
                    f"{self.api_url}/tasks/create/file",
                    headers=self._get_headers(),
                    files=files,
                    data=data,
                    timeout=30
                )

            if response.status_code != 200:
                return {
                    'available': False,
                    'error': f'Cuckoo submission failed: {response.status_code}'
                }

            task_data = response.json()
            task_id = task_data.get('task_id')

            if not task_id:
                return {
                    'available': False,
                    'error': 'No task ID returned from Cuckoo'
                }

            print(f"[CUCKOO] Task submitted. Task ID: {task_id}")
            print(f"[CUCKOO] Waiting for analysis to complete (timeout: {timeout}s)...")

            # Wait for analysis to complete
            result = self._wait_for_analysis(task_id, timeout)

            if result:
                # Parse and return relevant findings
                return self._parse_cuckoo_report(result, extension_id)
            else:
                return {
                    'available': False,
                    'error': 'Analysis timeout or failed'
                }

        except requests.exceptions.ConnectionError:
            return {
                'available': False,
                'error': 'Cannot connect to Cuckoo Sandbox API'
            }
        except Exception as e:
            return {
                'available': False,
                'error': f'Cuckoo submission error: {str(e)}'
            }

    def _wait_for_analysis(self, task_id, timeout):
        """Wait for Cuckoo analysis to complete"""
        start_time = time.time()

        while time.time() - start_time < timeout:
            try:
                # Check task status
                response = requests.get(
                    f"{self.api_url}/tasks/view/{task_id}",
                    headers=self._get_headers(),
                    timeout=10
                )

                if response.status_code == 200:
                    task_info = response.json()
                    status = task_info.get('task', {}).get('status')

                    if status == 'reported':
                        # Analysis complete, fetch report
                        return self._get_report(task_id)
                    elif status == 'failed':
                        print(f"[CUCKOO] Analysis failed for task {task_id}")
                        return None

                    # Still running
                    print(f"[CUCKOO] Analysis in progress... (status: {status})")

                time.sleep(10)  # Check every 10 seconds

            except Exception as e:
                print(f"[!] Error checking task status: {e}")
                time.sleep(10)

        print(f"[CUCKOO] Analysis timeout after {timeout}s")
        return None

    def _get_report(self, task_id):
        """Retrieve Cuckoo analysis report"""
        try:
            response = requests.get(
                f"{self.api_url}/tasks/report/{task_id}",
                headers=self._get_headers(),
                timeout=30
            )

            if response.status_code == 200:
                return response.json()
            else:
                print(f"[!] Error fetching report: {response.status_code}")
                return None

        except Exception as e:
            print(f"[!] Error retrieving report: {e}")
            return None

    def _parse_cuckoo_report(self, report, extension_id):
        """
        Parse Cuckoo report and extract relevant security findings

        Args:
            report: Full Cuckoo JSON report
            extension_id: Extension ID being analyzed

        Returns:
            dict: Parsed dynamic analysis results
        """
        try:
            info = report.get('info', {})
            signatures = report.get('signatures', [])
            network = report.get('network', {})
            behavior = report.get('behavior', {})

            # Extract network activity
            http_requests = network.get('http', [])
            dns_requests = network.get('dns', [])
            tcp_connections = network.get('tcp', [])

            # Parse suspicious behaviors
            malicious_indicators = []
            suspicious_indicators = []

            for sig in signatures:
                severity = sig.get('severity', 0)
                name = sig.get('name', 'Unknown')
                description = sig.get('description', '')

                indicator = {
                    'name': name,
                    'description': description,
                    'severity': severity
                }

                if severity >= 3:
                    malicious_indicators.append(indicator)
                elif severity >= 2:
                    suspicious_indicators.append(indicator)

            # Extract file operations
            file_activity = []
            if behavior.get('summary', {}).get('files'):
                for file_op in behavior['summary']['files']:
                    file_activity.append({
                        'operation': 'file_access',
                        'path': file_op
                    })

            # Extract registry operations (Windows-specific)
            registry_activity = []
            if behavior.get('summary', {}).get('keys'):
                for key in behavior['summary']['keys']:
                    registry_activity.append({
                        'operation': 'registry_access',
                        'key': key
                    })

            # Extract process activity
            processes = []
            if behavior.get('processes'):
                for proc in behavior['processes']:
                    processes.append({
                        'pid': proc.get('pid'),
                        'name': proc.get('process_name'),
                        'command_line': proc.get('command_line', '')
                    })

            # Calculate dynamic risk score
            dynamic_risk_score = 0
            if malicious_indicators:
                dynamic_risk_score += len(malicious_indicators) * 3
            if suspicious_indicators:
                dynamic_risk_score += len(suspicious_indicators) * 1
            if len(http_requests) > 10:
                dynamic_risk_score += 2

            dynamic_risk_score = min(dynamic_risk_score, 10)

            # Determine verdict
            if len(malicious_indicators) >= 3:
                verdict = 'MALICIOUS - Multiple suspicious behaviors detected'
            elif len(malicious_indicators) >= 1:
                verdict = 'SUSPICIOUS - Malicious indicators detected'
            elif len(suspicious_indicators) >= 5:
                verdict = 'SUSPICIOUS - Multiple suspicious behaviors'
            else:
                verdict = 'CLEAN - No significant malicious behavior'

            return {
                'available': True,
                'extension_id': extension_id,
                'task_id': info.get('id'),
                'verdict': verdict,
                'dynamic_risk_score': dynamic_risk_score,
                'malicious_indicators': malicious_indicators[:10],  # Top 10
                'suspicious_indicators': suspicious_indicators[:10],
                'network_activity': {
                    'http_requests': [
                        {'url': req.get('uri', ''), 'method': req.get('method', 'GET')}
                        for req in http_requests[:20]
                    ],
                    'dns_queries': [req.get('request', '') for req in dns_requests[:20]],
                    'tcp_connections': [
                        {'host': conn.get('dst', ''), 'port': conn.get('dport', 0)}
                        for conn in tcp_connections[:20]
                    ]
                },
                'file_activity': file_activity[:20],
                'registry_activity': registry_activity[:20],
                'processes': processes[:10],
                'cuckoo_report_url': f"{self.api_url}/analysis/{info.get('id')}/summary"
            }

        except Exception as e:
            print(f"[!] Error parsing Cuckoo report: {e}")
            return {
                'available': False,
                'error': f'Report parsing error: {str(e)}'
            }


def test_cuckoo_integration():
    """Test Cuckoo Sandbox integration"""
    print("=" * 80)
    print("CUCKOO SANDBOX INTEGRATION TEST")
    print("=" * 80)

    # Initialize client
    cuckoo = CuckooSandbox()

    if not cuckoo.enabled:
        print("\n[!] Cuckoo Sandbox not configured.")
        print("\nTo enable Cuckoo integration:")
        print("1. Install Cuckoo Sandbox: https://cuckoo.sh/")
        print("2. Start Cuckoo REST API: cuckoo api")
        print("3. Add to config.json:")
        print("""
{
    "cuckoo": {
        "api_url": "http://localhost:8090",
        "api_key": "your_api_key_if_auth_enabled"
    }
}
""")
        return

    # Test connection
    print(f"\n[+] Testing connection to {cuckoo.api_url}...")

    try:
        response = requests.get(f"{cuckoo.api_url}/cuckoo/status", timeout=5)
        if response.status_code == 200:
            print("[OK] Cuckoo API is reachable")
            status = response.json()
            print(f"    Version: {status.get('version', 'Unknown')}")
            print(f"    Tasks: {status.get('tasks', {})}")
        else:
            print(f"[!] API returned status {response.status_code}")
    except Exception as e:
        print(f"[!] Connection failed: {e}")


if __name__ == "__main__":
    test_cuckoo_integration()
