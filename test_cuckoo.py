#!/usr/bin/env python3
"""
Quick test script to verify Cuckoo Sandbox integration
"""

import sys
import json
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / 'src'))

from cuckoo_sandbox import CuckooSandbox
import requests


def test_cuckoo_connection():
    """Test Cuckoo Sandbox connection"""
    print("=" * 80)
    print("CUCKOO SANDBOX CONNECTION TEST")
    print("=" * 80)
    print()

    # Load config
    config_path = Path(__file__).parent / 'config.json'
    if not config_path.exists():
        print("[!] Error: config.json not found")
        print("    Run this script from the project root directory")
        return False

    with open(config_path, 'r') as f:
        config = json.load(f)

    cuckoo_config = config.get('cuckoo', {})
    api_url = cuckoo_config.get('api_url', 'http://localhost:8090')
    enabled = cuckoo_config.get('enabled', False)

    print(f"[i] Configuration:")
    print(f"    API URL: {api_url}")
    print(f"    Enabled: {enabled}")
    print()

    if not enabled:
        print("[!] Cuckoo is disabled in config.json")
        print("    Set cuckoo.enabled = true to enable dynamic analysis")
        return False

    # Test connection
    print(f"[+] Testing connection to {api_url}...")
    print()

    try:
        response = requests.get(f"{api_url}/cuckoo/status", timeout=5)

        if response.status_code == 200:
            print("[OK] SUCCESS - Cuckoo API is reachable!")
            print()

            status = response.json()
            print("[+] Cuckoo Status:")
            print(f"    Version: {status.get('version', 'Unknown')}")
            print(f"    Hostname: {status.get('hostname', 'Unknown')}")

            tasks = status.get('tasks', {})
            if tasks:
                print()
                print("[+] Task Queue:")
                print(f"    Pending: {tasks.get('pending', 0)}")
                print(f"    Running: {tasks.get('running', 0)}")
                print(f"    Completed: {tasks.get('completed', 0)}")
                print(f"    Total: {tasks.get('total', 0)}")

            machines = status.get('machines', {})
            if machines:
                print()
                print("[+] Analysis Machines:")
                print(f"    Available: {machines.get('available', 0)}")
                print(f"    Total: {machines.get('total', 0)}")

            print()
            print("=" * 80)
            print("READY FOR DYNAMIC ANALYSIS")
            print("=" * 80)
            print()
            print("Next steps:")
            print("  1. Run full analysis: python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep")
            print("  2. Look for 'STEP 5.5: Dynamic analysis' in output")
            print("  3. Check report for behavioral findings")
            print()

            return True

        else:
            print(f"❌ FAILED - API returned status {response.status_code}")
            print()
            print("Troubleshooting:")
            print("  1. Check if Cuckoo is running: docker-compose ps")
            print("  2. View logs: docker-compose logs -f cuckoo")
            print("  3. Restart: docker-compose restart cuckoo")
            return False

    except requests.exceptions.ConnectionError:
        print("❌ FAILED - Cannot connect to Cuckoo API")
        print()
        print("Cuckoo Sandbox is NOT running!")
        print()
        print("=" * 80)
        print("QUICK START GUIDE")
        print("=" * 80)
        print()
        print("Option 1: Docker (Recommended)")
        print("  1. Start Cuckoo: docker-compose up -d")
        print("  2. Wait 30 seconds for startup")
        print("  3. Run this test again: python test_cuckoo.py")
        print()
        print("Option 2: Manual Installation")
        print("  1. See CUCKOO_SETUP.md for detailed instructions")
        print("  2. Install Cuckoo: pip install cuckoo")
        print("  3. Initialize: cuckoo init")
        print("  4. Start API: cuckoo api --host 0.0.0.0 --port 8090")
        print()
        print("Option 3: Disable Dynamic Analysis")
        print("  1. Edit config.json")
        print("  2. Set cuckoo.enabled = false")
        print("  3. Analyzer will skip dynamic analysis (static analysis only)")
        print()
        return False

    except requests.exceptions.Timeout:
        print("❌ FAILED - Connection timeout")
        print()
        print("Cuckoo API is not responding. Check if service is healthy:")
        print("  docker-compose logs cuckoo")
        return False

    except Exception as e:
        print(f"❌ FAILED - Unexpected error: {e}")
        return False


def main():
    """Main entry point"""
    success = test_cuckoo_connection()
    sys.exit(0 if success else 1)


if __name__ == "__main__":
    main()
