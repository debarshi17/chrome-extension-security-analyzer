# Cuckoo Sandbox Setup Guide

## Overview

Cuckoo Sandbox provides **real dynamic analysis** by executing Chrome extensions in an isolated virtual machine and monitoring their behavior.

**What Cuckoo Actually Does:**
- Runs extension in isolated VM (Windows/Linux)
- Monitors network traffic (HTTP, DNS, TCP connections)
- Tracks file operations (read, write, delete)
- Records registry modifications (Windows)
- Logs process creation and API calls
- Generates behavioral signatures

---

## Quick Start (Recommended: Docker)

### Option 1: Docker Setup (Easiest)

**Prerequisites:**
- Docker Desktop installed
- 8GB+ RAM available
- 20GB+ disk space

**1. Create docker-compose.yml:**
```yaml
version: '3.8'

services:
  cuckoo:
    image: blacktop/cuckoo:latest
    container_name: cuckoo-sandbox
    ports:
      - "8090:8090"  # REST API
      - "8000:8000"  # Web UI
    volumes:
      - cuckoo-data:/cuckoo
      - ./downloads:/cuckoo/storage/analyses
    environment:
      - CUCKOO_MEMORY=4096
      - CUCKOO_MACHINERY=virtualbox
    restart: unless-stopped
    networks:
      - cuckoo-net

  cuckoo-web:
    image: blacktop/cuckoo:latest
    container_name: cuckoo-web
    command: web
    ports:
      - "8080:8080"
    depends_on:
      - cuckoo
    networks:
      - cuckoo-net

volumes:
  cuckoo-data:

networks:
  cuckoo-net:
    driver: bridge
```

**2. Start Cuckoo:**
```bash
docker-compose up -d
```

**3. Verify it's running:**
```bash
# Check API
curl http://localhost:8090/cuckoo/status

# Access Web UI
# Open http://localhost:8000 in browser
```

**4. Test with the analyzer:**
```bash
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

Look for:
```
[CUCKOO] STEP 5.5: Dynamic analysis (Cuckoo Sandbox)...
[CUCKOO] Task submitted. Task ID: 1
[CUCKOO] Waiting for analysis to complete...
[+] Dynamic analysis complete: MALICIOUS - Multiple suspicious behaviors detected
```

---

## Option 2: Manual Installation (Advanced)

### For Ubuntu/Debian:

**1. Install Dependencies:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-dev \
    libffi-dev libssl-dev libjpeg-dev zlib1g-dev \
    mongodb postgresql tcpdump apparmor-utils \
    virtualbox
```

**2. Install Cuckoo:**
```bash
# Create virtual environment
python3 -m venv cuckoo-env
source cuckoo-env/bin/activate

# Install Cuckoo
pip install cuckoo

# Initialize Cuckoo
cuckoo init
```

**3. Configure Cuckoo:**
```bash
cd ~/.cuckoo/conf

# Edit cuckoo.conf
cat > cuckoo.conf << EOF
[cuckoo]
version_check = yes
machinery = virtualbox
memory_dump = no

[resultserver]
ip = 192.168.56.1
port = 2042
EOF

# Edit virtualbox.conf (if using VirtualBox)
cat > virtualbox.conf << EOF
[virtualbox]
mode = headless
machines = cuckoo1

[cuckoo1]
label = cuckoo1
platform = windows
ip = 192.168.56.101
EOF
```

**4. Set up Virtual Machine:**
```bash
# Download Windows 10 VM
# https://developer.microsoft.com/en-us/windows/downloads/virtual-machines/

# Import to VirtualBox
VBoxManage import Win10_Dev.ova

# Configure network (Host-Only Adapter)
VBoxManage hostonlyif create
VBoxManage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1

# Take VM snapshot
VBoxManage snapshot cuckoo1 take clean_snapshot
```

**5. Start Cuckoo:**
```bash
# Terminal 1: Start Cuckoo daemon
cuckoo

# Terminal 2: Start REST API
cuckoo api --host 0.0.0.0 --port 8090

# Terminal 3: Start Web UI (optional)
cuckoo web --host 0.0.0.0 --port 8000
```

---

### For Windows:

**Not Recommended:** Cuckoo is designed for Linux. Use Docker or WSL2.

**Using WSL2:**
```bash
# Install WSL2
wsl --install -d Ubuntu-22.04

# Inside WSL, follow Ubuntu installation steps above
```

---

## Configuration

### Update config.json

Already configured! Check [config.json](config.json):

```json
{
  "cuckoo": {
    "api_url": "http://localhost:8090",
    "api_key": null,
    "enabled": true,
    "timeout": 300,
    "package": "chrome"
  }
}
```

**Parameters:**
- `api_url`: Cuckoo REST API endpoint
- `api_key`: Optional API key (if authentication enabled)
- `enabled`: Set to `true` to enable dynamic analysis
- `timeout`: Max analysis time in seconds (5 minutes default)
- `package`: Analysis package (`chrome` for extensions)

---

## Testing Cuckoo Integration

### 1. Test Cuckoo Connection:
```bash
python src/cuckoo_sandbox.py
```

Expected output:
```
================================================================================
CUCKOO SANDBOX INTEGRATION TEST
================================================================================

[+] Testing connection to http://localhost:8090...
[OK] Cuckoo API is reachable
    Version: 2.0.7
    Tasks: {'pending': 0, 'running': 0, 'completed': 5}
```

### 2. Test Full Analysis:
```bash
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

**What happens:**
1. Extension downloaded and unpacked
2. Static analysis completed
3. **Extension submitted to Cuckoo Sandbox**
4. Cuckoo runs extension in isolated VM
5. Behavioral analysis performed:
   - Network requests monitored
   - File operations logged
   - Registry changes tracked
   - Suspicious behaviors flagged
6. Report enhanced with dynamic findings

**Example Output:**
```
[CUCKOO] STEP 5.5: Dynamic analysis (Cuckoo Sandbox)...
--------------------------------------------------------------------------------
[CUCKOO] Creating submission package...
[CUCKOO] Submitting pdadlkbckhinonakkfkdaadceojbekep_sandbox.zip for analysis...
[CUCKOO] Task submitted. Task ID: 42
[CUCKOO] Waiting for analysis to complete (timeout: 300s)...
[CUCKOO] Analysis in progress... (status: running)
[CUCKOO] Analysis in progress... (status: running)
[+] Dynamic analysis complete: SUSPICIOUS - Malicious indicators detected
    Risk Score: 7/10

[!] 3 malicious behavior(s) detected:
    • Network communication to suspicious domain
    • Attempts to exfiltrate data
    • Suspicious API calls detected
```

---

## What Cuckoo Detects

### Network Activity:
- **HTTP Requests**: All outbound HTTP/HTTPS traffic
- **DNS Queries**: Domain name resolutions
- **TCP Connections**: Raw socket connections
- **WebSocket Connections**: Real-time C2 communication

**Example from ZoomStealer:**
```json
"network_activity": {
  "http_requests": [
    {
      "url": "https://us-central1-webinarstvus.cloudfunctions.net/webinarJSON",
      "method": "POST"
    }
  ],
  "dns_queries": [
    "meetingtv.us",
    "webinartv.us"
  ]
}
```

### File Operations:
- Files created/modified/deleted
- Paths accessed
- Persistence mechanisms

**Example:**
```json
"file_activity": [
  {
    "operation": "file_write",
    "path": "C:\\Users\\Admin\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\storage.json"
  }
]
```

### Registry Modifications (Windows):
- Auto-start entries
- System configuration changes
- Browser settings manipulation

### Process Activity:
- New processes spawned
- Command-line arguments
- Parent-child process relationships

---

## Behavioral Signatures

Cuckoo uses **signatures** to detect malicious behaviors:

### Example Signatures for ZoomStealer:
1. **`network_http_suspicious`**: HTTP requests to known malicious domains
2. **`exfiltration_chromium_cookies`**: Chrome cookie theft
3. **`persistence_registry_run`**: Auto-start via registry
4. **`network_websocket_c2`**: WebSocket C2 communication
5. **`data_collection_zoom_credentials`**: Zoom meeting data theft

---

## Troubleshooting

### Cuckoo Not Starting:
```bash
# Check logs
tail -f ~/.cuckoo/log/cuckoo.log

# Check if VM is reachable
ping 192.168.56.101

# Verify VirtualBox is running
VBoxManage list runningvms
```

### API Connection Failed:
```bash
# Check if API is running
curl http://localhost:8090/cuckoo/status

# Check firewall
sudo ufw allow 8090/tcp

# Restart Cuckoo API
pkill cuckoo
cuckoo api --host 0.0.0.0 --port 8090
```

### Analysis Timeout:
- Increase timeout in config.json: `"timeout": 600` (10 minutes)
- Check VM performance (allocate more RAM)
- Verify VM snapshot is clean

### VM Not Responding:
```bash
# Reset VM to clean snapshot
VBoxManage snapshot cuckoo1 restore clean_snapshot

# Restart VM
VBoxManage startvm cuckoo1 --type headless
```

---

## Performance Optimization

### Resource Allocation:
- **Minimum**: 4GB RAM, 2 CPU cores
- **Recommended**: 8GB RAM, 4 CPU cores
- **Optimal**: 16GB RAM, 8 CPU cores

### Analysis Speed:
- **Per extension**: 5-10 minutes
- **Parallel analysis**: Configure multiple VMs
- **Batch processing**: Queue multiple tasks

### Multiple VMs:
Edit `~/.cuckoo/conf/virtualbox.conf`:
```ini
[virtualbox]
machines = cuckoo1, cuckoo2, cuckoo3

[cuckoo1]
label = cuckoo1
platform = windows
ip = 192.168.56.101

[cuckoo2]
label = cuckoo2
platform = windows
ip = 192.168.56.102

[cuckoo3]
label = cuckoo3
platform = windows
ip = 192.168.56.103
```

---

## Security Considerations

### Isolation:
- ✅ Cuckoo VMs are **fully isolated**
- ✅ No internet access by default (monitored)
- ✅ Network traffic captured but not forwarded
- ✅ VMs reset to clean snapshot after each analysis

### Network Safety:
- Use **host-only networking** (no external connectivity)
- Enable **INetSim** to simulate internet services
- Monitor but don't allow actual C2 communication

### Data Protection:
- Sensitive data (credentials, API keys) NOT in VMs
- VMs are disposable (reset after each analysis)
- Analysis results stored separately

---

## Advanced Configuration

### Custom Analysis Packages:

Create `~/.cuckoo/analyzer/chrome_extension/`:
```python
# chrome_extension.py
from lib.core.packages import Package

class ChromeExtension(Package):
    """Analyze Chrome extensions"""

    def start(self, path):
        # Install extension
        self.execute("chrome.exe", f"--load-extension={path}")
        return True
```

### Enable Full Memory Dumps:
```bash
# Edit cuckoo.conf
[cuckoo]
memory_dump = yes
```

### Custom Signatures:
Create `~/.cuckoo/signatures/zoom_stealer.py`:
```python
from lib.cuckoo.common.abstracts import Signature

class ZoomStealerIndicator(Signature):
    name = "zoom_stealer"
    description = "Detects ZoomStealer malware indicators"
    severity = 5

    def run(self):
        indicators = [
            "webinarstvus.cloudfunctions.net",
            "meetingtv.us",
            "zoom credential theft"
        ]

        for indicator in indicators:
            if self.check_file(pattern=indicator):
                return True
        return False
```

---

## Status

**Configuration Status:** ✅ CONFIGURED

**Next Steps:**
1. Install Cuckoo (Docker recommended)
2. Start Cuckoo services
3. Run test analysis: `python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep`
4. Check report for dynamic analysis section

**Support:**
- Official Docs: https://cuckoo.sh/docs/
- Community: https://github.com/cuckoosandbox/cuckoo
- Issues: Report in this repo's Issues tab
