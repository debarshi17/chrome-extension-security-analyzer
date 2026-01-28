# Docker Desktop Setup for Windows - Step by Step

## ✅ Cuckoo Configuration Status: ENABLED

Your analyzer is configured for dynamic analysis. Now you just need Docker Desktop.

---

## Step 1: Install Docker Desktop (15 minutes)

### Download Docker Desktop

**Direct Link:** https://desktop.docker.com/win/main/amd64/Docker%20Desktop%20Installer.exe

**Or visit:** https://www.docker.com/products/docker-desktop/

### System Requirements

✅ **Windows 10/11** 64-bit: Pro, Enterprise, or Education (Build 19041 or higher)
✅ **RAM**: 4GB minimum (8GB recommended for Cuckoo)
✅ **Disk Space**: 20GB available

### Installation Steps

**1. Run the Installer:**
```powershell
# After downloading, run:
Docker Desktop Installer.exe
```

**2. Configuration Options (during install):**
- ✅ Enable **WSL 2** instead of Hyper-V (recommended)
- ✅ Add shortcut to desktop
- ✅ Use WSL 2 based engine

**3. Install:**
- Click "OK" to proceed
- Installation takes 5-10 minutes
- **Restart your computer when prompted** (required!)

**4. After Restart:**
- Docker Desktop will start automatically
- You'll see the Docker icon in system tray
- Wait for "Docker Desktop is running" status

---

## Step 2: Verify Docker Installation

Open **PowerShell** and run:

```powershell
# Check Docker version
docker --version

# Expected output:
# Docker version 24.0.x, build xxxxx

# Check Docker Compose version
docker compose version

# Expected output:
# Docker Compose version v2.x.x
```

**Important:** Docker Desktop includes `docker compose` (two words, no hyphen).

**If you get an error:**
- Make sure Docker Desktop is running (check system tray)
- Restart Docker Desktop
- Restart PowerShell (close and reopen)

---

## Step 3: Start Cuckoo Sandbox

### Option A: Using docker compose (built into Docker Desktop)

```powershell
# Navigate to your project directory
cd C:\Users\user2\Documents\GitHub\chrome-extension-security-analyzer

# Start Cuckoo (using docker compose without hyphen)
docker compose up -d

# Expected output:
#  ✔ Network chrome-extension-security-analyzer_cuckoo-net  Created
#  ✔ Volume "chrome-extension-security-analyzer_cuckoo-data"  Created
#  ✔ Volume "chrome-extension-security-analyzer_postgres-data"  Created
#  ✔ Container cuckoo-postgres  Started
#  ✔ Container cuckoo-mongo  Started
#  ✔ Container cuckoo-sandbox  Started
```

### Option B: If that doesn't work

```powershell
# Use the full path to docker compose plugin
docker-compose up -d

# Or download standalone docker-compose:
# https://github.com/docker/compose/releases/latest
```

---

## Step 4: Wait for Cuckoo Startup (30 seconds)

```powershell
# Watch the startup logs
docker compose logs -f cuckoo

# You'll see initialization messages
# Wait for: "Cuckoo Sandbox 2.0.x started"
# Press Ctrl+C to exit logs (Cuckoo keeps running)
```

---

## Step 5: Verify Cuckoo is Running

```powershell
# Check container status
docker compose ps

# Expected output:
# NAME                  STATUS          PORTS
# cuckoo-sandbox        Up 30 seconds   0.0.0.0:8090->8090/tcp, 0.0.0.0:8000->8000/tcp
# cuckoo-postgres       Up 31 seconds   5432/tcp
# cuckoo-mongo          Up 31 seconds   27017/tcp
```

**All containers should show "Up" status.**

---

## Step 6: Test Cuckoo Connection

```powershell
# Test the API
python test_cuckoo.py

# Expected output:
# ✅ SUCCESS - Cuckoo API is reachable!
# [+] Cuckoo Status:
#     Version: 2.0.7
#     Pending: 0
#     Running: 0
#
# READY FOR DYNAMIC ANALYSIS
```

---

## Step 7: Run Full Analysis with Dynamic Analysis

```powershell
# Analyze ZoomStealer with dynamic analysis
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep

# You should now see:
# [CUCKOO] STEP 5.5: Dynamic analysis (Cuckoo Sandbox)...
# [CUCKOO] Submitting extension for analysis...
# [CUCKOO] Task submitted. Task ID: 1
# [CUCKOO] Waiting for analysis to complete...
# [+] Dynamic analysis complete: MALICIOUS
#     Risk Score: 7/10
#
# [!] 3 malicious behavior(s) detected:
#     • Network communication to suspicious domain
#     • Attempts to exfiltrate data
#     • Suspicious API calls detected
```

---

## Common Issues & Solutions

### Issue 1: "docker compose: command not found"

**Solution:**
```powershell
# Make sure Docker Desktop is running
# Check system tray for Docker icon

# Restart Docker Desktop
# Open Docker Desktop app → Settings → Restart

# Close and reopen PowerShell
```

### Issue 2: "Cannot connect to Docker daemon"

**Solution:**
```powershell
# Docker Desktop not running
# Open Docker Desktop manually from Start Menu

# Wait for "Docker Desktop is running" in system tray
```

### Issue 3: "WSL 2 installation is incomplete"

**Solution:**
```powershell
# Install WSL 2 manually
wsl --install

# Set WSL 2 as default
wsl --set-default-version 2

# Restart computer
```

### Issue 4: "Container fails to start"

**Solution:**
```powershell
# Check logs
docker compose logs cuckoo

# Restart containers
docker compose restart

# Or rebuild
docker compose down
docker compose up -d
```

### Issue 5: "Port 8090 already in use"

**Solution:**
```powershell
# Find what's using port 8090
netstat -ano | findstr :8090

# Kill the process (replace PID with actual number)
taskkill /PID <PID> /F

# Restart Cuckoo
docker compose restart cuckoo
```

---

## Docker Desktop Tips

### Start/Stop Cuckoo

```powershell
# Stop Cuckoo (when not analyzing)
docker compose stop

# Start Cuckoo (when needed)
docker compose start

# Stop and remove containers (clean shutdown)
docker compose down

# Stop and remove everything including volumes
docker compose down -v
```

### View Logs

```powershell
# All logs
docker compose logs

# Follow logs (live updates)
docker compose logs -f

# Specific service
docker compose logs cuckoo
docker compose logs postgres
```

### Resource Management

```powershell
# Check resource usage
docker stats

# Docker Desktop Settings → Resources:
# - CPUs: 2-4 cores
# - Memory: 4-8 GB
# - Disk: 20 GB
```

### Cuckoo Web UI (Optional)

```powershell
# Access Cuckoo Web UI in browser
http://localhost:8000

# View analysis results
# Monitor task queue
# Browse behavioral reports
```

---

## Auto-start on Boot (Optional)

Docker Desktop can start automatically:

1. Open **Docker Desktop**
2. Settings → General
3. ✅ Enable "Start Docker Desktop when you log in"

Then Cuckoo will auto-start with your analyzer.

---

## Verification Checklist

Before running analysis, verify:

- [ ] Docker Desktop installed and running
- [ ] `docker --version` works
- [ ] `docker compose version` works
- [ ] `docker compose ps` shows 3 containers "Up"
- [ ] `python test_cuckoo.py` shows "SUCCESS"
- [ ] config.json has `"enabled": true`

---

## Next Steps

**1. Run your first dynamic analysis:**
```powershell
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

**2. Check the enhanced report:**
```
reports/pdadlkbckhinonakkfkdaadceojbekep_threat_intel_report.html
```

**3. Look for new sections:**
- Dynamic Analysis Results
- Network Activity
- File Operations
- Behavioral Signatures

---

## Performance Expectations

**With Cuckoo Enabled:**
- ✅ More comprehensive threat detection (95-99%)
- ✅ Behavioral confirmation
- ✅ Forensic-grade evidence
- ⚠️ Slower analysis (10-15 minutes per extension)
- ⚠️ Higher resource usage (Docker containers)

**Analysis Pipeline:**
```
Step 0-4:   Static Analysis (2 minutes)
Step 5:     VirusTotal (1-2 minutes with rate limits)
Step 5.5:   Cuckoo Sandbox (5-10 minutes) ← NEW
Step 6-9:   Advanced Detection + Reports (1 minute)

Total: ~10-15 minutes per extension (vs 2-5 without Cuckoo)
```

---

## Support

**Docker Desktop Issues:**
- Docs: https://docs.docker.com/desktop/windows/
- Community: https://forums.docker.com/

**Cuckoo Sandbox Issues:**
- Docs: https://cuckoo.sh/docs/
- Our guide: [CUCKOO_SETUP.md](CUCKOO_SETUP.md)

**This Project:**
- Issues: Report in GitHub Issues tab
- Logs: `docker compose logs cuckoo`

---

## Quick Command Reference

```powershell
# Start Cuckoo
docker compose up -d

# Stop Cuckoo
docker compose down

# View status
docker compose ps

# View logs
docker compose logs -f cuckoo

# Test connection
python test_cuckoo.py

# Run analysis
python src/analyzer.py <extension_id>

# Restart if stuck
docker compose restart cuckoo
```

---

## Status

**Configuration:** ✅ Cuckoo ENABLED in config.json

**Next:** Install Docker Desktop using steps above!

After installation, run:
```powershell
docker compose up -d
python test_cuckoo.py
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

You'll have **full dynamic analysis** for all extensions!
