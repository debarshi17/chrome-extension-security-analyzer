# Quick Start Guide

## Basic Setup (Static Analysis Only)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure VirusTotal API
Edit `config.json`:
```json
{
  "virustotal": {
    "api_key": "your_api_key_here",
    "enabled": true
  }
}
```

Get your free API key: https://www.virustotal.com/gui/join-us

### 3. Run Analysis
```bash
# Analyze ZoomStealer malware
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep

# Analyze any extension (get ID from Chrome Web Store URL)
python src/analyzer.py <extension_id>
```

### 4. View Reports
Open the HTML report in your browser:
```
reports/<extension_id>_threat_intel_report.html
```

---

## Advanced Setup (With Dynamic Analysis)

### Enable Cuckoo Sandbox

Cuckoo provides **real dynamic analysis** by running extensions in isolated VMs.

### Quick Docker Setup (5 minutes)

**1. Install Docker Desktop:**
- Windows: https://www.docker.com/products/docker-desktop/
- Mac: https://www.docker.com/products/docker-desktop/
- Linux: `sudo apt-get install docker-compose`

**2. Start Cuckoo:**
```bash
docker-compose up -d
```

**3. Wait for startup (30 seconds):**
```bash
# Check status
docker-compose ps

# View logs
docker-compose logs -f cuckoo
```

**4. Test connection:**
```bash
python test_cuckoo.py
```

Expected output:
```
✅ SUCCESS - Cuckoo API is reachable!
[+] Cuckoo Status:
    Version: 2.0.7
    Pending: 0
    Running: 0

READY FOR DYNAMIC ANALYSIS
```

**5. Run analysis with dynamic analysis:**
```bash
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

Look for this section:
```
[CUCKOO] STEP 5.5: Dynamic analysis (Cuckoo Sandbox)...
[CUCKOO] Task submitted. Task ID: 1
[+] Dynamic analysis complete: MALICIOUS
```

---

## What Gets Analyzed

### Static Analysis (Always Enabled):
- ✅ Chrome Web Store metadata
- ✅ Extension download & unpacking
- ✅ **Host permissions** - which websites it can access
- ✅ JavaScript AST analysis - code structure
- ✅ Malicious pattern detection
- ✅ Domain intelligence (DGA, typosquatting, C2)
- ✅ VirusTotal reputation checks
- ✅ **Threat campaign attribution** (DarkSpectre, ZoomStealer, etc.)
- ✅ PII data classification
- ✅ IOC database cross-reference

### Dynamic Analysis (If Cuckoo Enabled):
- ✅ **Real execution in isolated VM**
- ✅ Network traffic monitoring (HTTP, DNS, WebSocket)
- ✅ File operations (read, write, delete)
- ✅ Registry modifications (Windows)
- ✅ Process creation tracking
- ✅ API call logging
- ✅ Behavioral signatures

---

## Configuration Reference

### config.json Structure
```json
{
  "virustotal": {
    "api_key": "your_key_here",
    "enabled": true
  },
  "analysis": {
    "max_domains_to_check": 50,
    "timeout_seconds": 30
  },
  "cuckoo": {
    "api_url": "http://localhost:8090",
    "api_key": null,
    "enabled": true,
    "timeout": 300,
    "package": "chrome"
  }
}
```

### Disable Cuckoo
If you don't want dynamic analysis:
```json
{
  "cuckoo": {
    "enabled": false
  }
}
```

The analyzer will gracefully skip Step 5.5 and continue with static analysis only.

---

## Example: Analyzing ZoomStealer

### Command:
```bash
python src/analyzer.py pdadlkbckhinonakkfkdaadceojbekep
```

### Expected Results:

**1. Extension Info:**
```
Extension: ZED: Zoom Easy Downloader
Version: 21.16
Manifest Version: 3
```

**2. Host Permissions Analysis:**
```
[PERMISSIONS] STEP 2.5: Analyzing host permissions...
[+] Permission Scope: ALL_WEBSITES
[+] Risk Assessment: CRITICAL
[!] CRITICAL: Extension has <all_urls> access
[!] Accesses 13 sensitive domain(s)
    • Video Conferencing: 8 domain(s)
    • Social Media: 5 domain(s)
```

**3. Domain Intelligence:**
```
[DOMAIN] STEP 4: Domain intelligence analysis...
[[OK]] No obviously malicious domains detected

Domain: us-central1-webinarstvus.cloudfunctions.net
  Classification: Legitimate Infrastructure (Google Cloud Functions)
  Note: Platform is legitimate, but endpoint is attacker-controlled
```

**4. VirusTotal Results:**
```
[VT] STEP 5: VirusTotal domain reputation check...
[VT] Summary: 1 malicious, 0 suspicious, 1 clean/unknown

[!] VIRUSTOTAL ALERT: 1 MALICIOUS domain(s) detected!
    [ALERT] meetingtv.us
       • Detections: 8 vendors
       • Flagged by: ArcSight, Certego, CyRadar
```

**5. Dynamic Analysis (if Cuckoo enabled):**
```
[CUCKOO] STEP 5.5: Dynamic analysis...
[CUCKOO] Task submitted. Task ID: 42
[+] Dynamic analysis complete: SUSPICIOUS
    Risk Score: 7/10

[!] 3 malicious behavior(s) detected:
    • Network communication to suspicious domain
    • Attempts to exfiltrate data
    • Suspicious API calls detected
```

**6. Threat Attribution:**
```
[ATTRIBUTION] STEP 8.5: Threat campaign attribution...
[+] Attribution: DarkSpectre / ZoomStealer
    Threat Actor: Chinese state-sponsored APT
    Confidence: HIGH
    Impact: 8.8 million users affected
```

**7. Final Verdict:**
```
================================================================================
VERDICT: CRITICAL THREAT - VIRUSTOTAL CONFIRMED MALICIOUS
   +- 1 domain(s) flagged as malicious by security vendors
   +- IMMEDIATE ACTION: Block this extension immediately
   +- Investigate data compromise on affected systems
================================================================================
```

---

## Report Sections

The HTML report includes:

1. **Executive Summary** - Risk score, verdict, key findings
2. **Malware Classification** - Attack vectors, techniques
3. **Host Permissions & Website Access** ✨ - Which sites it can access
4. **Domain Intelligence** - C2 servers, DGA detection
5. **VirusTotal Results** - Vendor detections
6. **Advanced Malware Detection** - CSP manipulation, DOM injection
7. **PII Classification** - Data collection
8. **Threat Campaign Attribution** ✨ - Campaign identification with sources
9. **Dynamic Analysis** - Behavioral findings (if Cuckoo enabled)
10. **Recommendations** - Remediation steps

---

## Common Issues

### "VirusTotal API key not found"
- Get free API key: https://www.virustotal.com/gui/join-us
- Add to config.json: `"api_key": "your_key_here"`

### "Cuckoo Sandbox not configured"
- Normal if you haven't set up Cuckoo
- Dynamic analysis is optional
- To enable: See [CUCKOO_SETUP.md](CUCKOO_SETUP.md)

### "Cannot connect to Cuckoo"
```bash
# Check if running
docker-compose ps

# View logs
docker-compose logs -f cuckoo

# Restart
docker-compose restart cuckoo
```

### "Extension download failed"
- Extension may be removed from Chrome Web Store
- Check extension ID is correct
- Try with different extension

---

## Testing with Benign Extensions

**uBlock Origin (should be CLEAN):**
```bash
python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm
```

Expected: Risk Score 0-2/10, MINIMAL or LOW risk

**Grammarly (should be LOW):**
```bash
python src/analyzer.py kbfnbcaeplbcioakkpcpgfkobkghlhen
```

Expected: Risk Score 1-3/10, LOW risk (uses cloud APIs legitimately)

---

## Next Steps

1. **Read Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md) - How the analyzer works
2. **Quality Improvements**: [QUALITY_IMPROVEMENTS.md](QUALITY_IMPROVEMENTS.md) - Edge cases and testing
3. **Cuckoo Setup**: [CUCKOO_SETUP.md](CUCKOO_SETUP.md) - Dynamic analysis setup
4. **Phase Documentation**: See `PHASE_*.md` files for development history

---

## Support

- **Issues**: Report bugs or feature requests in GitHub Issues
- **Cuckoo Help**: https://cuckoo.sh/docs/
- **VirusTotal API**: https://developers.virustotal.com/reference/overview

---

## Current Status

✅ **Static Analysis**: Fully operational
✅ **VirusTotal Integration**: Configured (API key required)
✅ **Host Permissions Analysis**: Working
✅ **Threat Attribution**: Working (pattern-based)
✅ **Cuckoo Sandbox**: Configured (Docker setup ready)

**Next**: Start Cuckoo with `docker-compose up -d` for dynamic analysis!
