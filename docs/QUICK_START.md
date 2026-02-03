# Quick Start Guide

## Basic Setup (Static Analysis Only)

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Configure VirusTotal API
Copy the template and add your key:
```bash
cp config.json.template config.json
```

Edit `config.json`:
```json
{
  "virustotal": {
    "api_key": "your_api_key_here",
    "rate_limit_delay": 15
  }
}
```

Get your free API key: https://www.virustotal.com/gui/join-us

### 3. Run Analysis
```bash
# Analyze any extension (get ID from Chrome Web Store URL)
python src/analyzer.py <extension_id>

# Fast mode (skips VirusTotal API calls)
python src/analyzer.py <extension_id> --fast
```

### 4. View Reports
Open the HTML report in your browser:
```
reports/<extension_id>_threat_intel_report.html
```

---

## Advanced Setup (With Dynamic Network Capture)

### Enable Playwright Dynamic Analysis

Dynamic analysis launches a real Chromium browser with the extension loaded and captures all network traffic via Chrome DevTools Protocol (CDP).

### Setup

**1. Install Playwright:**
```bash
pip install playwright
playwright install chromium
```

**2. Run analysis with dynamic capture:**
```bash
python src/analyzer.py <extension_id> --dynamic
```

**3. Custom timeout (default 30 seconds):**
```bash
python src/analyzer.py <extension_id> --dynamic --dynamic-timeout 45
```

**What dynamic analysis captures:**
- All HTTP/HTTPS requests made by the extension
- WebSocket connections and frame data
- POST data payloads (potential exfiltration)
- Beaconing patterns (repeated calls to same endpoint)
- Post-navigation exfiltration (data sent after page loads)

---

## What Gets Analyzed

### Static Analysis (Always Enabled):
- Chrome Web Store metadata
- Extension download & unpacking
- **Host permissions** - which websites it can access
- JavaScript AST analysis - code structure
- Malicious pattern detection (70+ patterns)
- Domain intelligence (DGA, typosquatting, C2)
- VirusTotal reputation checks
- **Threat campaign attribution** (DarkSpectre, ZoomStealer, etc.)
- PII data classification
- IOC database cross-reference
- False positive filtering (benign libraries suppressed)

### Dynamic Analysis (With `--dynamic` flag):
- **Real browser execution** with extension loaded
- Network traffic monitoring (HTTP, HTTPS, WebSocket)
- Extension-initiated request identification
- Suspicious connection scoring
- Beaconing detection
- Post-navigation exfiltration detection
- WebSocket C2 channel detection

---

## Configuration Reference

### config.json Structure
```json
{
  "virustotal": {
    "api_key": "your_key_here",
    "rate_limit_delay": 15
  },
  "google_custom_search": {
    "api_key": null,
    "cx_id": null,
    "enabled": false
  }
}
```

VirusTotal is the only required external service. Dynamic analysis uses Playwright locally (no external API needed).

---

## Example Output

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
       Detections: 8 vendors
       Flagged by: ArcSight, Certego, CyRadar
```

**5. Threat Attribution:**
```
[ATTRIBUTION] STEP 8.5: Threat campaign attribution...
[+] Attribution: DarkSpectre / ZoomStealer
    Threat Actor: Chinese state-sponsored APT
    Confidence: HIGH
    Impact: 8.8 million users affected
```

**6. Final Verdict:**
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
3. **Host Permissions & Website Access** - Which sites it can access
4. **Domain Intelligence** - C2 servers, DGA detection
5. **VirusTotal Results** - Vendor detections
6. **Advanced Malware Detection** - CSP manipulation, DOM injection
7. **PII Classification** - Data collection
8. **Threat Campaign Attribution** - Campaign identification with sources
9. **Dynamic Network Analysis** - Traffic capture findings (if `--dynamic` used)
10. **Recommendations** - Remediation steps

---

## Common Issues

### "VirusTotal API key not found"
- Get free API key: https://www.virustotal.com/gui/join-us
- Copy template: `cp config.json.template config.json`
- Add your key to `config.json`

### "Playwright not installed" (when using --dynamic)
```bash
pip install playwright
playwright install chromium
```

### "Extension download failed"
- Extension may be removed from Chrome Web Store
- Check extension ID is correct
- Try with a different extension

---

## Testing with Benign Extensions

**uBlock Origin (should be LOW risk):**
```bash
python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm --fast
```

Expected: Risk Score 2-3/10, LOW risk

---

## Next Steps

1. **Read Architecture**: [ARCHITECTURE.md](ARCHITECTURE.md) - How the analyzer works
2. **VirusTotal API**: https://developers.virustotal.com/reference/overview

---

## Current Status

- **Static Analysis**: Fully operational
- **VirusTotal Integration**: Configured (API key required)
- **Host Permissions Analysis**: Working
- **Threat Attribution**: Working (pattern-based + OSINT)
- **Dynamic Network Capture**: Working (requires Playwright)
- **False Positive Filtering**: Working (benign library suppression)
