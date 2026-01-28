# Chrome Extension Security Analyzer - Architecture & Flow

## Overview
Professional-grade threat intelligence platform for analyzing Chrome extensions with VirusTotal integration, dynamic analysis, and OSINT attribution.

---

## Complete Analysis Flow

When you run: `python src/analyzer.py <extension_id>`

### Step 0: Chrome Web Store Metadata
**File:** [src/store_metadata.py](src/store_metadata.py)
**Function:** `fetch_metadata(extension_id)`

**What it does:**
- Scrapes Chrome Web Store page for the extension
- Extracts metadata: name, author, user count, rating, last update
- Checks for Chrome policy warnings
- Identifies risk signals (low adoption, no privacy policy)

**Actually performs:** HTTP request to `https://chromewebstore.google.com/detail/{extension_id}`
- Uses BeautifulSoup to parse HTML
- NO API access (Chrome doesn't provide public API)

**Output:** Store metadata dict with name, author, ratings, etc.

---

### Step 1: Download Extension
**File:** [src/downloader.py](src/downloader.py)
**Function:** `download_extension(extension_id)`

**What it does:**
- Downloads the .crx file from Chrome Web Store
- Saves to `downloads/{extension_id}.crx`

**Actually performs:**
```python
# Real download URL
url = f"https://clients2.google.com/service/update2/crx?response=redirect&prodversion=49.0&acceptformat=crx3&x=id%3D{extension_id}%26installsource%3Dondemand%26uc"
```

**Output:** Path to downloaded .crx file

---

### Step 2: Unpack Extension
**File:** [src/unpacker.py](src/unpacker.py)
**Function:** `unpack(crx_path)`

**What it does:**
- Extracts .crx (ZIP archive) to `data/extensions/{extension_id}/`
- Parses manifest.json
- Counts files and structure

**Actually performs:**
```python
with zipfile.ZipFile(crx_path, 'r') as zip_ref:
    zip_ref.extractall(extract_path)
```

**Output:** Path to unpacked extension directory + manifest dict

---

### Step 2.5: Host Permissions Analysis ✨ NEW (Phase 9)
**File:** [src/host_permissions_analyzer.py](src/host_permissions_analyzer.py)
**Function:** `analyze_manifest(manifest_path)`

**What it does:**
- Deep analysis of which websites the extension can ACCESS
- Parses `host_permissions`, `content_scripts`, `web_accessible_resources`
- Categorizes access by sensitivity:
  - Banking & Financial
  - Social Media
  - Email Providers
  - Video Conferencing (Zoom, Teams, Meet, Webex)
  - Productivity Tools
  - Shopping
  - Healthcare & Government
- Detects `<all_urls>` access (CRITICAL risk)
- Calculates permission scope (ALL_WEBSITES, VERY_BROAD, BROAD, etc.)
- Risk assessment per domain

**Important Distinction:**
- **Host Permissions** = Sites the extension CAN READ/MODIFY (e.g., zoom.us, twitter.com)
- **External Domains** = C2 servers the extension CONTACTS (analyzed in Step 4)

**Actually performs:**
```python
# Reads manifest.json
manifest = json.load(manifest_path)

# Extracts permissions
host_perms = manifest.get('host_permissions', [])
content_scripts = manifest.get('content_scripts', [])

# Categorizes each domain
for pattern in host_perms:
    domain = extract_domain(pattern)
    if domain in SENSITIVE_CATEGORIES['banking']:
        # Mark as banking access
    elif domain in SENSITIVE_CATEGORIES['video_conferencing']:
        # Mark as video conferencing access
```

**Output:**
```json
{
  "permission_scope": "ALL_WEBSITES",
  "risk_assessment": {
    "overall_risk": "CRITICAL",
    "risk_score": 41
  },
  "all_urls_access": true,
  "sensitive_access": {
    "video_conferencing": {
      "domains": ["zoom.us", "teams.microsoft.com"],
      "risk": "HIGH"
    }
  }
}
```

---

### Step 3: Static Analysis
**File:** [src/static_analyzer.py](src/static_analyzer.py)
**Function:** `analyze_extension(extension_dir)`

**What it does:**
- Scans all JavaScript files
- **AST (Abstract Syntax Tree) analysis** of code structure
- Detects malicious patterns:
  - `chrome.tabs.executeScript` abuse
  - `eval()` usage
  - `chrome.cookies` access
  - `chrome.storage` manipulation
  - Settings overrides
  - Remote script loading
- Configuration extraction (API keys, endpoints)
- Obfuscation detection
- Risk scoring

**Actually performs:**
```python
import esprima  # JavaScript AST parser

# Parse each .js file
ast = esprima.parseScript(js_code)

# Walk AST nodes
for node in ast.body:
    if node.type == 'CallExpression':
        if 'eval' in node.callee:
            # FLAG: eval() detected
```

**Output:** Analysis results with risk score, patterns found, AST findings

---

### Step 4: Domain Intelligence Analysis
**File:** [src/domain_intelligence.py](src/domain_intelligence.py)
**Function:** `analyze_domain(domain, url)`

**What it does:**
- Analyzes EXTERNAL domains the extension CONTACTS (C2 servers)
- NOT the same as host permissions
- Checks for:
  - **DGA (Domain Generation Algorithm)** - randomized domains used by malware
  - **Typosquatting** - fake domains mimicking legitimate sites (google.com vs goog1e.com)
  - **C2 patterns** - command & control infrastructure indicators
  - **Suspicious TLDs** - .xyz, .top, .tk, etc.
  - **Newly Registered Domains** - common in malware campaigns

**Actually performs:**
```python
# 1. Entropy calculation (randomness)
entropy = -sum(p * log2(p) for p in char_frequency)
if entropy > 4.5:
    # Likely DGA-generated

# 2. Consonant/vowel ratio
consonant_ratio = consonants / total_letters
if consonant_ratio > 0.7:
    # Unpronounceable = suspicious

# 3. Levenshtein distance for typosquatting
distance = levenshtein('google', 'goog1e')
if distance <= 2:
    # Typosquatting detected
```

**Edge Cases (Currently Fixed):**
- ❌ **BEFORE:** `us-central1-webinarstvus.cloudfunctions.net` flagged as "newly registered"
- ✅ **AFTER:** Recognizes `*.cloudfunctions.net` as Google infrastructure

**Output:** Domain threat assessment with risk level, classification, indicators

---

### Step 5: VirusTotal Domain Reputation
**File:** [src/virustotal_checker.py](src/virustotal_checker.py)
**Function:** `check_multiple_domains(domains)`

**What it does:**
- Sends EXTERNAL domains (C2 servers) to VirusTotal API
- NOT host permissions (we don't check if zoom.us is malicious!)
- Checks domain reputation from 90+ security vendors
- Rate limiting (15s between requests to avoid API ban)
- False positive filtering (Firebase, jQuery CDN, etc.)

**Actually performs:**
```python
# Real VirusTotal API call
headers = {'x-apikey': VIRUSTOTAL_API_KEY}
url = f"https://www.virustotal.com/api/v3/domains/{domain}"
response = requests.get(url, headers=headers)

# Parse detections
detections = response.json()['data']['attributes']['last_analysis_stats']
malicious_count = detections['malicious']
```

**Rate Limits:** 4 requests/minute (free tier), 15s delay enforced

**Output:** VT results with vendor detections, threat level, community votes

---

### Step 5.5: Cuckoo Sandbox Dynamic Analysis
**File:** [src/cuckoo_sandbox.py](src/cuckoo_sandbox.py)
**Function:** `submit_extension(extension_dir, extension_id)`

**What it does:**
- **ACTUAL sandboxing** via external Cuckoo Sandbox instance
- Submits .crx file to Cuckoo REST API
- Waits for analysis to complete
- Extracts behavioral indicators

**Is it REALLY sandboxing?**
- ✅ **YES** - if you have Cuckoo Sandbox installed and running
- ❌ **NO** - if not configured (gracefully skips)

**What Cuckoo Actually Does:**
1. Runs extension in isolated VM
2. Monitors:
   - Network traffic (HTTP, DNS, TCP connections)
   - File operations (read, write, delete)
   - Registry modifications (Windows)
   - Process creation
   - API calls
3. Generates behavioral report with signatures

**Setup Required:**
```bash
# Install Cuckoo (external tool)
pip install cuckoo
cuckoo init

# Start Cuckoo API server
cuckoo api

# Configure in config.json
{
  "cuckoo": {
    "api_url": "http://localhost:8090",
    "api_key": "optional"
  }
}
```

**Actually performs:**
```python
# Submit file
files = {'file': open('extension.crx', 'rb')}
response = requests.post(
    f"{cuckoo_api}/tasks/create/file",
    files=files,
    data={'package': 'chrome', 'timeout': 300}
)

# Poll for results
task_id = response.json()['task_id']
while True:
    status = requests.get(f"{cuckoo_api}/tasks/view/{task_id}")
    if status == 'reported':
        report = requests.get(f"{cuckoo_api}/tasks/report/{task_id}")
        break
```

**Output:** Dynamic analysis report with malicious behaviors, network activity, file ops

**Current Status:** Optional feature - works if Cuckoo is installed, otherwise skipped

---

### Step 6: Advanced Malware Detection
**File:** [src/advanced_detection.py](src/advanced_detection.py)
**Function:** `run_all_detections(extension_dir, dynamic_evidence)`

**What it does:**
- Advanced pattern detection for sophisticated malware techniques
- **CSP Manipulation** - removing Content Security Policy restrictions
- **DOM Event Injection** - remote code execution via DOM events (bypasses MV3)
- **WebSocket C2** - real-time command & control
- **Delayed Activation** - time bombs, install date checks
- **Code Obfuscation** - hex encoding, base64, unicode escapes

**Actually performs:**
```python
# Detect CSP removal
if 'declarativeNetRequest' in manifest:
    for rule in rules:
        if rule.action.type == 'modifyHeaders':
            if 'content-security-policy' in headers:
                # CRITICAL: CSP bypass detected

# Detect DOM event injection
js_code = read_file('content.js')
if 'addEventListener' in js_code and 'fetch(' in js_code:
    # Check if fetching remote code and executing
    if 'eval' in js_code or 'innerHTML' in js_code:
        # CRITICAL: Remote code execution
```

**Output:** Advanced findings with severity levels (CRITICAL, HIGH, MEDIUM)

---

### Step 7: PII Classification
**File:** [src/pii_classifier.py](src/pii_classifier.py)
**Function:** `classify_data_collection(extension_dir)`

**What it does:**
- Identifies what personal data the extension collects
- Classifies by sensitivity:
  - **High:** Credit cards, SSN, passwords
  - **Medium:** Email, phone, IP address
  - **Low:** Browser history, cookies
- Detects exfiltration endpoints

**Actually performs:**
```python
# Regex patterns for PII
patterns = {
    'credit_card': r'\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b',
    'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
}

# Scan for data collection
if 'chrome.cookies.getAll' in code:
    pii_types.append('cookies')
if 'chrome.history.search' in code:
    pii_types.append('browsing_history')
```

**Output:** PII types collected + risk assessment

---

### Step 8: IOC Database Update
**File:** [src/ioc_manager.py](src/ioc_manager.py)
**Function:** `add_extension_ioc(extension_data)`

**What it does:**
- Stores Indicators of Compromise (IOCs) in local database
- Tracks malicious domains across extensions
- Cross-references new extensions with known bad actors

**Actually performs:**
```python
# SQLite database
ioc_db = {
    'domains': [
        {'domain': 'meetingtv.us', 'first_seen': '2025-01-20', 'extensions': ['pdadlk...', 'abc123']},
    ],
    'extensions': [
        {'id': 'pdadlk...', 'name': 'ZoomStealer', 'risk': 'CRITICAL'},
    ]
}

# Check if domain seen before
if domain in ioc_db['domains']:
    print(f"[!] Domain {domain} previously flagged in {count} extensions")
```

**Output:** IOC database stats (total domains, extensions tracked)

---

### Step 8.5: Threat Campaign Attribution ✨ NEW (Phase 9)
**File:** [src/threat_attribution.py](src/threat_attribution.py)
**Function:** `search_threat_campaigns(extension_id, extension_name)`

**What it does:**
- **Pattern-based** campaign identification (not web scraping)
- Identifies known threat campaigns:
  - **DarkSpectre** - Chinese state-sponsored APT, 8.8M users
  - **ZoomStealer** - Video conferencing espionage
  - **CacheFlow** - Browser hijacking
  - **MagnetGoblin** - Credential theft
- Provides OSINT analysis with sources

**Actually performs:**
```python
# Pattern matching (reliable)
ext_name_lower = extension_name.lower()
if 'zoom' in ext_name_lower and 'download' in ext_name_lower:
    # Identified as ZoomStealer campaign
    return {
        'campaign_name': 'DarkSpectre / ZoomStealer',
        'threat_actor': 'DarkSpectre (Chinese state-sponsored APT)',
        'confidence': 'HIGH',
        'source_articles': [
            {'title': '...', 'url': 'https://thehackernews.com/...'},
            {'title': '...', 'url': 'https://bleepingcomputer.com/...'},
        ]
    }
```

**NOT web scraping** (Google blocks automated searches):
- Uses pre-loaded threat intelligence
- Pattern-based recognition
- Hardcoded known campaigns from security research

**Output:** Attribution with campaign name, actor, OSINT summary, source links

---

### Step 9: Generate Reports
**File:** [src/professional_report.py](src/professional_report.py)
**Function:** `generate_threat_intelligence_report(results)`

**What it does:**
- Generates professional HTML report
- Sections:
  1. Executive Summary
  2. Malware Classification
  3. **Host Permissions & Website Access** ✨ NEW
  4. Domain Intelligence
  5. VirusTotal Results
  6. Advanced Malware Detection
  7. PII Classification
  8. **Threat Campaign Attribution** ✨ NEW
  9. IOC Database
  10. Recommendations
- Color-coded risk levels
- Clickable references

**Actually performs:**
```python
# Generate HTML with Bootstrap styling
html = f"""
<div class="section">
    <h2>Host Permissions & Website Access</h2>
    <p>Permission Scope: {host_permissions['permission_scope']}</p>
    <p>Risk: {host_permissions['risk_assessment']['overall_risk']}</p>

    <h3>Sensitive Website Access</h3>
    <ul>
        <li>Video Conferencing: {', '.join(video_domains)}</li>
        <li>Social Media: {', '.join(social_domains)}</li>
    </ul>
</div>
"""
```

**Output:**
- `reports/{extension_id}_analysis.json` - Raw data
- `reports/{extension_id}_threat_intel_report.html` - Professional report

---

## Key Architectural Decisions

### 1. What IS Actually Sandboxed?
**Cuckoo Sandbox (Step 5.5):**
- ✅ Real sandboxing if Cuckoo installed
- ❌ Optional - gracefully skips if not configured
- Requires external setup (Cuckoo server)

**Everything else:**
- Static analysis (no execution)
- Domain lookups (VirusTotal API)
- Pattern matching (signatures)

### 2. Host Permissions vs External Domains
**Critical distinction:**
- **Host Permissions** (Step 2.5): Sites extension CAN ACCESS
  - Example: `https://*.zoom.us/*` = can read Zoom website
  - NOT sent to VirusTotal (we know zoom.us is legitimate)

- **External Domains** (Step 4-5): C2 servers extension CONTACTS
  - Example: `https://us-central1-webinarstvus.cloudfunctions.net/webinarJSON`
  - Sent to VirusTotal (this is the attacker's server)

### 3. Threat Attribution
**NOT web scraping** (unreliable):
- Pattern-based recognition
- Pre-loaded threat intelligence
- Hardcoded campaigns from security research

**Why no web search?**
- Google blocks automated searches
- BeautifulSoup parsing unreliable (HTML changes frequently)
- False negatives/positives from search results

---

## Edge Cases & Quality Issues

### 🐛 ISSUE 1: Cloud Provider CDNs Flagged as "Newly Registered"
**Problem:**
```
us-central1-webinarstvus.cloudfunctions.net
Risk: MEDIUM
Intelligence: "Possible newly registered domain"
```

**Root Cause:**
- `domain_intelligence.py` line 390-412: `_check_nrd_indicators()`
- Flags "complex subdomain structure" for domains with >3 parts
- `*.cloudfunctions.net` is Google's serverless platform (legitimate)

**Fix Needed:**
Add `cloudfunctions.net` to legitimate infrastructure list

### 🐛 ISSUE 2: Other Cloud Providers Missing
**Missing from whitelist:**
- `*.cloudfunctions.net` (Google Cloud Functions)
- `*.run.app` (Google Cloud Run)
- `*.firebase.io` (Firebase Realtime Database)
- `*.firebaseio.com` (Firebase)
- `*.appspot.com` (Google App Engine)
- `*.azurewebsites.net` (Azure - already listed)
- `*.herokuapp.com` (Heroku)
- `*.vercel.app` (Vercel)
- `*.netlify.app` (Netlify)

### 🐛 ISSUE 3: VirusTotal Domain Count Mismatch
**Problem:** User reported "Checking 7 domains" but extension only contacts 3

**Likely cause:**
- Mixing host permissions with external domains
- Need to verify domain extraction in static analyzer

---

## Summary

**Total Pipeline Steps:** 10 (0-9)
**Actual Analysis Time:** 2-5 minutes (depending on VT rate limits)
**External Dependencies:**
- VirusTotal API (required for domain checks)
- Cuckoo Sandbox (optional for dynamic analysis)
- BeautifulSoup (Chrome Web Store scraping)

**Output:**
- JSON report (technical)
- HTML report (professional, for clients)
- IOC database (cumulative)
