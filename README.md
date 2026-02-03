# Chrome Extension Security Analyzer

A professional-grade static analysis tool for detecting malicious Chrome extensions. Performs deep code analysis, permission auditing, threat intelligence correlation, and generates incident response-ready reports.

## Features

- **Multi-stage Analysis Pipeline**: Downloads, unpacks, and analyzes extensions automatically
- **70+ Malicious Code Patterns**: Detects keyloggers, screen capture, data theft, C2 communication, and more
- **JavaScript AST Analysis**: Resolves config variables to extract exact data exfiltration destinations
- **VirusTotal Integration**: Checks all domains against 90+ security vendors with intelligent caching
- **Threat Campaign Attribution**: Cross-references extensions against known malware campaigns via OSINT
- **PII Classification**: Identifies what sensitive data is being accessed (credentials, cookies, financial data)
- **Advanced Malware Detection**: Detects CSP manipulation, DOM event injection, WebSocket C2, time bombs
- **Permission Risk Analysis**: Flags dangerous permission combinations with security implications
- **Dynamic Network Capture**: Playwright + CDP-based runtime traffic analysis with WebSocket detection
- **False Positive Suppression**: Filters benign libraries (jQuery, Firebase, React) to reduce noise
- **Professional HTML Reports**: Dark-themed threat intelligence reports with code evidence

## Installation

```bash
# Clone and install
git clone https://github.com/debarshi17/chrome-extension-security-analyzer.git
cd chrome-extension-security-analyzer
pip install -r requirements.txt

# Add your VirusTotal API key
cp config.json.template config.json
# Edit config.json with your key
```

Get a free VirusTotal API key at https://www.virustotal.com/gui/join-us

## Usage

```bash
# Analyze an extension by its ID
python src/analyzer.py <extension_id>

# Fast mode (skips VirusTotal API calls for offline/quick analysis)
python src/analyzer.py <extension_id> --fast

# Skip just VirusTotal
python src/analyzer.py <extension_id> --skip-vt

# Enable dynamic network capture (requires: pip install playwright && playwright install chromium)
python src/analyzer.py <extension_id> --dynamic

# Dynamic analysis with custom timeout (default 30s)
python src/analyzer.py <extension_id> --dynamic --dynamic-timeout 45
```

The extension ID is the 32-character string from the Chrome Web Store URL:
```
https://chrome.google.com/webstore/detail/extension-name/abcdefghijklmnopqrstuvwxyz123456
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

Reports are saved to the `reports/` folder.

## Detection Categories

### Credential & Financial Data Theft
| Pattern | Description |
|---------|-------------|
| Password Field Targeting | Detects scripts targeting `input[type=password]` |
| OTP/2FA Interception | Detects targeting of verification code inputs |
| Credit Card Field Targeting | Detects access to payment card fields |
| CSRF Token Extraction | Detects theft of anti-forgery tokens |
| Hidden Autofill Trigger | Detects invisible fields designed to harvest autofilled data |

### Keylogging & Input Capture
| Pattern | Description |
|---------|-------------|
| Keyboard Event Listeners | Detects `keypress`, `keydown`, `keyup` handlers |
| Keystroke Buffer Arrays | Detects arrays used to store captured keystrokes |
| CSS Keylogging | Detects CSS attribute selectors for input exfiltration |
| Form Submit Interception | Detects form submission hijacking |
| Clipboard Theft | Detects `navigator.clipboard.read` access |

### Screen Capture & Surveillance
| Pattern | Description |
|---------|-------------|
| captureVisibleTab | Screenshots browser tabs |
| desktopCapture API | Captures entire screen content |
| tabCapture API | Records tab audio/video streams |
| html2canvas | Third-party screenshot library |
| getDisplayMedia | Screen recording API access |

### Data Exfiltration
| Pattern | Description |
|---------|-------------|
| POST to External Servers | Detects data sent via fetch/XMLHttpRequest |
| WebSocket C2 | Detects real-time command & control channels |
| sendBeacon | Stealthy exfiltration that survives page close |
| Encrypted Exfiltration | Detects RSA/AES encryption of stolen data |
| FormData Blob Upload | Detects binary data uploads |

### Code Injection & Evasion
| Pattern | Description |
|---------|-------------|
| eval() / new Function() | Dynamic code execution |
| Remote Script Injection | Loading external scripts via createElement |
| CSP Header Removal | Removing Content-Security-Policy (confirmed malware) |
| DOM Event Handler Injection | Manifest V3 remote code bypass |
| DevTools Detection | Anti-analysis techniques |
| JavaScript Obfuscation | _0x patterns, hex encoding, large string arrays |

### Browser Hijacking
| Pattern | Description |
|---------|-------------|
| Search Engine Override | Redirects searches for affiliate fraud |
| Homepage Hijacking | Changes browser homepage |
| Startup Page Hijacking | Sets malicious startup pages |
| New Tab Override | Replaces new tab page |

## Dangerous Permission Combinations

| Combination | Risk Level | Impact |
|-------------|------------|--------|
| `tabs` + `storage` | HIGH | Can track all visited URLs |
| `tabs` + `<all_urls>` | CRITICAL | Can screenshot any website |
| `cookies` + `<all_urls>` | CRITICAL | Can steal sessions from any site |
| `scripting` + `<all_urls>` | CRITICAL | Can inject code anywhere |
| `webRequest` + `<all_urls>` | CRITICAL | Can intercept all traffic |
| `clipboardRead` + `storage` | HIGH | Can steal copied passwords |
| `history` + `storage` | HIGH | Can exfiltrate browsing history |

## Advanced Detection

### Threat Campaign Attribution
The analyzer cross-references extensions against:
- Known malicious extension databases (Regularly updated to track all the latest extensions which were found to be malicious)
- OSINT web searches across security research sites
- Cached attribution from previous scans

### Domain Intelligence
- **Domain Age Detection**: Flags newly registered domains (<30 days = CRITICAL)
- **High-Risk TLD Detection**: Flags .top, .xyz, .club, .tk, and other abuse-prone TLDs
- **Safe Domain Whitelist**: Skips VirusTotal checks for known legitimate domains (Google, Mozilla, CDNs)

### PII Classification
Identifies what sensitive data extensions access:
- **CRITICAL**: Credentials, Financial Data
- **HIGH**: Cookies/Sessions, Personal Info, Email Content
- **MEDIUM**: Browsing History, Clipboard, Form Data
- **LOW**: Device Info, Geolocation

## Report Output

The analyzer generates:
- **JSON Report**: Machine-readable technical data
- **HTML Report**: Professional dark-themed threat intelligence report with:
  - Executive summary with risk score
  - VirusTotal domain reputation results
  - Code snippets with syntax highlighting
  - PII classification breakdown
  - Threat campaign attribution (if found)
  - Actionable security recommendations

## Limitations

- Static analysis covers most detection; dynamic analysis (`--dynamic`) requires Playwright
- Can't analyze code loaded from remote servers at runtime (unless `--dynamic` is used)
- Heavily obfuscated code may evade some pattern matching
- Some patterns may produce false positives - always review context

  Report Screenshots:
  <img width="1447" height="690" alt="image" src="https://github.com/user-attachments/assets/c50b332c-b386-4a1b-b657-c7628fab7059" />
  <img width="1461" height="695" alt="image" src="https://github.com/user-attachments/assets/677d80b6-c0f7-4f7c-a3f6-01852c34f543" />
  <img width="1176" height="610" alt="image" src="https://github.com/user-attachments/assets/4c80cfbe-225d-490c-8938-ac29a1b2b0b5" />
  <img width="1570" height="880" alt="image" src="https://github.com/user-attachments/assets/c02ace49-b152-4826-b41c-7b41abb110d3" />





## Legal

For authorized security testing and research only. Don't use for malicious purposes.

## Author

[@debarshi17](https://github.com/debarshi17)

## License

MIT
