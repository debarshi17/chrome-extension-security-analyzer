# Chrome Extension Security Analyzer

> **Detect malicious Chrome extensions before they steal your data.**

Browser extensions have full access to your passwords, cookies, and browsing history. Malicious ones exploit this to steal credentials, hijack crypto wallets, and spy on users. This tool catches them.

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![GitHub stars](https://img.shields.io/github/stars/debarshi17/chrome-extension-security-analyzer?style=social)](https://github.com/debarshi17/chrome-extension-security-analyzer/stargazers)

---

## Demo

Analyze any Chrome extension in seconds:

```bash
python src/analyzer.py nkbihfbeogaeaoehlefnkodbefgpgknn
```

**Output:**
```
[SCAN] CHROME EXTENSION SECURITY ANALYZER
================================================================================

[+] Extension: MetaMask
[+] Risk Score: 3.2/10 (LOW)

[ENHANCED] STEP 6.5: Enhanced detection (taint analysis, crypto, phishing)...
[!] TAINT: 2 data flow(s) from sensitive sources to network sinks
    -> chrome.storage.local.get -> fetch
    -> window.ethereum -> sendMessage

[REPORT] Reports generated:
   • HTML Report: reports/nkbihfbeogaeaoehlefnkodbefgpgknn_threat_analysis_report.html
```

### Report Screenshots

<p align="center">
  <img width="90%" alt="Threat Analysis Report" src="https://github.com/user-attachments/assets/c50b332c-b386-4a1b-b657-c7628fab7059" />
</p>

<p align="center">
  <img width="90%" alt="Code Evidence" src="https://github.com/user-attachments/assets/677d80b6-c0f7-4f7c-a3f6-01852c34f543" />
</p>

<p align="center">
  <img width="90%" alt="VirusTotal Results" src="https://github.com/user-attachments/assets/4c80cfbe-225d-490c-8938-ac29a1b2b0b5" />
</p>

<p align="center">
  <img width="90%" alt="PII Classification" src="https://github.com/user-attachments/assets/c02ace49-b152-4826-b41c-7b41abb110d3" />
</p>

---

## Why This Exists

In 2024-2025, malicious browser extensions compromised **millions of users**:

- **DarkSpectre Campaign**: 8.8M users affected via fake productivity extensions
- **ChatGPT Mods Campaign**: 16 extensions stealing Facebook session cookies
- **GhostPoster**: Extensions hiding malicious code inside image files (steganography)
- **Crypto Wallet Drainers**: Extensions replacing clipboard wallet addresses

These extensions passed Chrome Web Store review. They looked legitimate. They had thousands of 5-star reviews.

**Static analysis catches what review processes miss.**

---

## Quick Start

```bash
# Clone
git clone https://github.com/debarshi17/chrome-extension-security-analyzer.git
cd chrome-extension-security-analyzer

# Install dependencies
pip install -r requirements.txt

# Analyze an extension (grab the ID from Chrome Web Store URL)
python src/analyzer.py cjpalhdlnbpafiamejdnhcphjbkeiagm
```

**Optional: Add VirusTotal API key for domain reputation checks**
```bash
cp config.json.template config.json
# Edit config.json with your free API key from https://www.virustotal.com/gui/join-us
```

The extension ID is the 32-character string from the Chrome Web Store URL:
```
https://chrome.google.com/webstore/detail/extension-name/abcdefghijklmnopqrstuvwxyz123456
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

---

## Features

### Detection Engine
- **150+ Malicious Code Patterns** — Keyloggers, screen capture, data theft, C2 communication, crypto wallet theft
- **Taint Analysis Engine** — Tracks data flow from sensitive sources (cookies, passwords) to network sinks (fetch, WebSocket)
- **Cryptocurrency Theft Detection** — Wallet override, clipboard hijacking, seed phrase extraction, approve() injection
- **Phishing Detection** — Fullscreen iframe overlays, fake login forms, password field monitoring
- **Advanced Obfuscation Detection** — Entropy analysis, string rotation, eval bypass, constructor chains

### Analysis Pipeline
- **JavaScript AST Analysis** — Resolves config variables to extract exact exfiltration destinations
- **VirusTotal Integration** — Checks domains against 90+ security vendors
- **Threat Campaign Attribution** — Cross-references against known malware campaigns via OSINT
- **PII Classification** — Identifies what sensitive data is accessed (credentials, cookies, financial)
- **Dynamic Network Capture** — Runtime traffic analysis with Playwright + Chrome DevTools Protocol

### Output
- **Professional HTML Reports** — Dark-themed threat intelligence reports with code evidence
- **Machine-Readable JSON** — For automation and integration
- **Risk Scoring** — 0-10 scale with severity classification

---

## Use Cases

| Who | Use Case |
|-----|----------|
| **Security Researchers** | Analyze suspicious extensions, hunt for malware campaigns |
| **IT Administrators** | Audit extensions before enterprise deployment |
| **Incident Responders** | Investigate compromised systems, extract IOCs |
| **Browser Security Teams** | Automate extension vetting workflows |
| **Bug Bounty Hunters** | Find malicious extensions for vendor reports |

---

## CLI Options

```bash
# Basic analysis
python src/analyzer.py <extension_id>

# Fast mode (skip VirusTotal API calls)
python src/analyzer.py <extension_id> --fast

# Enable dynamic network capture (requires Playwright)
python src/analyzer.py <extension_id> --dynamic

# Custom timeout for dynamic analysis
python src/analyzer.py <extension_id> --dynamic --dynamic-timeout 45
```

---

## Detection Categories

### Credential & Financial Theft
| Pattern | Description |
|---------|-------------|
| Password Field Targeting | Scripts targeting `input[type=password]` |
| Credit Card Harvesting | Access to payment card fields |
| OTP/2FA Interception | Theft of verification codes |
| Hidden Autofill Trigger | Invisible fields harvesting autofilled data |

### Cryptocurrency Theft
| Pattern | Description |
|---------|-------------|
| Wallet Object Override | Hijacking `window.ethereum` / `window.solana` |
| Clipboard Address Swap | Replacing copied wallet addresses |
| Seed Phrase Detection | Extracting BIP39 recovery phrases |
| Token Approval Injection | Injecting unlimited `approve()` calls |

### Keylogging & Surveillance
| Pattern | Description |
|---------|-------------|
| Keystroke Capture | `keypress`, `keydown` event handlers with buffers |
| Screen Recording | `captureVisibleTab`, `getDisplayMedia`, `tabCapture` |
| CSS Keylogging | Attribute selectors exfiltrating input values |
| Clipboard Theft | `navigator.clipboard.read` access |

### Data Exfiltration
| Pattern | Description |
|---------|-------------|
| Taint Flow Detection | Cookies/passwords flowing to fetch/WebSocket |
| Encrypted Exfiltration | RSA/AES encryption of stolen data |
| sendBeacon | Stealthy exfiltration surviving page close |
| WebSocket C2 | Real-time command & control channels |

### Code Injection & Evasion
| Pattern | Description |
|---------|-------------|
| CSP Header Removal | Removing Content-Security-Policy (confirmed malware) |
| DOM Event Injection | Manifest V3 remote code bypass |
| Eval Bypass | `window['ev'+'al']` concatenation tricks |
| Obfuscation Detection | String rotation, high entropy, constructor chains |

---

## Dangerous Permission Combinations

| Combination | Risk | Impact |
|-------------|------|--------|
| `cookies` + `<all_urls>` | CRITICAL | Steal sessions from any site |
| `webRequest` + `<all_urls>` | CRITICAL | Intercept all traffic |
| `scripting` + `<all_urls>` | CRITICAL | Inject code anywhere |
| `tabs` + `<all_urls>` | CRITICAL | Screenshot any website |
| `clipboardRead` + `storage` | HIGH | Steal copied passwords |

---

## Advanced Detection

### Taint Analysis Engine
Tracks sensitive data from source to sink:
```
chrome.cookies.getAll() → JSON.stringify() → fetch()
         ↑ SOURCE                              ↑ SINK

[CRITICAL] Session cookies flowing to external server
```

### Threat Campaign Attribution
Cross-references extensions against:
- Known malicious extension databases (updated regularly)
- OSINT web searches across security research sites
- Cached attribution from previous scans

### Domain Intelligence
- DGA (Domain Generation Algorithm) detection
- Typosquatting detection
- High-risk TLD flagging (.top, .xyz, .tk)
- VirusTotal reputation with false positive filtering

---

## Limitations

- Static analysis covers most threats; use `--dynamic` for runtime behavior
- Heavily obfuscated code may evade pattern matching
- Remote code loaded at runtime requires dynamic analysis
- Some patterns may need manual review for context

---

## Contributing

Contributions welcome! Areas where help is needed:

- [ ] New detection patterns for emerging threats
- [ ] Browser extension (analyze from right-click menu)
- [ ] Web UI for non-technical users
- [ ] Additional threat campaign signatures

See [issues](https://github.com/debarshi17/chrome-extension-security-analyzer/issues) for current tasks.

---

## License

MIT — Use freely for security research and authorized testing.

---

## Author

**[@debarshi17](https://github.com/debarshi17)**

---

<p align="center">
  <b>If this tool helped you, consider giving it a ⭐</b>
</p>
