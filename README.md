# Chrome Extension Security Analyzer

A static analysis tool for detecting malicious Chrome extensions. Scans extension code for suspicious patterns, analyzes permissions, and generates threat intelligence reports.

## What It Does

- Downloads Chrome extensions directly from the Web Store
- Scans for 64+ malicious code patterns (keyloggers, screen capture, data theft, etc.)
- Flags dangerous permission combinations
- Checks domains against VirusTotal (90+ security vendors)
- Generates professional HTML reports with code evidence

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
```

The extension ID is the 32-character string from the Chrome Web Store URL:
```
https://chrome.google.com/webstore/detail/extension-name/abcdefghijklmnopqrstuvwxyz123456
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
```

Reports are saved to the `reports/` folder.

## What Gets Detected

| Category | Examples |
|----------|----------|
| Keylogging | Keyboard listeners, password field targeting |
| Screen Capture | Screenshot APIs, canvas export |
| Data Exfiltration | POST requests, WebSocket, sendBeacon |
| Code Injection | eval(), remote script loading |
| Credential Theft | Cookie access, clipboard reading |
| Evasion | DevTools detection, code obfuscation |

## Dangerous Permission Combinations

| Combination | Risk |
|-------------|------|
| `tabs` + `storage` | Can track all visited URLs |
| `tabs` + `<all_urls>` | Can screenshot any website |
| `cookies` + `<all_urls>` | Can steal sessions from any site |
| `scripting` + `<all_urls>` | Can inject code anywhere |

## Limitations

- Static analysis only - doesn't execute code
- Can't analyze code loaded from remote servers at runtime
- Heavily obfuscated code may evade pattern matching
- Some patterns may produce false positives - always review context

## Legal

For authorized security testing and research only. Don't use for malicious purposes.

## Author

[@debarshi17](https://github.com/debarshi17)

## License

MIT
