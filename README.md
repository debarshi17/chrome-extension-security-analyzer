# Chrome Extension Security Analyzer

A professional-grade static analysis tool for detecting malicious Chrome extensions. Performs deep code analysis, permission scrutiny, and generates threat intelligence reports trusted by security teams.

## What It Does

This tool downloads Chrome extensions directly from the Web Store, unpacks them, and performs comprehensive security analysis including:

- **64+ Malicious Pattern Detection** - Keyloggers, screen capture, data exfiltration, C2 communication
- **Permission Risk Analysis** - Flags dangerous permission combinations (tabs+storage, scripting+all_urls, etc.)
- **VirusTotal Integration** - Cross-references domains with 90+ security vendors
- **AST-Based Code Analysis** - Resolves config variables to find actual exfiltration destinations
- **Threat Campaign Attribution** - Identifies known malware campaigns (DarkSpectre, SpyVPN, etc.)
- **Professional HTML Reports** - Dark-themed threat intelligence reports with code snippets

## Installation

### Prerequisites
- Python 3.9 or higher
- VirusTotal API key (free tier works)

### Setup

```bash
# Clone the repository
git clone https://github.com/debarshi17/chrome-extension-security-analyzer.git
cd chrome-extension-security-analyzer

# Install dependencies
pip install -r requirements.txt

# Configure VirusTotal API key
cp config.json.template config.json
# Edit config.json and add your VirusTotal API key
```

### Configuration

Create `config.json` in the root directory:

```json
{
    "virustotal_api_key": "your_api_key_here"
}
```

Get a free API key from [VirusTotal](https://www.virustotal.com/gui/join-us).

## Usage

### Basic Analysis

```bash
# Analyze an extension by ID (from Chrome Web Store URL)
python src/analyzer.py <extension_id>

# Example: Analyze a suspicious extension
python src/analyzer.py eebihieclccoidddmjcencomodomdoei
```

The extension ID is the 32-character string in the Chrome Web Store URL:
```
https://chrome.google.com/webstore/detail/extension-name/eebihieclccoidddmjcencomodomdoei
                                                        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
                                                              This is the extension ID
```

### Output

The analyzer generates two files in the `reports/` directory:

1. **`<id>_analysis.json`** - Raw analysis data in JSON format
2. **`<id>_threat_intel_report.html`** - Professional threat intelligence report

### Command Line Options

```bash
python src/analyzer.py <extension_id> [options]

Options:
  --output-dir DIR    Output directory for reports (default: reports/)
  --skip-vt           Skip VirusTotal checks (faster, no API needed)
  --verbose           Show detailed analysis progress
```

## What Gets Detected

### Malicious Code Patterns

| Category | Examples |
|----------|----------|
| **Keylogging** | keydown/keyup listeners, password field targeting, keystroke buffers |
| **Screen Capture** | captureVisibleTab, desktopCapture, html2canvas |
| **Data Exfiltration** | FormData uploads, sendBeacon, WebSocket exfiltration |
| **Code Injection** | eval(), executeScript, remote script loading |
| **Evasion Techniques** | DevTools detection, JS obfuscation signatures, hex-encoded strings |
| **Credential Theft** | Cookie access, clipboard reading, form data harvesting |

### Permission Combination Warnings

The analyzer flags dangerous permission combinations:

| Combination | Risk | Why It's Dangerous |
|-------------|------|-------------------|
| `tabs` + `storage` | HIGH | URL harvesting - can track all visited sites |
| `tabs` + `<all_urls>` | CRITICAL | Screen capture capability on any website |
| `scripting` + `<all_urls>` | CRITICAL | Can inject code into any webpage |
| `cookies` + `<all_urls>` | CRITICAL | Session hijacking on any site |
| `webRequest` + `<all_urls>` | CRITICAL | Can intercept all web traffic |

## Sample Report

The HTML report includes:

- **Executive Summary** - Risk score, verdict, key findings
- **Permission Analysis** - All permissions with risk levels and combination warnings
- **Threat Analysis** - Detected patterns with code snippets showing exact malicious code
- **VirusTotal Results** - Domain reputation from security vendors
- **Threat Attribution** - Known campaign matches (if any)
- **Code Evidence** - Syntax-highlighted snippets with line numbers

## Project Structure

```
chrome-extension-security-analyzer/
├── src/
│   ├── analyzer.py              # Main orchestrator
│   ├── static_analyzer.py       # Pattern detection (64+ patterns)
│   ├── ast_analyzer.py          # JavaScript AST analysis
│   ├── professional_report.py   # HTML report generator
│   ├── virustotal_checker.py    # VirusTotal integration
│   ├── domain_intelligence.py   # DGA/typosquatting detection
│   ├── threat_attribution.py    # Campaign attribution
│   ├── pii_classifier.py        # Data classification
│   ├── advanced_detection.py    # CSP manipulation, DOM injection
│   └── ioc_manager.py           # IOC database management
├── data/
│   └── known_malicious_extensions.json  # Threat intelligence database
├── config.json.template         # API key template
├── requirements.txt             # Python dependencies
└── reports/                     # Generated reports (gitignored)
```

## Known Malware Campaigns

The tool includes a database of known malicious extensions from security research:

- **DarkSpectre/ZoomStealer** - 8.8M users affected, video conferencing theft
- **SpyVPN** - Silent screenshot surveillance, encrypted exfiltration
- **LayerX Identified** - Various malicious extensions from security disclosures

## Limitations

- **Static Analysis Only** - Does not execute code; some runtime-loaded malware may be missed
- **Remote Payloads** - Code loaded from external servers at runtime cannot be analyzed
- **Obfuscation** - Heavily obfuscated code may not match patterns (though obfuscation itself is flagged)
- **False Positives** - Some legitimate extensions use similar patterns; review context carefully

## Legal Notice

This tool is for authorized security testing, research, and educational purposes only.

**Do not use this tool to:**
- Create or distribute malware
- Violate Chrome Web Store Terms of Service
- Conduct unauthorized security assessments
- Any illegal activities

The developers are not responsible for misuse of this tool.

## Contributing

Contributions welcome! Areas where help is needed:

- Additional malicious pattern signatures
- Dynamic analysis capabilities
- UI improvements for reports
- Documentation and examples

## Credits

- Security research by [KOI Security](https://koi.ai), [Wladimir Palant](https://palant.info), [LayerX Security](https://layerxsecurity.com)
- VirusTotal for domain reputation API
- The security research community

## Author

Created by [@debarshi17](https://github.com/debarshi17)

## License

MIT License - see LICENSE file for details.
