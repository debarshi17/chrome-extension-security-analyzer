# Chrome Extension Security Analyzer

AI-powered security analysis tool for Chrome extensions. Automatically detects malicious code, analyzes permissions, and generates security reports.

## 🎯 Features

- **Extension Discovery**: Download and unpack Chrome extensions
- **Static Analysis**: Detect suspicious code patterns and dangerous permissions
- **Heuristic Analysis: Rule-based pattern detection and code review
- **Risk Scoring**: Automatic security risk assessment (1-10 scale)
- **Web Dashboard**: Interactive interface for viewing results
- **Report Generation**: JSON and PDF reports

## 🚀 Quick Start

### Prerequisites

- Python 3.9+

### Installation
```bash
# Clone the repository
git clone https://github.com/debarshi17/chrome-extension-security-analyzer.git
cd chrome-extension-security-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Configure
cp config.yaml.example config.yaml
# Edit config.yaml with your API keys
```

### Usage
```bash
# Analyze a single extension
python src/analyzer.py --extension-id <extension-id>

# Run web dashboard
python web/app.py

# Batch analysis
python src/batch_analyzer.py --input extensions.txt
```

## 📁 Project Structure
```
chrome-extension-security-analyzer/
├── src/
│   ├── downloader.py       # Download extensions from Chrome Web Store
│   ├── unpacker.py         # Extract and parse .crx files
│   ├── static_analyzer.py  # Pattern matching and code analysis
│   ├── ai_reviewer.py      # AI-powered code review
│   └── report_generator.py # Generate reports
├── web/
│   ├── app.py             # Flask web server
│   └── templates/         # HTML templates
├── data/
│   ├── extensions.db      # SQLite database
│   └── patterns/          # Malicious pattern definitions
├── config.yaml            # Configuration file
└── requirements.txt       # Python dependencies
```

## 🔒 Security & Privacy

- All analysis is performed locally
- All analysis is performed locally on your machine
- Extensions are downloaded from official Chrome Web Store only
- Tool is for educational and security research purposes only

## ⚖️ Legal & Ethical Use

This tool is intended for:
- Security research
- Educational purposes
- Authorized security assessments
- Helping users identify malicious extensions

**Do NOT use this tool for:**
- Creating malware
- Attacking developers
- Violating Chrome Web Store Terms of Service
- Any illegal activities

## 🤝 Contributing

Contributions welcome! Please read CONTRIBUTING.md first.

## 📄 License

MIT License - see LICENSE file for details

## 👤 Author

Created by [@debarshi17](https://github.com/debarshi17)

## 🙏 Acknowledgments

- Chrome Web Store
- Security research community