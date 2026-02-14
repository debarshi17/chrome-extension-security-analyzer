# Project Overview

## Product Name
Browser & VSCode Extension Security Analyzer

## What this product does
A professional-grade security analysis platform that detects malicious browser extensions (Chrome, Edge) and VSCode extensions before installation. It combines static code analysis, behavioral correlation, taint tracking, dynamic runtime analysis, domain intelligence, and threat attribution to produce risk scores and detailed threat reports.

## Target Users
- Security teams evaluating extensions before enterprise deployment
- Security researchers analyzing malware campaigns
- Extension developers validating their own code
- Individual users checking extension safety

## Core Value Proposition
Catches sophisticated threats that simple pattern matching misses by correlating capabilities across permissions, code patterns, network behavior, and runtime signals into compound threat assessments. Produces analyst-grade reports with evidence and remediation guidance.

## Current Stage
Active development - MVP functional for Chrome/Edge/VSCode analysis with static + dynamic + threat intel. Enhancing detection engine toward commercial quality.

## Tech Stack
- **Analysis Engine**: Python 3.10+ (regex, esprima AST, Shannon entropy)
- **Dynamic Analysis**: Playwright + Chrome DevTools Protocol (CDP)
- **Threat Intel**: VirusTotal API, domain intelligence, OSINT web search
- **Reports**: HTML (dark-theme professional), JSON (technical)
- **CLI**: argparse-based with --fast, --dynamic, --edge, --vscode modes

## Main Repositories / Folders
```
src/                          # Core analysis modules (~20,800 lines)
  analyzer.py                 # Main orchestrator (Chrome/Edge pipeline)
  static_analyzer.py          # 181 regex patterns + AST + permissions; large-file caps, 0–100% progress
  ast_analyzer.py             # esprima AST; large-file skip, config cap, depth limit
  advanced_detection.py       # CSP manipulation, WebSocket C2, delayed activation
  enhanced_detection.py       # Wallet hijack, phishing, crypto theft
  taint_analyzer.py           # Source-sink data flow tracking
  network_capture.py          # Playwright dynamic analysis + CDP
  behavioral_engine.py        # [NEW] Static behavioral correlation engine
  domain_intelligence.py      # Typosquatting, DGA, C2 pattern detection
  virustotal_checker.py       # VT domain reputation
  threat_attribution.py       # Campaign matching + OSINT
  professional_report.py      # HTML report generator
  host_permissions_analyzer.py # Host permission categorization
  pii_classifier.py           # PII/data type classification
  false_positive_filter.py    # FP suppression logic
  vscode_analyzer.py          # VSCode extension analyzer (separate engine)
  vscode_downloader.py        # VS Marketplace downloader
  vscode_unpacker.py          # VSIX unpacker
test_fixtures/                # 20 malicious extension samples (10 original + 10 evasion)
reports/                      # Generated HTML/JSON reports
data/                         # Downloaded extensions cache
ai-context/                   # AI session context files
```
