# Architecture

## High Level Flow

### Chrome/Edge Extension Analysis (9-step pipeline)
1. **Store Metadata** - Fetch from Chrome Web Store / Edge Add-ons (name, author, users, rating, warnings)
2. **Download** - Download .crx file from store
3. **Unpack** - Extract .crx to directory, read manifest.json
4. **Permissions Analysis** - Score individual permissions + host permission categorization + attack-path combinations
5. **Static Analysis** - 181 regex patterns + AST analysis (esprima) + taint tracking (source-sink flows)
6. **Domain Intelligence** - Typosquatting, DGA detection, C2 patterns for all extracted URLs
7. **VirusTotal** - Domain reputation check against 90+ security vendors
8. **Dynamic Analysis** (optional) - Playwright loads extension, CDP captures network/console/WebSocket, behavioral convergence verdict
9. **Report Generation** - HTML (dark-theme professional) + JSON (technical data)

Between steps 6 and 7, additional detection passes run:
- Advanced Detection: CSP manipulation, DOM event injection, WebSocket C2, delayed activation, obfuscation
- Enhanced Detection: Wallet hijack, phishing overlays, crypto theft
- **Behavioral Correlation Engine** [NEW]: Correlates all findings into compound threat patterns

### VSCode Extension Analysis (4-layer model)
1. **Metadata & Publisher** - VS Marketplace metadata, publisher verification, install count
2. **Supply Chain** - Dependencies, node_modules, bundled code analysis
3. **Deep Code Analysis** - 200+ patterns + 22 behavioral correlation rules + capability detection
4. **Risk Scoring** - Multi-component model (code + correlations + infrastructure + positive signals)

## Main Components

### 1) Extension Fetcher (`downloader.py`, `vscode_downloader.py`)
Downloads from Chrome Web Store, Edge Add-ons, or VS Marketplace. Handles CRX/VSIX formats.

### 2) Static Analysis Engine (`static_analyzer.py`) + AST (`ast_analyzer.py`)
- **181 regex patterns** across 16+ attack categories (credential theft, keylogging, screen capture, code injection, data exfiltration, obfuscation, fingerprinting, etc.)
- **AST analysis** via esprima: Tracks fetch/XHR destinations, data flow, config references
- **Permission scoring**: Individual + combination attack-path scoring
- **False positive reduction**: Comment skipping, library detection, first-party domain allowlisting
- **Large-file / robustness (2026-02):**
  - **JS file set**: `node_modules` and `bower_components` are excluded from both AST and pattern scan to avoid huge dependency trees.
  - **AST** (`ast_analyzer.py`): Files &gt;2 MiB skip full AST (esprima + traverse) to avoid parse/traverse hangs; `_traverse_ast` has a max depth of 10,000 to prevent runaway recursion. Config extraction (`_extract_config_values`) only reads files with "config" in the name, skips files &gt;512 KiB, and caps read at 512 KiB to avoid hang/ReDoS.
  - **Pattern scan** (`static_analyzer.py`): `_read_file_cached` caps read at 5 MiB per file so regex scanning stays bounded.
- **Progress**: A single 0–100% progress bar (tqdm) for static analysis: first half = AST (one step per file via `progress_callback`), second half = pattern/obfuscation scan. Bar is in `static_analyzer.analyze_extension`; `ast_analyzer.analyze_directory(extension_dir, progress_callback=...)` supports the callback.
- **Two-pass regex** [V3]: `_safe_pattern_finditer()` for patterns with `[\s\S]{0,N}` where N>=200. Splits into anchor+tail and matches in bounded window to prevent catastrophic backtracking. 20 of 164 patterns converted.
- **VT graduated threshold** [V3]: `update_risk_with_virustotal()` uses graduated penalties: 5+ detections = +3.0, 3+ = +1.5 (MODERATE), 1-2 = +0.5 (LOW). Prevents false positives on fb.me/huggingface.co.
- **Remote Iframe C2 patterns** [V3]: 3 new patterns (Remote Iframe UI Injection, Fullscreen Remote Iframe, Dynamic Remote Iframe Source)
- **Attack narrative** [V3]: `generate_attack_narrative()` builds 4-stage chain (ACCESS → COLLECT → EXFILTRATE → PERSIST) with confidence levels
- **Taint analyzer size guard** [V3]: `MAX_AST_PARSE_SIZE = 2MB` in `taint_analyzer.py`. Files >2MB fall back to regex-only analysis.

### 3) Behavioral Correlation Engine (`behavioral_engine.py`) [V2+V3]
Correlates findings from ALL analysis layers into 18 compound threat rules:
- Session theft chains (cookies + all_urls + network)
- Credential harvesters (password monitoring + POST exfil)
- Surveillance agents (keylogger + screen capture + network)
- Remote code execution (CSP removal + eval + external scripts)
- Wallet hijacking, phishing overlays, WebSocket C2
- Evasion-wrapped payloads, native system escape, OAuth theft
- Traffic MitM, extension manipulation, staged payloads
- **Remote-Controlled Extension** [V3]: Remote iframe C2 + all_urls detection

### 4) Dynamic Analysis (`network_capture.py`) [V2]
- Playwright launches Chrome with extension loaded
- CDP captures: network requests, WebSocket frames, console messages, responses
- Behavioral analysis: beaconing detection, post-navigation exfil, credential patterns
- Chrome API mocking: synthetic cookie/tab/history data via Proxy injection
- Canary token detection: synthetic session cookies monitored in outbound traffic
- Date.now() time manipulation: +30 days to trigger time-bomb payloads
- DOM mutation tracking: script injection, iframe insertion, event handler injection via CDP
- Chrome API call logging: Proxy-based interception of sensitive APIs (cookies, tabs, identity, history)
- Verdict system: CLEAN → LOW_RISK → SUSPICIOUS → MALICIOUS (canary leak → auto MALICIOUS)

### 5) Threat Intelligence
- **VirusTotal** (`virustotal_checker.py`): Domain reputation, 24h caching, rate limiting
- **Domain Intelligence** (`domain_intelligence.py`): Typosquatting (Levenshtein), DGA scoring, C2 patterns
- **Threat Attribution** (`threat_attribution.py`): Campaign matching, OSINT web search

### 6) Sensitive Target Detector (`sensitive_target_detector.py`) [V3]
Detects extensions targeting high-value services:
- 4 categories: email, productivity, finance, auth (with domain lists)
- Manifest content_scripts + host_permissions matching
- Gmail-specific surveillance module detection (7 indicators: DOM selectors, MutationObserver, compose hooks, message IDs)
- Risk multiplier: email → 1.3x, Gmail module → 1.4x, finance → 1.3x, auth → 1.2x

### 7) Campaign Fingerprinting (`campaign_detector.py`) [V3]
Generates fingerprints for malicious campaign clustering:
- Code hashes (normalized, lib-excluded)
- Infrastructure fingerprint (sorted domain hash)
- Capability fingerprint (sorted technique hash)
- 3 built-in campaign signatures: GhostPoster, PDF Toolbox, Great Suspender
- Scoring: domain overlap, infra fingerprint match, indicator matching

### 8) Report Generator (`professional_report.py`)
Dark-theme HTML reports (Mandiant/CrowdStrike style) with:
- Executive summary, risk score gauge, threat classification
- Risk score breakdown with 4-component bars [V2]
- Behavioral correlations with attack chain cards [V2]
- Permission attack paths visualization [V2]
- **Attack narrative chain visualization** [V3]: ACCESS → COLLECT → EXFILTRATE → PERSIST stage cards
- **Sensitive target detection** [V3]: Target list, Gmail surveillance module detail, category chips
- **Campaign fingerprint** [V3]: Matched campaign cards, fingerprint hashes, domain list
- Detailed findings with code snippets and evidence
- Permission analysis, domain intelligence, VirusTotal results
- Supply chain version diff [V2]
- Remediation recommendations

## Known Weak Spots (Updated)
1. **Static analysis on very large extensions** - Files &gt;2 MiB skip AST (see Large-file / robustness above); pattern scan is capped at 5 MiB per file. Full AST on giant single-file bundles is intentionally skipped to avoid hangs.
2. **Static patterns miss novel malware** - Regex can't understand code semantics (mitigated by behavioral correlation engine combining signals)
3. ~~Dynamic analysis is short-lived~~ - ADDRESSED: Date.now() override triggers time-bomb payloads
4. ~~No forced execution~~ - PARTIALLY ADDRESSED: Time manipulation + synthetic API data triggers dormant paths
5. ~~No Chrome API call logging~~ - ADDRESSED: Proxy-based API interception logs all sensitive calls
6. ~~No version diff~~ - ADDRESSED: `version_diff.py` with 8 supply chain indicators
7. ~~Risk scoring ad-hoc~~ - ADDRESSED: 4-component model with malice floor and positive signal suppression
8. **ML-based semantic analysis not implemented** - Would catch entirely novel attack patterns
9. **Full V8 forced execution not implemented** - FV8-style path exploration requires V8 modification
