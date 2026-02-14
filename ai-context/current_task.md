# Current Task

## What we are working on right now
V3 Enhancement Sprint — Code quality fixes, new detection capabilities, risk scoring rebalance, and report integration.

## Why this matters
Real-world testing revealed: (1) regex backtracking risk on large files, (2) VT false positives on benign domains with 1-2 detections, (3) missing detection for remote iframe C2 architecture, (4) no sensitive target detection (Gmail/banking/auth), (5) no attack narrative synthesis, (6) no campaign fingerprinting.

## V3 Sprint Tasks

### Part 1: Code Issues & Performance Fixes
- [x] **Regex backtracking fix** — Added `_safe_pattern_finditer()` two-pass approach in `static_analyzer.py`. Patterns with `[\s\S]{0,N}` where N>=200 are split into anchor+tail and matched in a bounded window. 20 of 164 patterns converted.
- [x] **Taint analyzer size guard** — Added `MAX_AST_PARSE_SIZE = 2MB` guard before `esprima.parseScript()` in `taint_analyzer.py`. Files >2MB fall back to regex-only analysis.
- [x] **VT threshold fix** — Graduated penalty in `update_risk_with_virustotal()`: 5+ detections = +3.0, 3+ = +1.5 (MODERATE confidence), 1-2 = +0.5 (LOW confidence). Suspicious domains get +0.5. Prevents fb.me/huggingface.co false positives.

### Part 2: Critical Missing Detection
- [x] **Remote Iframe C2 detection** — 3 new patterns in `static_analyzer.py` (Remote Iframe UI Injection, Fullscreen Remote Iframe, Dynamic Remote Iframe Source). Rule 18 in `behavioral_engine.py` (Remote-Controlled Extension). Added `remote_c2_extension` → `REMOTE_C2_LOADER` archetype in `classify_threat()`.
- [x] **Sensitive target detector** — Created `src/sensitive_target_detector.py`. Checks manifest content_scripts + host_permissions for 4 categories (email, productivity, finance, auth). Gmail module detection scans JS for 7 Gmail-specific indicators (DOM selectors, MutationObserver, compose hooks). Returns risk multiplier (up to 1.4x for Gmail surveillance).
- [x] **Attack narrative generator** — Added `generate_attack_narrative()` to `static_analyzer.py`. Builds 4-stage chain: ACCESS → COLLECT → EXFILTRATE → PERSIST. Outputs confidence (low/medium/high) and impact summary. Tested: 4-stage chain with "high" confidence on synthetic data.
- [x] **Campaign fingerprinting** — Created `src/campaign_detector.py`. Generates code hashes (normalized, lib-excluded), infrastructure fingerprint (domain hash), capability fingerprint (technique hash). Matches against 3 built-in campaign signatures (GhostPoster, PDF Toolbox, Great Suspender). Tested: GhostPoster matched at 0.9 confidence.

### Part 3: Risk Scoring Rebalance
- [x] **Behavioral floors** — Tightened: 2+ critical → min 7.0 (was 6.0), 1 critical → min 5.5 (was 5.0)
- [x] **Sensitive target multiplier** — Email → 1.3x, Gmail module → 1.4x, finance → 1.3x, auth → 1.2x. Remote C2 → min 7.5.
- [x] **Attack narrative confidence integration** — High confidence → floor 7.0, medium → floor 5.0

### Part 4: Integration
- [x] Integrate all new modules into `analyzer.py` pipeline — Added Steps 2.6 (sensitive targets), 6.8 (attack narrative), 8.8 (campaign fingerprint) to `analyzer.py`. All new modules instantiated in `__init__`.
- [x] Update `professional_report.py` for attack narratives, sensitive targets, campaign fingerprints — Added 3 new sections: `_generate_attack_narrative_section()` (chain visualization with stage cards + arrows), `_generate_sensitive_targets_section()` (target list + Gmail surveillance module detail), `_generate_campaign_fingerprint_section()` (matched campaign cards + fingerprint hashes). Wired into report assembly after attack paths.

## Files being modified/created
- `src/static_analyzer.py` — Two-pass regex, attack narrative, new patterns
- `src/taint_analyzer.py` — AST size guard
- `src/behavioral_engine.py` — Remote C2 rule, updated technique sets
- `src/sensitive_target_detector.py` — NEW: Sensitive target detection
- `src/campaign_detector.py` — NEW: Campaign fingerprinting
- `src/analyzer.py` — Pipeline integration for new modules
- `src/professional_report.py` — New report sections
