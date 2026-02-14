# Next Steps

## Immediate Tasks (V3 Sprint Complete - Now Testing)
- [x] Static analysis robustness: large-file skip, config cap, traverse depth limit, node_modules exclude, progress bar 0–100% (2026-02-12)
- [x] V2 Engine: behavioral engine, permission attack paths, CSP, risk scoring V2, dynamic analysis, version diff (2026-02-09)
- [x] V3 Regex backtracking fix: two-pass `_safe_pattern_finditer()` for 20/164 patterns (2026-02-13)
- [x] V3 Taint analyzer size guard: 2MB cap before esprima parse (2026-02-13)
- [x] V3 VT graduated threshold: 5+/3+/1-2 detection tiers (2026-02-13)
- [x] V3 Remote Iframe C2: 3 patterns + Rule 18 + REMOTE_C2_LOADER archetype (2026-02-13)
- [x] V3 Sensitive target detector: 4 categories, Gmail module, risk multiplier (2026-02-13)
- [x] V3 Attack narrative: 4-stage chain with confidence (2026-02-13)
- [x] V3 Campaign fingerprinting: code hashes, infra/capability fingerprints, 3 signatures (2026-02-13)
- [x] V3 Risk scoring rebalance: tighter floors, sensitive multiplier, narrative confidence (2026-02-13)
- [x] V3 Pipeline integration: Steps 2.6, 6.8, 8.8 in analyzer.py (2026-02-13)
- [x] V3 Report sections: attack narrative, sensitive targets, campaign fingerprint in professional_report.py (2026-02-13)
- [ ] End-to-end test V3 pipeline on real extension
- [ ] Regression test benign extensions (Bitwarden, uBlock Origin)
- [ ] Test dynamic analysis (--dynamic) with API mocking and canary tokens

## Long Term / Ideas
- ML-based semantic code analysis (JavaSith approach)
- Behavioral baselining over time (store results, alert on changes)
- OAuth scope analysis for extensions requesting Google/Microsoft tokens
- Real browser interaction simulation (beyond headless browsing)
- Extension version history database for trend analysis
- Web dashboard for team-based extension review
- Browser extension client that scans installed extensions
- Forced execution via service worker context injection (full FV8-lite implementation)
