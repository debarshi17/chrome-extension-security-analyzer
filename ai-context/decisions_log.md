# Decisions Log

## Decision Template
Date:
Decision:
Reason:
Alternatives considered:

---

## Decisions

### VSCode Analyzer: Behavioral Correlation Architecture
Date: 2026-02-09
Decision: Implement behavioral correlations as rules within `_correlate_behaviors()` method that combine findings from different categories into compound threat patterns
Reason: Simple, maintainable, no ML dependencies. Each rule clearly maps to a known attack archetype.
Alternatives considered: ML-based clustering, graph analysis

### VSCode Analyzer: Risk Scoring Model
Date: 2026-02-09
Decision: 5-component model (metadata + supply_chain + code_analysis + behavioral_correlations + infrastructure) with positive signal suppression and tiered malice floor
Reason: Prevents any single low-severity finding from being masked by positive signals when compound critical threats exist
Alternatives considered: Single weighted sum, ML regression

### VSCode Analyzer: MAX_SCAN_SIZE Fix
Date: 2026-02-09
Decision: Increase from 512KB to 2MB, and scan patterns even on oversized files (truncated to limit)
Reason: 577KB webpack bundles (like clacla/CoSave) were being completely skipped for pattern scanning, causing critical capabilities to go undetected
Alternatives considered: Chunk-based scanning, per-line scanning

### Browser Analyzer: Behavioral Engine as Separate Module
Date: 2026-02-09
Decision: Create `behavioral_engine.py` as a standalone module rather than embedding rules in `static_analyzer.py`
Reason: Browser analysis has more data sources to correlate (permissions, patterns, AST, taint, advanced, enhanced, dynamic). Separate module keeps concerns clean and allows reuse.
Alternatives considered: Embedding in static_analyzer.py like VSCode's approach

### Browser Analyzer: Permission Combination Attack-Paths
Date: 2026-02-09
Decision: Model 8 specific attack paths instead of generic pairwise combination scoring
Reason: Real attacks use specific permission combinations. Generic pairwise would create false positives on benign combinations. Attack-path model maps to actual threat scenarios.
Alternatives considered: Pairwise scoring matrix, permission graph traversal

### Browser Analyzer: 6-Phase Enhancement Plan
Date: 2026-02-09
Decision: Implement all 6 phases (static correlation, permission paths, CSP, risk scoring, dynamic analysis, version diff)
Reason: User wants comprehensive commercial-grade product. Research (FV8, JavaSith, BDR) confirms all gaps are significant.
Alternatives considered: Static-only phases first, dynamic later

### Browser Analyzer: Risk Scoring V2 - 4-Component Model
Date: 2026-02-09
Decision: Replace ad-hoc additive model with 4-component model: permissions (0-2.5) + code analysis (0-2.5) + behavioral correlations (0-3.0) + infrastructure (0-2.0) with positive signal suppression and malice floor
Reason: Old model maxed patterns at 1 point, making it impossible for code-heavy threats to score above MEDIUM. New model gives behavioral correlations the highest weight (3.0) since they represent compound attack chains.
Alternatives considered: Keep old model with higher weights

### Browser Analyzer: Canary Token Design
Date: 2026-02-09
Decision: Inject synthetic session cookies and monitor outbound traffic for canary values. If detected = definitive proof of data theft.
Reason: Static analysis can only identify capability, not intent. Canary tokens prove actual data theft in dynamic analysis with zero false positives.
Alternatives considered: Only monitor for real credential leaks (higher false negative rate)

### Browser Analyzer: Time Manipulation for Forced Execution
Date: 2026-02-09
Decision: Override Date.now() and Date constructor to advance 30 days forward during dynamic analysis
Reason: FV8 research shows 2,899 extensions hide behind time-bomb conditionals. 30 days is a common activation delay. This approach doesn't require V8 modification.
Alternatives considered: Full V8 modification (not feasible in Python tool), shorter time offsets

### V3: Two-Pass Regex for Catastrophic Backtracking
Date: 2026-02-13
Decision: Split patterns with `[\s\S]{0,N}` (N>=200) into anchor+tail and match in bounded window via `_safe_pattern_finditer()`. 20 of 164 patterns converted.
Reason: Large JS files (>100KB) can trigger exponential backtracking on greedy `[\s\S]` quantifiers. Two-pass approach keeps detection fidelity while bounding worst-case to O(n).
Alternatives considered: Timeout per regex (unreliable), rewrite all patterns to use `[^]*` or atomic groups (Python re doesn't support atomic)

### V3: VirusTotal Graduated Threshold
Date: 2026-02-13
Decision: 5+ detections = +3.0, 3+ = +1.5 (MODERATE), 1-2 = +0.5 (LOW). Suspicious = +0.5.
Reason: Domains like fb.me and huggingface.co get 1-2 detections from 90+ vendors due to URL shortener/CDN classification. Previous flat +3.0 penalty inflated scores for benign extensions.
Alternatives considered: Ignore all VT results <3 (loses signal), vendor-specific weighting (too complex)

### V3: Sensitive Target Detection as Separate Module
Date: 2026-02-13
Decision: Create `sensitive_target_detector.py` with domain matching and Gmail module detection rather than adding to behavioral engine.
Reason: Sensitive target detection is manifest-driven (runs early in pipeline at Step 2.6) while behavioral engine runs after pattern scanning. Separate module also allows risk multiplier to be applied during scoring.
Alternatives considered: Embedding in behavioral_engine.py, adding to static_analyzer.py

### V3: Campaign Fingerprinting with Built-in Signatures
Date: 2026-02-13
Decision: Fingerprint via normalized code hashes + sorted domain hash + sorted technique hash. Match against 3 built-in campaign signatures (GhostPoster, PDF Toolbox, Great Suspender) with configurable threshold.
Reason: Known malicious campaign patterns recur across multiple extensions. Fingerprinting enables automatic identification. Built-in signatures cover the most well-documented campaigns.
Alternatives considered: External signature database only (requires network), ML-based clustering (needs training data)

### Static Analysis: Large-File and Hang Hardening
Date: 2026-02-12
Decision: (1) Exclude node_modules/bower_components from JS file list; (2) Skip full AST for files &gt;2 MiB and cap config extraction at 512 KiB; (3) Cap AST traverse depth at 10,000; (4) Cap pattern-scan file read at 5 MiB; (5) Add single 0–100% progress bar (tqdm) for static analysis.
Reason: Large extensions (e.g. 58 JS files, some 400–600 KiB) caused static analysis to hang at "Extracting configuration values" or run for very long with no feedback. Config extraction read unbounded files whose name contained "config"; esprima/traverse on huge files can hang; unbounded recursion in _traverse_ast is risky. Progress bar gives user visibility (1–100%).
Alternatives considered: Per-file timeout (complex in single-threaded Python), removing config extraction (kept with size cap)
