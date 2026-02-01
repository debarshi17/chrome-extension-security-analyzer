# Phase 12: Delta-Based Risk Monitoring System

**Date:** January 30, 2026  
**Status:** Planning & Architecture Design  
**Goal:** Transition from one-time scans to continuous, update-aware risk scoring

---

## 🎯 Executive Summary

Currently: **Static analysis one-time snapshot**  
Target: **Continuous risk monitoring with delta-based scoring**

Key insight: Don't rescan everything on each update. Score **what changed**.

---

## 📊 Current State (Phases 1-11)

### What We Have ✅
- ✅ Extension downloader + CRX unpacker
- ✅ Static analysis (manifest, permissions, code patterns)
- ✅ AST analysis with config resolution
- ✅ VirusTotal integration with domain age + TLD risk
- ✅ PII classification (10 categories)
- ✅ Advanced malware detection (CSP removal, DOM injection, etc.)
- ✅ Professional HTML reports
- ✅ IOC database (dynamic, validated)
- ✅ Web search threat attribution

### What's Missing ❌
- ❌ Version snapshot storage (to track over time)
- ❌ Structured diff engine (manifest vs code vs behavior)
- ❌ Update detection (polling or webhooks)
- ❌ Delta-based risk scoring (only new signals count)
- ❌ Risk signal tracking ("watch for X next update")
- ❌ Additive risk model with context reductions
- ❌ Update history timeline
- ❌ Trust decay curves (risk increases when old signals reappear)

---

## 🏗️ Phase 12 Architecture

### Proposed Components

```
┌─────────────────────────────────────────────┐
│         Extension ID (from user)            │
└──────────────────┬──────────────────────────┘
                   │
      ┌────────────▼───────────┐
      │  Check Latest Version  │
      │   (Chrome Web Store)   │
      └────────────┬───────────┘
                   │
       ┌───────────▼────────────┐
       │ Version Already Seen?  │
       └───┬──────────────┬─────┘
           │              │
        YES│              │NO
           │              │
    ┌──────▼──┐    ┌──────▼──────────────┐
    │ Skip    │    │ Fetch + Analyze     │
    │ (cached)│    │ New Version         │
    └─────────┘    └─────────┬───────────┘
                            │
              ┌─────────────▼────────────┐
              │  Run Baseline Analysis   │
              │  (Current phases 1-11)   │
              └─────────────┬────────────┘
                            │
              ┌─────────────▼────────────┐
              │  Store Baseline Snapshot │
              │  (v1 → Snapshot DB)      │
              └─────────────┬────────────┘
                            │
                            ▼
                   ┌─────────────────┐
                   │  First Analysis  │
                   │  Complete        │
                   └─────────────────┘

────────────────────────────────────────────

    Next Update Detected (v2 released)
    
              ┌─────────────┐
              │ New Version │
              │ Available   │
              └──────┬──────┘
                     │
         ┌───────────▼────────────┐
         │  Download + Unpack v2  │
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  Generate Snapshot v2  │
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  RUN DIFF ENGINE       │
         │  (v1 snapshot vs v2)   │
         │  Output: Structured    │
         │  diff JSON             │
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  Risk Signal Engine    │
         │  (Rules + LLM)         │
         │  Score new signals     │
         │  Detect false positives│
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  Additive Risk Scoring │
         │  Prev + New - Trusted  │
         └───────────┬────────────┘
                     │
         ┌───────────▼────────────┐
         │  Update Report         │
         │  (with delta section)  │
         └────────────────────────┘
```

---

## 🔧 Core Modules to Build

### 1. **Snapshot Store** (NEW)

**File:** `src/snapshot_manager.py`

Purpose: Store and retrieve per-version analysis fingerprints.

```python
class SnapshotManager:
    """
    Stores immutable snapshots of extension analysis per version.
    Enables time-series risk tracking and delta computation.
    """
    
    def __init__(self, db_path: str = "data/snapshots.db"):
        # SQLite or JSON file-based
        pass
    
    def store_snapshot(
        self, 
        extension_id: str, 
        version: str, 
        analysis_data: dict
    ) -> bool:
        """
        Store a snapshot for later diff.
        
        Snapshot fields:
        - manifest_hash (SHA256)
        - permissions (list)
        - host_permissions (list)
        - content_scripts (list)
        - file_tree (nested dict)
        - ast_fingerprints (per JS file)
        - obfuscation_score (0-100)
        - network_domains (list)
        - dom_sinks (list)
        - network_sinks (list)
        - risk_score (float)
        - risk_verdict (string)
        - analysis_timestamp
        """
        pass
    
    def get_snapshot(
        self,
        extension_id: str,
        version: str
    ) -> Optional[dict]:
        pass
    
    def get_latest_snapshot(
        self,
        extension_id: str
    ) -> Optional[dict]:
        """Get the most recent version snapshot."""
        pass
    
    def list_versions(
        self,
        extension_id: str
    ) -> List[str]:
        """Get all stored versions for this extension."""
        pass
```

### 2. **Diff Engine** (NEW)

**File:** `src/diff_engine.py`

Purpose: Compare two snapshots and produce structured diff.

```python
class DiffEngine:
    """
    Compares two extension snapshots and produces a structured diff.
    
    This is the KEY component for reducing false positives and noise.
    """
    
    def diff(
        self,
        old_snapshot: dict,
        new_snapshot: dict
    ) -> dict:
        """
        Returns:
        {
            "manifest_changes": {
                "permissions_added": ["tabs", "webRequest"],
                "permissions_removed": [],
                "permissions_modified": {},
                "content_scripts_added": [
                    {
                        "matches": ["<all_urls>"],
                        "js": ["inject.js"]
                    }
                ],
                "host_permissions_added": ["<all_urls>"],
                "host_permissions_removed": [],
                "version_changed": ("1.0.0", "1.0.1")
            },
            "code_changes": {
                "new_files": ["inject.js", "config.js"],
                "deleted_files": ["legacy.js"],
                "modified_files": ["background.js"],
                "new_network_sinks": ["fetch", "XMLHttpRequest"],
                "new_dom_access": [
                    "document.getElementById",
                    "element.innerHTML"
                ],
                "new_eval_usage": True,
                "obfuscation_increase": 15  # from 10 to 25
            },
            "behavioral_changes": {
                "new_domains": ["api.example.com"],
                "removed_domains": [],
                "new_content_script_targets": ["<all_urls>"],
                "increased_capability": "can now access all tabs"
            },
            "risk_implications": {
                "capability_expansion": True,
                "reach_expansion": False,
                "data_access_expansion": True
            }
        }
        """
        pass
```

### 3. **Risk Signal Engine** (HYBRID)

**File:** `src/risk_signal_engine.py`

Purpose: Deterministic rules + LLM judgment on diff.

```python
class RiskSignalEngine:
    """
    Two-layer risk analysis:
    1. Fast deterministic rules
    2. LLM context + intent
    """
    
    def analyze_diff(
        self,
        diff: dict,
        previous_risk_score: float,
        analysis_client=None  # Optional contextual analysis
    ) -> dict:
        """
        Returns:
        {
            "new_risk_signals": [
                {
                    "signal": "content_scripts_added",
                    "description": "Extension now injects into all pages",
                    "weight": "high",
                    "base_score_increase": 25,
                    "context": "First content script added"
                },
                {
                    "signal": "dom_access_expanded",
                    "description": "New access to document.cookie",
                    "weight": "medium",
                    "base_score_increase": 15,
                    "context": "Existing DOM access was limited to form fields"
                }
            ],
            "false_positive_assessment": {
                "is_likely_benign": False,
                "benign_scenarios": [
                    "Legitimate feature expansion",
                    "New UI improvements"
                ],
                "confidence": 0.85
            },
            "recommended_next_signals": [
                "Watch for remote config fetch",
                "Monitor network traffic to new domains",
                "Check for time-delayed activation"
            ],
            "llm_analyst_summary": "Update shows significant capability expansion..."
        }
        """
        
        # Layer 1: Deterministic Rules
        signals = self._apply_deterministic_rules(diff)
        
        # Layer 2: LLM Context
        llm_judgment = self._get_llm_judgment(diff, signals)
        
        return {
            "new_risk_signals": signals,
            "false_positive_assessment": llm_judgment,
            "recommended_next_signals": self._generate_watch_list(signals, diff)
        }
    
    def _apply_deterministic_rules(self, diff: dict) -> List[dict]:
        """Hard-coded signal scoring (deterministic)."""
        # Signal weights from earlier design
        signals = []
        
        if "content_scripts" in diff.get("manifest_changes", {}):
            signals.append({
                "signal": "content_scripts_added",
                "weight": "high",
                "base_score": 25
            })
        
        # ... more rules
        
        return signals
    
    def _get_llm_judgment(self, diff: dict, signals: List[dict]) -> dict:
        """Analyze context + intent."""
        # Use production prompt from architecture doc
        pass
```

### 4. **Additive Risk Scoring** (CORE)

**File:** `src/additive_risk_scorer.py`

Purpose: Calculate new total risk using additive model.

```python
class AdditiveRiskScorer:
    """
    Risk model: New Score = Previous + New Signals - Context Reduction
    """
    
    SIGNAL_WEIGHTS = {
        "content_scripts_added": 25,
        "all_urls_added": 30,
        "dom_access_added": 20,
        "dom_network_correlation": 40,
        "tabs_permission_added": 15,
        "obfuscation_increase": 20,
        "remote_config_added": 30,
        "first_to_third_party_shift": 25,
    }
    
    CONTEXT_REDUCTIONS = {
        "verified_publisher": -5,
        "known_library": -10,
        "first_party_only": -15,
        "update_log_transparency": -3,
    }
    
    SEVERITY_BANDS = {
        (0, 19): "Low",
        (20, 39): "Medium",
        (40, 69): "High",
        (70, 100): "Critical"
    }
    
    def calculate_new_score(
        self,
        previous_score: float,
        new_signals: List[dict],
        context_factors: dict
    ) -> dict:
        """
        Returns:
        {
            "previous_score": 25.0,
            "signal_additions": [
                {"signal": "content_scripts_added", "points": 25},
                {"signal": "tabs_permission_added", "points": 15}
            ],
            "total_additions": 40,
            "context_reductions": [
                {"factor": "verified_publisher", "reduction": -5}
            ],
            "total_reductions": -5,
            "new_score": 60.0,  # 25 + 40 - 5
            "severity_band": "High",
            "score_change_reason": "Significant capability expansion + new network access"
        }
        """
        pass
```

---

## 🎯 Risk Signals to Watch (Operationalized)

Reference table from architecture:

| Signal Introduced in Update | Base Score | When to Alert |
|-----|------|-----|
| `content_scripts` added | +25 | First time ever |
| `<all_urls>` added | +30 | Expands from specific domains |
| DOM access added | +20 | New types of access |
| DOM + network correlation | +40 | Both added together |
| `tabs` permission added | +15 | Access to all tabs |
| Obfuscation increase | +20 | >15 point jump |
| Remote config / fetch added | +30 | Enables remote control |
| First-party → third-party shift | +25 | Starts talking to external servers |
| Code size increase | +10 | >50% increase (could be obfuscation) |
| Eval usage added | +25 | Dynamic code execution |

**Context Reductions:**
- Verified publisher: −5
- Known library (jQuery, React, etc.): −10
- First-party domain only: −15
- Update log shows transparency: −3

---

## 🚀 Implementation Roadmap

### Phase 12.1: Snapshot Store (Week 1)
- [ ] Design SQLite schema
- [ ] Implement `SnapshotManager`
- [ ] Integrate into current `analyzer.py` (store snapshot after each analysis)
- [ ] Test: Run baseline scan, verify snapshot stored

### Phase 12.2: Diff Engine (Week 2)
- [ ] Implement manifest diff logic
- [ ] Implement file tree diff
- [ ] Implement AST fingerprint comparison
- [ ] Test: Create two versions, verify diff accuracy

### Phase 12.3: Risk Signal Engine (Week 2-3)
- [ ] Implement deterministic rules
- [ ] Integrate contextual judgment engine
- [ ] Add false positive detection
- [ ] Generate "watch list" recommendations

### Phase 12.4: Additive Risk Scoring (Week 3)
- [ ] Implement signal + context calculation
- [ ] Create severity bands
- [ ] Integrate into report generation

### Phase 12.5: Update Detection (Week 4)
- [ ] Chrome Web Store version polling
- [ ] Webhook support (optional)
- [ ] Automatic re-analysis on new version

### Phase 12.6: Report Updates (Week 4)
- [ ] Add "Update History" section to HTML report
- [ ] Add "Delta Analysis" panel
- [ ] Timeline visualization

---

## 💾 Database Schema (SQLite)

### snapshots table

```sql
CREATE TABLE snapshots (
    id INTEGER PRIMARY KEY,
    extension_id TEXT NOT NULL,
    version TEXT NOT NULL,
    manifest_hash TEXT,
    analysis_data JSON,
    risk_score REAL,
    risk_verdict TEXT,
    created_at TIMESTAMP,
    
    UNIQUE(extension_id, version)
);

CREATE INDEX idx_ext_version ON snapshots(extension_id, version);
CREATE INDEX idx_ext_created ON snapshots(extension_id, created_at);
```

### updates table

```sql
CREATE TABLE updates (
    id INTEGER PRIMARY KEY,
    extension_id TEXT NOT NULL,
    from_version TEXT,
    to_version TEXT,
    delta_data JSON,
    new_signals JSON,
    risk_score_previous REAL,
    risk_score_new REAL,
    detected_at TIMESTAMP,
    analyzed_at TIMESTAMP
);
```

---

## 📝 Production LLM Prompt (Ready to Use)

**File:** `src/prompts/delta_risk_analysis.md`

```
You are a security analyst specializing in browser extension supply-chain risk.

You are given:
1. A **previous safe version** of a Chrome extension
2. A **newly released update**
3. A **structured diff** showing only what changed

Your task is to assess **newly introduced risk**, not re-evaluate the entire extension.

### Structured Diff Provided:
[DIFF_JSON_HERE]

### Instructions:

- Identify **new risk signals introduced in this update**
- Ignore behaviors that already existed in the previous version
- Focus on **capability expansion** (e.g., new reach, new data access, new sinks)
- Explicitly consider **false-positive scenarios** such as:
  - Legitimate feature expansion
  - Known third-party libraries
  - First-party-only network traffic
  - Update log shows legitimate changelog

### For each new risk signal:
- Describe the behavior
- Explain why it increases risk
- Assign a risk weight: low / medium / high

### Output Format (JSON):

{
  "new_risk_signals": [
    {
      "signal": "string",
      "description": "string",
      "weight": "low|medium|high",
      "reasoning": "string"
    }
  ],
  "false_positive_assessment": {
    "likely_benign": true/false,
    "confidence": 0.0-1.0,
    "benign_scenarios": ["string"]
  },
  "verdict": "benign_update|suspicious_monitor|high_risk|potentially_malicious",
  "summary": "string"
}

Be conservative, explain reasoning clearly, and avoid declaring malware unless justified by behavior change.
```

---

## ✅ Success Criteria

By end of Phase 12:

- ✅ Can store extension versions
- ✅ Can diff two versions
- ✅ Can score new signals only (not re-scan noise)
- ✅ Reduces false positives 50%+ compared to Phase 11
- ✅ Can detect when old malicious signals return
- ✅ Report shows update history + delta
- ✅ Can generate "watch for X next update" list
- ✅ Scales to monitoring 100+ extensions over time

---

## 🔗 Integration Points

### Into Existing Code:

1. **analyzer.py**: After Phase 1-11 analysis, call `snapshot_manager.store_snapshot()`
2. **professional_report.py**: Add new "Update History" section
3. **store_metadata.py**: Fetch current version, trigger diff if changed
4. **New CLI flag**: `--monitor` (continuous polling) vs `--analyze` (one-time)

### New Dependencies:

```
sqlite3  # Built-in
```

---

## 🎓 Why This Matters

**Current limitation (Phase 11):**
> Extension analyzed on Day 1 as "Medium risk"
> Extension updated on Day 5 with malicious content script
> User never knows (one-time scan)

**After Phase 12:**
> Day 1: Baseline = "Medium risk" (snapshot stored)
> Day 5: Update detected → diff → "New content_script + <all_urls> = +30 risk"
> Day 5: New score = 55 (HIGH) → **Alert user immediately**

This is the production-grade approach.

---

**Next Session:** Ready to implement Phase 12.1?
