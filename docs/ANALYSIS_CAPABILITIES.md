# How the Analyzer Detects Malicious Behavior

This document explains **how** the tool analyzes extensions: WebSocket/network, dynamic capture, and taint analysis. It does not define policy; it describes the technical pipeline.

---

## 1. Static analysis (always runs)

- **Pattern scanning** (`static_analyzer.py`): Regex-based detection of dangerous patterns (e.g. `new WebSocket(`, `fetch(`, `chrome.cookies`, credential keys in POST bodies). Uses `scan_code()` with context extraction; on parse/slice errors it falls back to `_scan_code_minimal()` so critical files are still pattern-scanned.
- **AST analysis** (`ast_analyzer.py`): Parses JS with esprima, extracts `fetch`/XHR/WebSocket call sites, resolves config URLs where possible, and classifies network calls and data exfiltration. Feeds into “network_calls” and “data_exfiltration” in results.
- **Taint analysis** (`taint_analyzer.py`): **Static only.** It parses JS (esprima), tracks variables that get values from sensitive **sources** (e.g. `chrome.cookies`, `chrome.storage`, password inputs, `document.cookie`) and checks if they flow into **sinks** (e.g. `fetch`, `XMLHttpRequest`, `WebSocket`, `navigator.sendBeacon`). It does **not** run the extension or see real network traffic; it only infers flows from the code. So:
  - **WebSocket usage in code** → detected by static patterns + AST.
  - **“Does this variable that holds a cookie get sent over the wire?”** → inferred by taint (source → sink) in the static code.

---

## 2. Dynamic network capture (optional, `--dynamic`)

- **When**: Only when you pass the `--dynamic` flag and Playwright is installed.
- **How**: Playwright starts a real Chromium instance with the extension loaded (`--load-extension=...`). The tool then:
  - Injects Chrome API monitoring and uses **Chrome DevTools Protocol (CDP)** to enable `Network.enable` and capture all network events (including WebSockets) from that browser session.
  - Visits a set of **trigger URLs** (and optionally host-permission domains from the manifest) to stimulate the extension (e.g. so background/content scripts run and may open WebSockets or send POSTs).
  - Records every request (URL, method, headers, POST body, resource type) and every WebSocket connection (URL, frames if available).
- **Scoring**: Each request is scored (IP literal, suspicious TLD, JWT/base64 in body, credential-like keys, beacon paths, etc.). WebSockets are scored separately (e.g. non-allowlisted domains, SaaS lookalikes). Beaconing (repeated hits to the same endpoint) and “post-navigation exfil” (requests soon after page load) are detected.
- **Output**: `network_capture` in results: `extension_requests`, `suspicious_connections`, `beaconing`, `post_nav_exfil`, `websocket_connections`, `verdict` (CLEAN / LOW_RISK / SUSPICIOUS / MALICIOUS).

So: **WebSocket and other “live” traffic are analyzed by actually running the extension in a browser and capturing packets via Playwright + CDP**, not by taint alone. Taint is a static hint; dynamic capture is the runtime proof.

---

## 3. Summary table

| Capability              | Mechanism                          | When / Flag      |
|-------------------------|-------------------------------------|------------------|
| WebSocket in code       | Static regex + AST                  | Always            |
| WebSocket at runtime    | Playwright + CDP network capture    | With `--dynamic`  |
| Exfil (fetch/XHR) in code | AST + static patterns + taint   | Always            |
| Exfil at runtime       | Playwright + CDP (POST body, URLs)  | With `--dynamic`  |
| Taint (source→sink)     | Static only (esprima, no execution) | Always (Step 6.5)|

---

## 4. References

- **Network capture**: `src/network_capture.py` (Playwright launch, CDP, scoring, WebSocket list).
- **Taint**: `src/taint_analyzer.py` (sources/sinks, variable tracking); invoked from `src/analyzer.py` in “Step 6.5: Enhanced detection”.
- **Report**: “Dynamic Network Analysis” and “Suspicious WebSocket Connections” in the HTML report use `network_capture` and `advanced_detection` (e.g. `websocket_c2`).
