"""
Report Validator — Automated "Bablu Review"

Fetches the last N analyzed extensions, cross-references every finding with
the actual extension source code, and classifies each as:
  TRUE_POSITIVE  — finding is real and the code confirms malicious intent
  FALSE_POSITIVE — finding is noise (library code, polyfill, comment, filter rule)
  NEEDS_REVIEW   — ambiguous, requires human judgment

Produces a per-extension validation summary + aggregate quality metrics.

Usage:
    python report_validator.py              # validate last 10
    python report_validator.py --count 5    # validate last 5
    python report_validator.py --id <ext>   # validate one extension
"""

import json
import re
import sys
import argparse
from pathlib import Path
from datetime import datetime


# ─────────────────────────────────────────────────────────────────────
# Known false-positive patterns
# ─────────────────────────────────────────────────────────────────────

# Webpack / library polyfills that trigger "Dynamic Function Creation"
_WEBPACK_GLOBAL_THIS = re.compile(
    r"""new\s+Function\s*\(\s*['"]return\s+this['"]\s*\)""", re.IGNORECASE
)

# reflect-metadata / lodash / library patterns that trigger "Keystroke Buffer Array"
_BENIGN_KEYS_ARRAY = re.compile(
    r'(ownKeys|metadataKeys|objectKeys|Object\.keys|getOwnPropertyNames)',
    re.IGNORECASE,
)

# idb library wrapper that triggers "IndexedDB Data Harvesting"
_IDB_LIBRARY_PATTERN = re.compile(
    r'(function\s+openDB|idb|indexedDB\.open\s*\(\s*name)',
    re.IGNORECASE,
)

# Standard chrome.storage.sync usage (settings, analytics user ID)
_BENIGN_STORAGE_KEYS = re.compile(
    r'(analyticsUserid|panalyticsUserid|settings|preferences|config|options|theme|'
    r'enabled|disabled|whitelist|blocklist|language|locale|version|installDate|'
    r'onboarding|tutorial|firstRun|lastSync)',
    re.IGNORECASE,
)

# JS line comment or block comment detection
_LINE_COMMENT = re.compile(r'^\s*//')
_BLOCK_COMMENT_START = re.compile(r'/\*')
_BLOCK_COMMENT_END = re.compile(r'\*/')

# Filter rule file extensions
_FILTER_EXTENSIONS = {'.txt', '.lst', '.rules'}

# Known benign domains (CDN, documentation, standards)
_BENIGN_DOMAIN_PATTERNS = re.compile(
    r'(apache\.org|w3\.org|mozilla\.org|chromium\.org|github\.com|'
    r'googleapis\.com|gstatic\.com|cloudflare\.com|jquery\.com|'
    r'npmjs\.org|unpkg\.com|cdnjs\.cloudflare\.com|'
    r'movable-type\.co\.uk|creativecommons\.org|python\.org|'
    r'opensource\.org|blueimp\.net|pajhome\.org\.uk|'
    r'webpack\.js\.org|nodejs\.org|ecma-international\.org|'
    r'developer\.chrome\.com|docs\.google\.com|microsoft\.com)',
    re.IGNORECASE,
)

# Patterns indicating actual malicious data flow (for TP classification)
_MALICIOUS_EXFIL_PATTERN = re.compile(
    r'(fetch|XMLHttpRequest|sendBeacon|\.send\s*\()[\s\S]{0,300}'
    r'(document\.cookie|password|credential|chrome\.cookies|session|token)',
    re.IGNORECASE,
)

_MALICIOUS_C2_PATTERN = re.compile(
    r'(WebSocket|new\s+WebSocket|wss?://[\w.-]+)',
    re.IGNORECASE,
)

_MALICIOUS_KEYLOGGER_PATTERN = re.compile(
    r'addEventListener\s*\(\s*["\']key(down|up|press)["\']',
    re.IGNORECASE,
)

_MALICIOUS_COOKIE_THEFT = re.compile(
    r'(document\.cookie|chrome\.cookies\.get)',
    re.IGNORECASE,
)


class ReportValidator:
    """Automated finding validator — the 'Bablu review' engine."""

    def __init__(self, base_dir=None):
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent
        self.reports_dir = self.base_dir / 'reports'
        self.extensions_dir = self.base_dir / 'data' / 'extensions'
        # Cache for file contents
        self._file_cache = {}

    # ── Public API ───────────────────────────────────────────────────

    def validate_last_n(self, n=10):
        """Validate the last N analyzed extensions. Returns list of validation results."""
        jsons = sorted(
            self.reports_dir.glob('*_analysis.json'),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
        results = []
        for jpath in jsons[:n]:
            ext_id = jpath.name.replace('_analysis.json', '')
            try:
                result = self.validate_extension(ext_id, jpath)
                results.append(result)
            except Exception as e:
                results.append({
                    'extension_id': ext_id,
                    'error': str(e),
                    'findings': [],
                })
        return results

    def validate_extension(self, ext_id, json_path=None):
        """Validate a single extension's analysis against its source code."""
        if json_path is None:
            json_path = self.reports_dir / f'{ext_id}_analysis.json'

        analysis = json.loads(json_path.read_text(encoding='utf-8'))
        ext_dir = self.extensions_dir / ext_id

        has_source = ext_dir.is_dir() and any(ext_dir.rglob('*.js'))
        is_attributed = bool(analysis.get('threat_attribution', {}).get('source_articles'))
        risk_score = analysis.get('risk_score', 0)
        risk_level = analysis.get('risk_level', 'UNKNOWN')
        name = analysis.get('name', ext_id)

        # Validate each finding category
        pattern_validations = self._validate_malicious_patterns(analysis, ext_dir, has_source)
        domain_validations = self._validate_domains(analysis, ext_dir, has_source)
        vt_validations = self._validate_vt_results(analysis)
        behavioral_validations = self._validate_behavioral_correlations(analysis, pattern_validations)

        all_findings = pattern_validations + domain_validations + vt_validations + behavioral_validations

        # Deduplicate findings for counting: group by (verdict, finding_name)
        # so 50x "localStorage Access FP" counts once, not 50 times
        deduped_map = {}  # (verdict, name_prefix) -> finding
        for f in all_findings:
            key = (f['verdict'], f['finding_name'][:60])
            if key not in deduped_map:
                deduped_map[key] = {**f, '_count': 1}
            else:
                deduped_map[key]['_count'] += 1

        deduped_findings = list(deduped_map.values())

        tp = sum(1 for f in deduped_findings if f['verdict'] == 'TRUE_POSITIVE')
        fp = sum(1 for f in deduped_findings if f['verdict'] == 'FALSE_POSITIVE')
        nr = sum(1 for f in deduped_findings if f['verdict'] == 'NEEDS_REVIEW')
        total = len(deduped_findings)

        return {
            'extension_id': ext_id,
            'name': name,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'has_source': has_source,
            'is_threat_attributed': is_attributed,
            'total_findings': total,
            'total_findings_raw': len(all_findings),
            'true_positives': tp,
            'false_positives': fp,
            'needs_review': nr,
            'fp_rate': round(fp / total * 100, 1) if total else 0,
            'findings': deduped_findings,
        }

    # ── Malicious pattern validation ────────────────────────────────

    def _validate_malicious_patterns(self, analysis, ext_dir, has_source):
        """Check each malicious_pattern finding against actual source code."""
        results = []
        for pat in analysis.get('malicious_patterns', []):
            result = self._validate_one_pattern(pat, ext_dir, has_source)
            results.append(result)
        return results

    def _validate_one_pattern(self, pat, ext_dir, has_source):
        """Validate a single malicious pattern finding."""
        name = pat.get('name', '')
        severity = pat.get('severity', 'unknown')
        file_path = pat.get('file', '')
        line = pat.get('line', 0)
        context = pat.get('context', '') or pat.get('evidence', '')
        technique = pat.get('technique', '')

        verdict = 'NEEDS_REVIEW'
        reason = 'No source available for verification'

        if not has_source:
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # Read the code context around the finding
        code_context = self._read_context(ext_dir, file_path, line, window=30)

        # ── Check: Webpack globalThis polyfill ──
        if 'new function' in name.lower() or 'dynamic function' in name.lower():
            if code_context and _WEBPACK_GLOBAL_THIS.search(code_context):
                verdict = 'FALSE_POSITIVE'
                reason = 'Webpack globalThis polyfill: new Function("return this")()'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Keystroke Buffer Array (var keys = []) ──
        if 'keystroke' in name.lower() or 'keylog' in name.lower():
            if code_context:
                has_key_event = bool(re.search(
                    r'addEventListener\s*\(\s*["\']key(down|up|press)["\']',
                    code_context, re.IGNORECASE
                ))
                has_library_ctx = bool(_BENIGN_KEYS_ARRAY.search(code_context))
                if has_library_ctx and not has_key_event:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Library code (reflect-metadata/lodash) -- "keys" array is metadata keys, not keystrokes'
                elif has_key_event:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Keyboard event listener found near keystroke buffer'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Array named "keys" without clear keyboard or library context'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Chrome Storage Sync ──
        if 'storage sync' in name.lower() or 'chrome.storage.sync' in (context or '').lower():
            if code_context:
                is_benign = bool(_BENIGN_STORAGE_KEYS.search(code_context))
                has_sensitive = bool(re.search(
                    r'(password|credential|cookie|token|session|auth|credit|card)',
                    code_context, re.IGNORECASE,
                ))
                if is_benign and not has_sensitive:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Stores analytics/settings data, not credentials'
                elif has_sensitive:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Sensitive data keywords found near chrome.storage.sync'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'chrome.storage.sync usage -- data type unclear'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: IndexedDB ──
        if 'indexeddb' in name.lower():
            if code_context and _IDB_LIBRARY_PATTERN.search(code_context):
                verdict = 'FALSE_POSITIVE'
                reason = 'idb library wrapper (standard Promise-based IndexedDB), not data harvesting'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Credit card targeting ──
        if 'credit card' in name.lower() or 'financial' in name.lower():
            if code_context:
                has_input_targeting = bool(re.search(
                    r'(autocomplete.*cc-|name.*card|type.*credit|getElementById.*card|'
                    r'querySelector.*\[.*card|input.*credit)',
                    code_context, re.IGNORECASE,
                ))
                if not has_input_targeting:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'No actual DOM input field targeting found -- pattern matched data structure or filter rules'
                else:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Actual credit card input field targeting detected'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: __proto__ / prototype reference ──
        if '__proto__' in name.lower() or 'prototype' in name.lower():
            verdict = 'FALSE_POSITIVE'
            reason = 'Prototype reference is standard JS -- common in polyfills and libraries'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: localStorage access ──
        if 'localstorage' in name.lower() and severity == 'low':
            verdict = 'FALSE_POSITIVE'
            reason = 'localStorage access is a standard API used by most extensions'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Tab URL access (informational) ──
        if 'tab url' in name.lower() or 'tab.url' in name.lower():
            if severity == 'low':
                verdict = 'FALSE_POSITIVE'
                reason = 'Tab URL access is standard for ad blockers and navigation-aware extensions'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: CSRF Token Extraction ──
        if 'csrf' in name.lower() or 'token extraction' in name.lower():
            if code_context:
                has_dom_read = bool(re.search(
                    r'(querySelector|getElementById|getAttribute|\.value|\.content)',
                    code_context, re.IGNORECASE
                ))
                has_exfil = bool(re.search(
                    r'(fetch|XMLHttpRequest|sendBeacon|\.send\s*\()',
                    code_context, re.IGNORECASE
                ))
                if has_dom_read and has_exfil:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'CSRF token read + network send in context -- potential token theft'
                else:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'CSRF token reference without exfiltration context -- standard form handling'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Input Value Direct Access ──
        if 'input value' in name.lower():
            if code_context:
                has_sensitive_field = bool(re.search(
                    r'(password|credit|card|ssn|cvv|expiry|login|auth)',
                    code_context, re.IGNORECASE
                ))
                has_exfil = bool(re.search(
                    r'(fetch|XMLHttpRequest|sendBeacon|\.send\s*\()',
                    code_context, re.IGNORECASE
                ))
                if has_sensitive_field and has_exfil:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Sensitive input field access + network send detected'
                elif has_sensitive_field:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Sensitive input field access -- verify if data is exfiltrated'
                else:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Generic .value access -- standard form/UI handling'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Unicode Escape Obfuscation ──
        if 'unicode escape' in name.lower():
            if code_context:
                # Check if it's near i18n / locale context
                has_i18n = bool(re.search(
                    r'(locale|i18n|intl|translate|lang|__\(|getMessage)',
                    code_context, re.IGNORECASE
                ))
                has_eval = bool(re.search(
                    r'(eval|Function\s*\(|setTimeout\s*\(\s*["\'])',
                    code_context, re.IGNORECASE
                ))
                if has_i18n and not has_eval:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Unicode escapes in i18n/locale context -- internationalization, not obfuscation'
                elif has_eval:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Unicode escapes near eval/Function -- likely code obfuscation'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Unicode escape sequences -- verify if obfuscation or i18n'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: WebAssembly ──
        if 'webassembly' in name.lower() or 'wasm' in name.lower():
            if code_context:
                has_mining = bool(re.search(
                    r'(hash|mine|coin|pool|stratum|cryptonight|monero)',
                    code_context, re.IGNORECASE
                ))
                if has_mining:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'WebAssembly with crypto-mining indicators'
                else:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'WebAssembly without crypto-mining indicators -- likely legitimate computation'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Comment-Based Code Hiding ──
        if 'comment-based' in name.lower() or 'comment.*hiding' in name.lower():
            if code_context:
                # Check if in minified file (very long lines)
                lines = code_context.split('\n')
                avg_line_len = sum(len(l) for l in lines) / max(len(lines), 1)
                if avg_line_len > 500:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Comment pattern in minified code -- artifact of minification, not code hiding'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Comment near eval/Function -- verify if comments hide executable code'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Headless Browser Detection ──
        if 'headless' in name.lower() or 'automation detection' in name.lower():
            if code_context:
                has_webdriver = bool(re.search(r'navigator\.webdriver', code_context))
                has_phantom = bool(re.search(r'(phantom|selenium|puppeteer)', code_context, re.IGNORECASE))
                if has_webdriver and not has_phantom:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'navigator.webdriver check -- anti-fingerprinting or anti-analysis'
                elif has_phantom:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Headless browser detection (phantom/selenium/puppeteer) -- anti-analysis behavior'
                else:
                    verdict = 'FALSE_POSITIVE'
                    reason = 'Automation detection keyword without clear anti-analysis context'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: DevTools Detection ──
        if 'devtools' in name.lower():
            verdict = 'NEEDS_REVIEW'
            reason = 'DevTools detection -- anti-analysis if paired with behavior change, else benign'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: VT file hash match ──
        if 'virustotal file hash' in name.lower():
            verdict = 'TRUE_POSITIVE'
            reason = 'VirusTotal file hash detection -- definitive if vendor count >= 3'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Data Exfiltration via POST ──
        if 'exfiltration' in name.lower() or 'data.*post' in name.lower():
            if code_context:
                has_sensitive_source = bool(re.search(
                    r'(document\.cookie|chrome\.cookies|password|credential|session)',
                    code_context, re.IGNORECASE
                ))
                if has_sensitive_source:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Data exfiltration with sensitive data source (cookies/credentials/session)'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'POST exfiltration -- verify data sensitivity and destination'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Cookie Theft ──
        if 'cookie theft' in name.lower() or 'cookie access' in name.lower():
            if code_context:
                has_exfil = bool(re.search(
                    r'(fetch|XMLHttpRequest|sendBeacon|\.send\s*\(|WebSocket)',
                    code_context, re.IGNORECASE
                ))
                if has_exfil:
                    verdict = 'TRUE_POSITIVE'
                    reason = 'Cookie access with nearby network send -- session theft'
                else:
                    verdict = 'NEEDS_REVIEW'
                    reason = 'Cookie access without nearby exfiltration -- verify context'
                return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: WebSocket ──
        if 'websocket' in name.lower():
            verdict = 'NEEDS_REVIEW'
            reason = 'WebSocket connection -- potential C2 channel, verify destination'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Fetch POST ──
        if 'fetch post' in name.lower() and severity == 'low':
            verdict = 'NEEDS_REVIEW'
            reason = 'Fetch POST is common; only malicious if destination is suspicious'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: executeScript injection ──
        if 'executescript' in name.lower() or 'remote script injection' in name.lower():
            verdict = 'NEEDS_REVIEW'
            reason = 'executeScript is used by ad blockers legitimately but also by malware for injection'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # ── Check: Chrome alarms ──
        if 'alarm' in name.lower() and 'heartbeat' in name.lower():
            verdict = 'NEEDS_REVIEW'
            reason = 'Alarms/timers are used by ad blockers for filter updates but also by C2 beacons'
            return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

        # Default: anything with severity critical/high that we didn't catch
        if severity in ('critical', 'high'):
            verdict = 'NEEDS_REVIEW'
            reason = 'Unhandled high-severity pattern -- manual review needed'
        else:
            verdict = 'NEEDS_REVIEW'
            reason = 'Pattern not covered by automated FP checks'

        return self._finding(name, severity, file_path, line, verdict, reason, 'pattern')

    # ── Domain validation ───────────────────────────────────────────

    def _validate_domains(self, analysis, ext_dir, has_source):
        """Check if extracted domains are from real code or from comments/filter rules."""
        results = []
        if not has_source:
            return results

        for item in analysis.get('urls_in_code', []):
            host = item.get('host', '')
            file_path = item.get('file', '')
            line = item.get('line', 0)
            if not host:
                continue

            # Only validate a sample (first 20) to avoid huge output
            if len(results) >= 20:
                break

            verdict, reason = self._check_domain_in_source(host, file_path, line, ext_dir)
            results.append(self._finding(
                f'Domain: {host}', 'info', file_path, line, verdict, reason, 'domain'
            ))

        return results

    def _check_domain_in_source(self, host, file_path, line, ext_dir):
        """Check if a domain appears in actual code vs comment vs filter rule."""
        # Check if it's from a filter rule file
        if file_path:
            ext = Path(file_path).suffix.lower()
            if ext in _FILTER_EXTENSIONS:
                return 'FALSE_POSITIVE', f'Domain extracted from filter rule file ({file_path})'

        # Check if it's a known benign domain
        if _BENIGN_DOMAIN_PATTERNS.search(host):
            return 'FALSE_POSITIVE', f'Known benign domain (documentation/CDN/standard)'

        # Read the line and check if it's in a comment
        code_line = self._read_line(ext_dir, file_path, line)
        if code_line:
            stripped = code_line.strip()
            if stripped.startswith('//') or stripped.startswith('*') or stripped.startswith('/*'):
                return 'FALSE_POSITIVE', f'Domain appears inside a code comment'

        return 'NEEDS_REVIEW', 'Domain in code -- verify if it is a real C2/exfil endpoint'

    # ── VT results validation ───────────────────────────────────────

    def _validate_vt_results(self, analysis):
        """Check VT domain results for low-confidence detections."""
        results = []
        for vt in analysis.get('virustotal_results', []):
            if not vt.get('known'):
                continue
            domain = vt.get('domain', '')
            threat_level = vt.get('threat_level', 'CLEAN')
            stats = vt.get('stats', {})
            mal_count = stats.get('malicious', 0)
            sus_count = stats.get('suspicious', 0)

            if threat_level == 'MALICIOUS' and mal_count <= 1:
                verdict = 'FALSE_POSITIVE'
                reason = f'Only {mal_count} vendor(s) flagged -- below noise threshold (need >= 3)'
            elif threat_level == 'MALICIOUS' and mal_count >= 5:
                verdict = 'TRUE_POSITIVE'
                reason = f'{mal_count} vendors flagged -- strong consensus'
            elif threat_level == 'MALICIOUS' and mal_count >= 3:
                verdict = 'NEEDS_REVIEW'
                reason = f'{mal_count} vendors flagged -- moderate signal, verify manually'
            elif threat_level == 'SUSPICIOUS':
                verdict = 'NEEDS_REVIEW'
                reason = f'Suspicious ({sus_count} flags) -- not definitive'
            else:
                continue  # Skip clean domains

            results.append(self._finding(
                f'VT Domain: {domain}', 'high' if mal_count >= 3 else 'medium',
                '', 0, verdict, reason, 'virustotal'
            ))

        # Also check file hash VT results
        for vt_f in analysis.get('virustotal_file_results', []):
            if vt_f.get('threat_level') == 'MALICIOUS':
                mal = vt_f.get('stats', {}).get('malicious', 0)
                fname = vt_f.get('filename', vt_f.get('hash', '')[:16])
                if mal <= 1:
                    verdict = 'NEEDS_REVIEW'
                    reason = f'File hash flagged by only {mal} vendor -- low confidence'
                else:
                    verdict = 'TRUE_POSITIVE'
                    reason = f'File hash flagged by {mal} vendors -- confirmed malware'
                results.append(self._finding(
                    f'VT File Hash: {fname}', 'critical', fname, 0, verdict, reason, 'virustotal'
                ))

        return results

    # ── Behavioral correlation validation ───────────────────────────

    def _validate_behavioral_correlations(self, analysis, pattern_validations):
        """Check if behavioral correlations are based on FP findings."""
        results = []
        correlations = analysis.get('behavioral_correlations', {}).get('correlations', [])

        # Build a set of FP finding names
        fp_names = set()
        for pv in pattern_validations:
            if pv['verdict'] == 'FALSE_POSITIVE':
                fp_names.add(pv['finding_name'].lower())

        # Build a set of TP finding names
        tp_names = set()
        for pv in pattern_validations:
            if pv['verdict'] == 'TRUE_POSITIVE':
                tp_names.add(pv['finding_name'].lower())

        for corr in correlations:
            corr_name = corr.get('name', '')
            confidence = corr.get('confidence', '')
            evidence = corr.get('evidence', '')

            # Check if the correlation is built on FP findings
            evidence_lower = (evidence or '').lower()
            relies_on_fp = False
            fp_evidence = []
            relies_on_tp = False
            tp_evidence = []

            if 'keystroke' in evidence_lower and any('keystroke' in fp for fp in fp_names):
                relies_on_fp = True
                fp_evidence.append('keystroke buffer (FP)')
            if 'credential' in evidence_lower and any('storage sync' in fp for fp in fp_names):
                relies_on_fp = True
                fp_evidence.append('chrome storage sync (FP)')
            if 'dynamic code' in evidence_lower and any('dynamic function' in fp or 'new function' in fp for fp in fp_names):
                relies_on_fp = True
                fp_evidence.append('dynamic function (FP)')

            # Check if correlation relies on TP findings
            if 'cookie' in evidence_lower and any('cookie' in tp for tp in tp_names):
                relies_on_tp = True
                tp_evidence.append('cookie theft (TP)')
            if 'exfiltration' in evidence_lower and any('exfiltration' in tp for tp in tp_names):
                relies_on_tp = True
                tp_evidence.append('data exfiltration (TP)')
            if 'credit card' in evidence_lower and any('credit card' in tp for tp in tp_names):
                relies_on_tp = True
                tp_evidence.append('credit card targeting (TP)')

            if relies_on_tp:
                verdict = 'TRUE_POSITIVE'
                reason = f'Correlation supported by confirmed findings: {", ".join(tp_evidence)}'
            elif relies_on_fp:
                verdict = 'FALSE_POSITIVE'
                reason = f'Correlation built on FP findings: {", ".join(fp_evidence)}'
            else:
                verdict = 'NEEDS_REVIEW'
                reason = f'Correlation evidence not directly tied to known FP or TP patterns'

            results.append(self._finding(
                f'Behavioral: {corr_name}', corr.get('severity', 'high'),
                '', 0, verdict, reason, 'behavioral'
            ))

        return results

    # ── Helpers ──────────────────────────────────────────────────────

    def _read_context(self, ext_dir, file_path, line, window=30):
        """Read ~window lines around the given line from the extension file."""
        if not file_path or not ext_dir.is_dir():
            return ''
        # Try multiple path resolutions
        candidates = [
            ext_dir / file_path,
            ext_dir / file_path.replace('\\', '/'),
        ]
        # The file_path might be like "service_worker\index.js" or "content\index.js"
        for candidate in candidates:
            if candidate.is_file():
                return self._read_file_lines(candidate, line, window)
        # Try fuzzy match by filename
        fname = Path(file_path).name
        for f in ext_dir.rglob(fname):
            if f.is_file():
                return self._read_file_lines(f, line, window)
        return ''

    def _read_line(self, ext_dir, file_path, line):
        """Read a single line from a file."""
        ctx = self._read_context(ext_dir, file_path, line, window=0)
        if ctx:
            lines = ctx.split('\n')
            return lines[0] if lines else ''
        return ''

    def _read_file_lines(self, fpath, center_line, window):
        """Read file and return lines around center_line."""
        key = str(fpath)
        if key not in self._file_cache:
            try:
                self._file_cache[key] = fpath.read_text(encoding='utf-8', errors='ignore')
            except Exception:
                return ''
        content = self._file_cache[key]
        lines = content.split('\n')
        start = max(0, center_line - window - 1)
        end = min(len(lines), center_line + window)
        return '\n'.join(lines[start:end])

    def _finding(self, name, severity, file_path, line, verdict, reason, category):
        return {
            'finding_name': name,
            'severity': severity,
            'file': file_path,
            'line': line,
            'verdict': verdict,
            'reason': reason,
            'category': category,
        }

    # ── Report generation ───────────────────────────────────────────

    @staticmethod
    def print_summary(validations):
        """Print a readable summary of all validation results."""
        print('\n' + '=' * 90)
        print('  AUTOMATED FINDING VALIDATION REPORT -- "Bablu Review"')
        print('=' * 90)
        print(f'  Extensions reviewed: {len(validations)}')
        print(f'  Generated: {datetime.now().strftime("%Y-%m-%d %H:%M")}')
        print('=' * 90)

        total_tp = total_fp = total_nr = total_all = 0

        for v in validations:
            ext_id = v.get('extension_id', '?')
            name = v.get('name', ext_id)

            if 'error' in v:
                print(f'\n  [{ext_id[:12]}..] {name}')
                print(f'    ERROR: {v["error"]}')
                continue

            tp = v['true_positives']
            fp = v['false_positives']
            nr = v['needs_review']
            total = v['total_findings']
            raw_total = v.get('total_findings_raw', total)
            fp_rate = v['fp_rate']
            risk = v['risk_score']
            level = v['risk_level']
            attributed = v['is_threat_attributed']
            has_src = v['has_source']

            total_tp += tp
            total_fp += fp
            total_nr += nr
            total_all += total

            # Color-code: attributed extensions should have high TP
            tag = '[ATTRIBUTED]' if attributed else '[UNATTRIBUTED]'
            src_tag = '[source]' if has_src else '[no source]'

            print(f'\n  [{ext_id[:20]}] {name}')
            print(f'    Risk: {risk}/10 ({level}) | {tag} | {src_tag}')
            dedup_note = f' (deduped from {raw_total} raw)' if raw_total != total else ''
            print(f'    Findings: {total} unique{dedup_note} | [TP] {tp} | [FP] {fp} | [?] {nr} | FP Rate: {fp_rate}%')

            # Show FP details (top 5)
            fps = [f for f in v['findings'] if f['verdict'] == 'FALSE_POSITIVE']
            if fps:
                print(f'    False Positives:')
                for f in fps[:5]:
                    count = f.get('_count', 1)
                    count_str = f' ({count}x)' if count > 1 else ''
                    print(f'      [FP] {f["finding_name"][:55]}{count_str} -- {f["reason"][:75]}')
                if len(fps) > 5:
                    print(f'      ... and {len(fps) - 5} more')

            # Show TP details (top 5)
            tps = [f for f in v['findings'] if f['verdict'] == 'TRUE_POSITIVE']
            if tps:
                print(f'    True Positives:')
                for f in tps[:5]:
                    count = f.get('_count', 1)
                    count_str = f' ({count}x)' if count > 1 else ''
                    print(f'      [TP] {f["finding_name"][:55]}{count_str} -- {f["reason"][:75]}')

            # Quality assessment
            if attributed and fp_rate > 50:
                print(f'    [!] WARNING: Attributed malware but {fp_rate}% FP rate -- detection engine needs tuning')
            elif not attributed and fp_rate < 20 and risk >= 7:
                print(f'    [!] ATTENTION: High risk, low FP rate, no attribution -- possible missed threat intel')
            elif not attributed and fp_rate > 70:
                print(f'    [i] LIKELY BENIGN: {fp_rate}% FP rate with no attribution -- consider lowering risk')

        # Aggregate stats
        print('\n' + '=' * 90)
        print('  AGGREGATE QUALITY METRICS')
        print('=' * 90)
        if total_all:
            print(f'  Total unique findings across all extensions: {total_all}')
            print(f'  True Positives:  {total_tp} ({round(total_tp/total_all*100,1)}%)')
            print(f'  False Positives: {total_fp} ({round(total_fp/total_all*100,1)}%)')
            print(f'  Needs Review:    {total_nr} ({round(total_nr/total_all*100,1)}%)')
            print(f'  Overall FP Rate: {round(total_fp/total_all*100,1)}%')

            attributed_exts = [v for v in validations if v.get('is_threat_attributed')]
            benign_exts = [v for v in validations if not v.get('is_threat_attributed') and 'error' not in v]

            if attributed_exts:
                attr_tp = sum(v['true_positives'] for v in attributed_exts)
                attr_total = sum(v['total_findings'] for v in attributed_exts)
                print(f'\n  Attributed malware ({len(attributed_exts)} exts):')
                print(f'    TP rate: {round(attr_tp/attr_total*100,1) if attr_total else 0}% -- '
                      f'{"GOOD" if attr_total and attr_tp/attr_total > 0.3 else "NEEDS IMPROVEMENT"}')

            if benign_exts:
                ben_fp = sum(v['false_positives'] for v in benign_exts)
                ben_total = sum(v['total_findings'] for v in benign_exts)
                print(f'  Unattributed exts ({len(benign_exts)} exts):')
                print(f'    FP rate: {round(ben_fp/ben_total*100,1) if ben_total else 0}% -- '
                      f'{"GOOD (< 40%)" if ben_total and ben_fp/ben_total < 0.4 else "TOO NOISY"}')
        else:
            print('  No findings to analyze.')

        print('\n' + '=' * 90)

    @staticmethod
    def save_json_report(validations, output_path):
        """Save the full validation results as JSON."""
        report = {
            'generated': datetime.now().isoformat(),
            'extensions_reviewed': len(validations),
            'results': validations,
        }
        Path(output_path).write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding='utf-8')
        print(f'\n[+] Validation report saved: {output_path}')


# ─────────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description='Automated Finding Validator -- "Bablu Review"',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python report_validator.py                 # Validate last 10 extensions
    python report_validator.py --count 5       # Validate last 5
    python report_validator.py --id feflcg...  # Validate one extension
    python report_validator.py --json out.json # Also save JSON report
        """
    )
    parser.add_argument('--count', '-n', type=int, default=10,
                        help='Number of recent extensions to validate (default: 10)')
    parser.add_argument('--id', type=str, default=None,
                        help='Validate a specific extension ID')
    parser.add_argument('--json', type=str, default=None,
                        help='Save full validation results to JSON file')
    parser.add_argument('--base-dir', type=str, default=None,
                        help='Base directory of the project (default: auto-detect)')

    args = parser.parse_args()

    validator = ReportValidator(base_dir=args.base_dir)

    if args.id:
        print(f'[+] Validating extension: {args.id}')
        result = validator.validate_extension(args.id)
        results = [result]
    else:
        print(f'[+] Validating last {args.count} analyzed extensions...')
        results = validator.validate_last_n(args.count)

    ReportValidator.print_summary(results)

    if args.json:
        validator.save_json_report(results, args.json)


if __name__ == '__main__':
    main()
