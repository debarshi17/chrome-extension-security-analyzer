"""
Enhanced Static Analysis Engine with VirusTotal Integration
Detects malicious Chrome extensions including campaign attribution
Based on DarkSpectre/ZoomStealer campaign analysis
"""

import json
import re
import hashlib
from pathlib import Path
from collections import defaultdict
from urllib.parse import urlparse
import math
from ast_analyzer import JavaScriptASTAnalyzer



class EnhancedStaticAnalyzer:
    """Performs enhanced static analysis on Chrome extensions"""

    def __init__(self):
        self.ast_analyzer = JavaScriptASTAnalyzer()

        # File content cache to avoid reading files multiple times
        self._file_cache = {}

        # Dangerous permissions with detailed explanations
        self.dangerous_permissions = {
            'debugger': {
                'score': 10,
                'description': 'Can debug and inspect other extensions and web pages',
                'risk': 'CRITICAL - Full access to browser internals'
            },
            '<all_urls>': {
                'score': 9,
                'description': 'Access to ALL websites you visit',
                'risk': 'CRITICAL - Can read/modify all web pages'
            },
            'webRequest': {
                'score': 8,
                'description': 'Can intercept all network requests',
                'risk': 'HIGH - Can spy on all your web traffic'
            },
            'webRequestBlocking': {
                'score': 9,
                'description': 'Can block or modify network traffic',
                'risk': 'CRITICAL - Can hijack or block requests'
            },
            'proxy': {
                'score': 8,
                'description': 'Can change proxy settings',
                'risk': 'HIGH - Can route traffic through attacker servers'
            },
            'cookies': {
                'score': 7,
                'description': 'Can access cookies from all sites',
                'risk': 'HIGH - Can steal session tokens'
            },
            'history': {
                'score': 6,
                'description': 'Can read your browsing history',
                'risk': 'MEDIUM - Privacy violation'
            },
            'management': {
                'score': 8,
                'description': 'Can manage other extensions',
                'risk': 'HIGH - Can disable security extensions'
            },
            'nativeMessaging': {
                'score': 7,
                'description': 'Can communicate with native apps',
                'risk': 'HIGH - Can execute system commands'
            },
            'desktopCapture': {
                'score': 8,
                'description': 'Can capture screen content',
                'risk': 'HIGH - Can screenshot sensitive info'
            },
            'tabCapture': {
                'score': 7,
                'description': 'Can capture tab content',
                'risk': 'HIGH - Can record tab activity'
            },
            'clipboardRead': {
                'score': 6,
                'description': 'Can read clipboard data',
                'risk': 'MEDIUM - Can steal copied passwords'
            },
            'geolocation': {
                'score': 5,
                'description': 'Can access your location',
                'risk': 'MEDIUM - Privacy concern'
            },
        }
        
        # Settings override risks
        self.settings_override_risks = {
            'search_provider': 10,
            'homepage': 9,
            'startup_pages': 9,
        }
        
        # Suspicious TLDs
        self.suspicious_tlds = [
            '.xyz', '.top', '.club', '.online', '.site',
            '.uno', '.pw', '.tk', '.ml', '.ga', '.icu',
            '.bid', '.win', '.review', '.download'
        ]
        
        # Affiliate/tracking parameters
        self.affiliate_markers = [
            'fr=', 'partner=', 'affid=', 'utm_source=',
            'utm_medium=', 'subid=', 'clickid=', 'PC=',
            'aff_id=', 'ref=', 'referrer='
        ]
        
        # First-party domains - network calls to these are NOT exfiltration
        # These are legitimate service APIs that extensions commonly integrate with
        self.FIRST_PARTY_DOMAINS = [
            # Google services
            'google.com', 'googleapis.com', 'mail.google.com', 'accounts.google.com',
            'drive.google.com', 'docs.google.com', 'calendar.google.com',
            'youtube.com', 'gstatic.com', 'googleusercontent.com',
            # Microsoft services
            'microsoft.com', 'office.com', 'outlook.com', 'live.com',
            'microsoftonline.com', 'azure.com', 'graph.microsoft.com',
            # Other major platforms
            'github.com', 'api.github.com', 'githubusercontent.com',
            'amazon.com', 'aws.amazon.com',
            'facebook.com', 'graph.facebook.com',
            'twitter.com', 'api.twitter.com', 'x.com',
            'linkedin.com', 'api.linkedin.com',
            'slack.com', 'api.slack.com',
            'notion.so', 'api.notion.com',
            'trello.com', 'api.trello.com',
            'dropbox.com', 'api.dropboxapi.com',
        ]

        # Malicious code patterns with better descriptions
        self.malicious_patterns = [
            {
                'name': 'Fetch POST Request (Review Destination)',
                'pattern': r'fetch\s*\([^)]*method\s*:\s*["\']POST["\']',
                'severity': 'low',
                'description': 'Sends POST request - check if destination is first-party (legitimate) or external (suspicious). First-party API calls to Google/Microsoft/etc are normal.',
                'technique': 'Network request'
            },
            # ACTUAL exfiltration - POST with credentials to dynamic/suspicious destinations
            {
                'name': 'Authenticated POST to Dynamic URL',
                'pattern': r'fetch\s*\(\s*[a-zA-Z_]\w*[\s\S]{0,50}credentials\s*:\s*["\']include["\'][\s\S]{0,100}method\s*:\s*["\']POST["\']',
                'severity': 'medium',
                'description': 'POST with credentials to a variable URL - review if URL is first-party service or external. Legitimate for Gmail/Outlook extensions calling their own APIs.',
                'technique': 'Authenticated request'
            },
            # Cookie/session replay - fetch with credentials: 'include' (any method). In inject scripts (e.g. network-helper.js) replays victim requests with their cookies.
            {
                'name': 'Fetch with credentials include (cookie replay)',
                'pattern': r'fetch\s*\([\s\S]{0,150}?credentials\s*:\s*["\']include["\']',
                'severity': 'high',
                'description': "Replays network requests with the victim's cookies (credentials: 'include'). In inject or content scripts (e.g. network-helper.js) this can hijack sessions or exfiltrate as the user.",
                'technique': 'Credential theft'
            },
            {
                'name': 'XMLHttpRequest (Informational)',
                'pattern': r'new\s+XMLHttpRequest\s*\(',
                'severity': 'low',
                'description': 'Makes network requests - common in web apps. Review destination domain.',
                'technique': 'Network communication'
            },
            {
                'name': 'Dynamic Code Execution (eval)',
                'pattern': r'\beval\s*\(',
                'severity': 'high',
                'description': 'Executes code from strings (severe security risk)',
                'technique': 'Code injection'
            },
            {
                'name': 'Base64 Decode (Obfuscation)',
                'pattern': r'atob\s*\(',
                'severity': 'medium',
                'description': 'Decodes base64 strings (often used to hide malicious code)',
                'technique': 'Code obfuscation'
            },
            {
                'name': 'Dynamic Function Creation',
                'pattern': r'new\s+Function\s*\(',
                'severity': 'high',
                'description': 'Creates functions at runtime (code injection risk)',
                'technique': 'Code injection'
            },
            {
                'name': 'Cookie Theft',
                'pattern': r'document\.cookie',
                'severity': 'high',
                'description': 'Accesses cookies (possible session hijacking)',
                'technique': 'Credential theft'
            },
            {
                'name': 'Keyboard Event Listener',
                'pattern': r'addEventListener\s*\(\s*["\']key(press|down|up)["\']',
                'severity': 'medium',
                'description': 'Registers keyboard event listeners (review for legitimacy - may be for shortcuts or malicious keylogging)',
                'technique': 'Input monitoring'
            },
            {
                'name': 'WebAssembly (Potential Crypto Mining)',
                'pattern': r'WebAssembly\.(?:instantiate|compile|compileStreaming|instantiateStreaming)\s*\([\s\S]{0,200}(?:worker|hash|mine|coin|pool|stratum)',
                'severity': 'medium',
                'description': 'Uses WebAssembly with crypto-mining indicators (hash, mine, worker pool)',
                'technique': 'Resource abuse'
            },
            {
                'name': 'Background Worker',
                'pattern': r'new\s+Worker\s*\(',
                'severity': 'low',
                'description': 'Creates background workers',
                'technique': 'Background execution'
            },
            {
                'name': 'localStorage Access',
                'pattern': r'localStorage\.(getItem|setItem)',
                'severity': 'low',
                'description': 'Accesses browser local storage',
                'technique': 'Data persistence'
            },
            # Screen Capture Detection (KOI Security SpyVPN research)
            {
                'name': 'Screen Capture via captureVisibleTab',
                'pattern': r'chrome\.tabs\.captureVisibleTab\s*\(',
                'severity': 'critical',
                'description': 'CAPTURES SCREENSHOTS of browser tabs - can steal passwords, banking info, personal messages displayed on screen',
                'technique': 'Screen capture/surveillance'
            },
            {
                'name': 'Desktop Capture API',
                'pattern': r'chrome\.desktopCapture\.',
                'severity': 'critical',
                'description': 'Captures desktop screen content - severe privacy violation',
                'technique': 'Screen capture/surveillance'
            },
            {
                'name': 'Tab Capture API',
                'pattern': r'chrome\.tabCapture\.',
                'severity': 'critical',
                'description': 'Captures tab audio/video stream - can record user activity',
                'technique': 'Screen capture/surveillance'
            },
            # Code Injection Detection
            {
                'name': 'Remote Script Injection via executeScript',
                'pattern': r'chrome\.scripting\.executeScript\s*\(',
                'severity': 'high',
                'description': 'Injects JavaScript into web pages - can steal data or modify page content',
                'technique': 'Code injection'
            },
            {
                'name': 'Legacy Script Injection (tabs.executeScript)',
                'pattern': r'chrome\.tabs\.executeScript\s*\(',
                'severity': 'high',
                'description': 'Legacy method to inject scripts into pages - review for malicious use',
                'technique': 'Code injection'
            },
            {
                'name': 'CSS Injection',
                'pattern': r'chrome\.scripting\.insertCSS\s*\(',
                'severity': 'medium',
                'description': 'Injects CSS into pages - can be used to hide or modify UI elements',
                'technique': 'UI manipulation'
            },
            # Screenshot-related message handlers
            {
                'name': 'Screenshot Capture Message Handler',
                'pattern': r'["\']capture(Viewport|Screen|Tab|Image)["\']',
                'severity': 'high',
                'description': 'Handles screenshot capture requests - may capture sensitive screen content',
                'technique': 'Screen capture/surveillance'
            },
            {
                'name': 'Canvas to Data URL (Screenshot Export)',
                'pattern': r'\.toDataURL\s*\([^)]*image',
                'severity': 'medium',
                'description': 'Converts canvas to image data - often used to export captured screenshots',
                'technique': 'Data exfiltration'
            },
            {
                'name': 'html2canvas Screenshot Library',
                'pattern': r'html2canvas\s*\(',
                'severity': 'high',
                'description': 'Uses html2canvas library to capture full-page screenshots',
                'technique': 'Screen capture/surveillance'
            },
            # Screenshot & Media Exfiltration Patterns
            {
                'name': 'FormData Screenshot Upload',
                'pattern': r'formData\.append\s*\([^)]*screenshot',
                'severity': 'critical',
                'description': 'Uploads screenshot data via FormData - likely exfiltrating captured screen content',
                'technique': 'Screenshot exfiltration'
            },
            {
                'name': 'FormData Image Blob Upload',
                'pattern': r'formData\.append\s*\([^)]*\.(jpg|jpeg|png|gif|webp)["\']',
                'severity': 'high',
                'description': 'Uploads image file via FormData - may be exfiltrating screenshots or captured media',
                'technique': 'Image exfiltration'
            },
            {
                'name': 'DataURL to Blob Conversion',
                'pattern': r'fetch\s*\(\s*dataUrl',
                'severity': 'medium',
                'description': 'Converts dataURL to blob - commonly used to process captured screenshots for upload',
                'technique': 'Data conversion'
            },
            # User/Device Tracking Patterns
            {
                'name': 'Persistent Machine ID Generation',
                'pattern': r'machine-id|machineId|device-id|deviceId',
                'severity': 'medium',
                'description': 'Generates or stores persistent device identifier - may track user across sessions',
                'technique': 'Device fingerprinting'
            },
            {
                'name': 'Random ID Generation for Tracking',
                'pattern': r'Math\.random\(\)\.toString\(\d+\)\.slice',
                'severity': 'low',
                'description': 'Generates random identifier - review context for tracking purposes',
                'technique': 'ID generation'
            },
            {
                'name': 'Tab URL Access (Informational)',
                'pattern': r'sender\.tab\.url|tab\.url',
                'severity': 'low',
                'description': 'Accesses tab URL - common for legitimate extensions. Only suspicious if combined with network calls to external servers.',
                'technique': 'URL access'
            },
            # ACTUAL URL exfiltration - requires both source (tab.url) AND sink (fetch/XHR)
            {
                'name': 'Tab URL to Network Sink',
                'pattern': r'tab\.url[\s\S]{0,200}(fetch|XMLHttpRequest|sendBeacon|\.send\s*\()',
                'severity': 'high',
                'description': 'Tab URL is accessed near a network call - review if URL data flows to external server',
                'technique': 'URL exfiltration'
            },
            # Encrypted Data Exfiltration
            {
                'name': 'Embedded RSA Public Key',
                'pattern': r'-----BEGIN PUBLIC KEY-----',
                'severity': 'high',
                'description': 'Embeds RSA public key - may encrypt exfiltrated data to evade detection',
                'technique': 'Encrypted exfiltration'
            },
            {
                'name': 'RSA-OAEP Key Import',
                'pattern': r'RSA-OAEP',
                'severity': 'high',
                'description': 'Imports RSA-OAEP key for encryption - review for data exfiltration purposes',
                'technique': 'Asymmetric encryption'
            },
            {
                'name': 'AES-GCM Encryption',
                'pattern': r'AES-GCM',
                'severity': 'medium',
                'description': 'Uses AES-GCM authenticated encryption - may hide exfiltrated data from network inspection',
                'technique': 'Symmetric encryption'
            },
            {
                'name': 'Crypto Subtle Encrypt',
                'pattern': r'crypto\.subtle\.encrypt\s*\(',
                'severity': 'medium',
                'description': 'Uses Web Crypto API for encryption - review context for data exfiltration',
                'technique': 'Data encryption'
            },
            {
                'name': 'Encrypted Blob with IV',
                'pattern': r'["\'](iv|IV|wrappedKey|encData|encImg|encMeta)["\']',
                'severity': 'high',
                'description': 'Uses encrypted blob field names with IV - suggests encrypted data exfiltration',
                'technique': 'Encrypted exfiltration'
            },
            # FormData Exfiltration Patterns
            {
                'name': 'FormData with Binary Blob',
                'pattern': r'new\s+FormData\s*\(\s*\)[\s\S]{0,500}\.append\s*\([^)]*new\s+Blob',
                'severity': 'high',
                'description': 'Creates FormData with binary blob - may be uploading captured data',
                'technique': 'Binary data exfiltration'
            },
            {
                'name': 'Bulk Data Collection via FormData',
                'pattern': r'formData\.append[\s\S]{0,100}formData\.append[\s\S]{0,100}formData\.append',
                'severity': 'medium',
                'description': 'Multiple FormData appends - may be collecting extensive user data',
                'technique': 'Data collection'
            },
            # ========== KEYLOGGER & INPUT CAPTURE ==========
            {
                'name': 'Input Field Event Listener',
                'pattern': r'addEventListener\s*\(\s*["\'](input|change)["\']',
                'severity': 'medium',
                'description': 'Monitors input field changes - review if targeting sensitive fields',
                'technique': 'Input monitoring'
            },
            {
                'name': 'Password Field Targeting',
                'pattern': r'input\[type=["\']?password["\']?\]|querySelectorAll?\s*\([^)]*password',
                'severity': 'critical',
                'description': 'Targets password input fields - HIGH RISK of credential theft',
                'technique': 'Credential theft'
            },
            {
                'name': 'Credit Card Field Targeting',
                'pattern': r'cardnumber|card-number|cc-number|cvv|cvc|creditcard|card_number|cc_num|ccv|credit.?card',
                'severity': 'critical',
                'description': 'Targets payment card fields - HIGH RISK of financial data theft',
                'technique': 'Financial data theft'
            },
            {
                'name': 'Card Expiry Field Targeting',
                'pattern': r'expiry.?date|exp.?month|exp.?year|card.?expir|cc.?exp',
                'severity': 'critical',
                'description': 'Targets card expiration fields - financial data theft indicator',
                'technique': 'Financial data theft'
            },
            {
                'name': 'Form Data Harvesting',
                'pattern': r'querySelectorAll\s*\(\s*["\']input|getElementsByTagName\s*\(\s*["\']input',
                'severity': 'medium',
                'description': 'Queries all input fields on page - may be harvesting form data',
                'technique': 'Form data collection'
            },
            {
                'name': 'Keystroke Buffer Array',
                'pattern': r'(let|var|const)\s+\w*(log|key|buffer|stroke|char)\w*\s*=\s*\[\s*\]',
                'severity': 'high',
                'description': 'Creates array for buffering keystrokes - KEYLOGGER INDICATOR',
                'technique': 'Keystroke logging'
            },
            {
                'name': 'Key Event Data Push',
                'pattern': r'\.(push|concat)\s*\([^)]*\.key\b|\.(push|concat)\s*\([^)]*keyCode',
                'severity': 'high',
                'description': 'Pushes key event data to array - KEYLOGGER BEHAVIOR',
                'technique': 'Keystroke logging'
            },
            {
                'name': 'Clipboard Read Access',
                'pattern': r'navigator\.clipboard\.read|document\.execCommand\s*\(\s*["\']paste',
                'severity': 'high',
                'description': 'Reads clipboard contents - can steal copied passwords/sensitive data',
                'technique': 'Clipboard theft'
            },
            # ========== CSS-BASED KEYLOGGING ==========
            {
                'name': 'CSS Attribute Selector Injection',
                'pattern': r'input\[value\$=|input\[value\^=|input\[value\*=',
                'severity': 'critical',
                'description': 'CSS attribute selector on input value - CSS KEYLOGGING TECHNIQUE',
                'technique': 'CSS keylogging'
            },
            {
                'name': 'CSS Background URL Exfiltration',
                'pattern': r'background(-image)?\s*:\s*url\s*\([^)]*\?.*?(key|char|val|input)',
                'severity': 'critical',
                'description': 'CSS background URL with parameters - CSS KEYLOGGING via server requests',
                'technique': 'CSS keylogging'
            },
            # ========== SCREEN CAPTURE (Additional) ==========
            {
                'name': 'Canvas toBlob Export',
                'pattern': r'\.toBlob\s*\(',
                'severity': 'medium',
                'description': 'Converts canvas to blob - commonly used for screenshot exfiltration',
                'technique': 'Image export'
            },
            {
                'name': 'Offscreen Document Creation (MV3)',
                'pattern': r'chrome\.offscreen\.createDocument|offscreen.*reason.*CLIPBOARD|offscreen.*reason.*DOM_SCRAPING',
                'severity': 'high',
                'description': 'Creates offscreen document - MV3 technique to run invisible capture scripts',
                'technique': 'Offscreen execution'
            },
            {
                'name': 'getDisplayMedia Screen Recording',
                'pattern': r'getDisplayMedia|getUserMedia.*video',
                'severity': 'critical',
                'description': 'Requests screen/camera access - can record user activity',
                'technique': 'Screen recording'
            },
            # ========== EXFILTRATION SINKS ==========
            {
                'name': 'Beacon Data Exfiltration',
                'pattern': r'navigator\.sendBeacon\s*\(',
                'severity': 'high',
                'description': 'Uses sendBeacon API - sends data even when page closes (stealthy exfiltration)',
                'technique': 'Beacon exfiltration'
            },
            {
                'name': 'WebSocket Connection',
                'pattern': r'new\s+WebSocket\s*\(',
                'severity': 'medium',
                'description': 'Opens WebSocket connection - review for C2 or real-time data exfiltration',
                'technique': 'WebSocket communication'
            },
            {
                'name': 'WebSocket Data Send',
                'pattern': r'\.send\s*\([^)]*JSON\.stringify|ws\.send\s*\(',
                'severity': 'high',
                'description': 'Sends data via WebSocket - possible real-time exfiltration',
                'technique': 'WebSocket exfiltration'
            },
            {
                'name': 'Obfuscated URL Assembly',
                'pattern': r'\[[\s\S]*?["\'](ht|htt|http|ws)["\'][\s\S]*?\]\.join\s*\(\s*["\']["\']?\s*\)',
                'severity': 'critical',
                'description': 'Assembles URL from array fragments - EVASION TECHNIQUE to hide C2 domains',
                'technique': 'URL obfuscation'
            },
            {
                'name': 'Hex Encoded String',
                'pattern': r'\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}\\x[0-9a-fA-F]{2}',
                'severity': 'high',
                'description': 'Contains hex-encoded strings - may hide malicious URLs or code',
                'technique': 'String obfuscation'
            },
            {
                'name': 'Chrome Alarms Heartbeat',
                'pattern': r'chrome\.alarms\.create|chrome\.alarms\.onAlarm',
                'severity': 'medium',
                'description': 'Creates scheduled alarms - may be used for periodic C2 check-ins',
                'technique': 'Scheduled execution'
            },
            {
                'name': 'Periodic Data Beacon (setInterval)',
                'pattern': r'setInterval\s*\([^)]*fetch|setInterval\s*\([^)]*XMLHttpRequest|setInterval\s*\([^)]*sendBeacon',
                'severity': 'high',
                'description': 'Periodically sends data - HEARTBEAT PATTERN for C2 communication',
                'technique': 'Periodic exfiltration'
            },
            # ========== EVASION & ANTI-ANALYSIS ==========
            {
                'name': 'setTimeout String Execution',
                'pattern': r'setTimeout\s*\(\s*["\'][^"\']+["\']',
                'severity': 'high',
                'description': 'Executes string via setTimeout - code injection technique',
                'technique': 'Delayed code execution'
            },
            {
                'name': 'Remote Script Injection (createElement)',
                'pattern': r'createElement\s*\(\s*["\']script["\'][\s\S]{0,200}\.src\s*=',
                'severity': 'high',
                'description': 'Creates script element with external source - REMOTE CODE LOADING',
                'technique': 'Remote script injection'
            },
            {
                'name': 'DevTools Detection',
                'pattern': r'devtools|__REACT_DEVTOOLS__|window\.outerWidth\s*-\s*window\.innerWidth|debugger',
                'severity': 'high',
                'description': 'Detects developer tools - ANTI-ANALYSIS technique to hide malicious behavior',
                'technique': 'Anti-debugging'
            },
            {
                'name': 'JavaScript Obfuscator Signature',
                'pattern': r'_0x[0-9a-f]{4,}|var\s+_0x[0-9a-f]+\s*=\s*\[',
                'severity': 'high',
                'description': 'Contains obfuscator signatures (_0x pattern) - code intentionally hidden',
                'technique': 'Code obfuscation'
            },
            {
                'name': 'Large String Array (Obfuscation)',
                'pattern': r'var\s+\w+\s*=\s*\[\s*["\'][^"\']{50,}',
                'severity': 'medium',
                'description': 'Contains large encoded string arrays - possible obfuscated code',
                'technique': 'String array obfuscation'
            },
            {
                'name': 'CharCode Decoding',
                'pattern': r'String\.fromCharCode\s*\(\s*[\d,\s]+\)',
                'severity': 'medium',
                'description': 'Decodes strings from char codes - may hide malicious strings',
                'technique': 'String obfuscation'
            },
            {
                'name': 'Prototype Reference (Informational)',
                'pattern': r'__proto__',
                'severity': 'low',
                'description': 'References __proto__ - common in library code (regenerator-runtime, babel, etc.). Only suspicious if combined with user-controlled assignment.',
                'technique': 'Prototype access'
            },
            # ACTUAL prototype pollution - requires write context
            {
                'name': 'Prototype Assignment',
                'pattern': r'Object\.prototype\.\w+\s*=',
                'severity': 'high',
                'description': 'Assigns to Object.prototype - may be prototype pollution if value is user-controlled',
                'technique': 'Prototype pollution'
            },
            {
                'name': 'Dynamic Property Assignment to Prototype',
                'pattern': r'\[[\s\S]{0,50}__proto__[\s\S]{0,50}\]\s*=',
                'severity': 'high',
                'description': 'Dynamic assignment involving __proto__ - potential prototype pollution vector',
                'technique': 'Prototype pollution'
            },
            {
                'name': 'Unsafe Object Merge',
                'pattern': r'(Object\.assign|_\.merge|_\.extend|\$\.extend)\s*\([^)]*,\s*(req\.|request\.|body\.|params\.|query\.|input)',
                'severity': 'high',
                'description': 'Merges user-controlled input into object - prototype pollution risk if input contains __proto__',
                'technique': 'Prototype pollution'
            },
            # ========== HIGH-RISK API COMBINATIONS ==========
            {
                'name': 'WebRequest Blocking',
                'pattern': r'chrome\.webRequest\.onBeforeRequest|webRequestBlocking',
                'severity': 'high',
                'description': 'Intercepts/blocks web requests - can modify or steal request data',
                'technique': 'Request interception'
            },
            {
                'name': 'Cookie Store Access',
                'pattern': r'chrome\.cookies\.getAll|chrome\.cookies\.get\s*\(',
                'severity': 'high',
                'description': 'Reads browser cookies - can steal session tokens',
                'technique': 'Cookie theft'
            },
            {
                'name': 'History Access',
                'pattern': r'chrome\.history\.search|chrome\.history\.getVisits',
                'severity': 'medium',
                'description': 'Reads browsing history - privacy violation',
                'technique': 'History theft'
            },
            {
                'name': 'Bookmark Access',
                'pattern': r'chrome\.bookmarks\.getTree|chrome\.bookmarks\.search',
                'severity': 'low',
                'description': 'Reads bookmarks - may be collecting user interests',
                'technique': 'Bookmark collection'
            },
            {
                'name': 'Downloads Manipulation',
                'pattern': r'chrome\.downloads\.download\s*\(|chrome\.downloads\.open',
                'severity': 'medium',
                'description': 'Initiates downloads - may download malware or exfiltrate data',
                'technique': 'Download manipulation'
            },
            # ========== DOM-BASED SENSITIVE DATA ACCESS ==========
            {
                'name': 'OTP/2FA Input Targeting',
                'pattern': r'input\[.*?(otp|2fa|verification|mfa|totp|sms.?code|auth.?code).*?\]|querySelectorAll?\s*\([^)]*otp',
                'severity': 'critical',
                'description': 'Targets OTP/2FA input fields - can intercept two-factor authentication codes to bypass account security',
                'technique': 'Credential theft'
            },
            {
                'name': 'CSRF Token Extraction',
                'pattern': r'(?:querySelector|getElementById|getElementsByName|getAttribute)\s*\([^)]*(?:csrf|_token|authenticity_token|__RequestVerificationToken|xsrf)[\s\S]{0,80}(?:\.value|\.content|\.textContent)',
                'severity': 'high',
                'description': 'Reads CSRF token from DOM - can forge authenticated requests on behalf of the user',
                'technique': 'CSRF token theft'
            },
            {
                'name': 'CSRF/Session Cookie Manipulation (VK/remixsec)',
                'pattern': r'remixsec|remixsec_redir',
                'severity': 'high',
                'description': 'References VK CSRF protection cookie - used by VK Styles malware to bypass origin checks',
                'technique': 'CSRF cookie manipulation'
            },
            {
                'name': 'C2/Config from meta tag (dead drop)',
                'pattern': r'getAttribute\s*\(\s*["\']content["\']\s*\)[\s\S]{0,250}(?:fetch|XMLHttpRequest|\.src\s*=)|querySelector\s*\([^)]*meta[^)]*\)[\s\S]{0,150}\.content[\s\S]{0,200}(?:fetch|\.src)',
                'severity': 'critical',
                'description': 'Parses meta tag content then uses for fetch/URL - C2 via page metadata (VK Styles TTP)',
                'technique': 'Meta tag dead drop'
            },
            {
                'name': 'Computed analytics/tracking ID (evasion)',
                'pattern': r'["\']R-A-["\']\s*\+\s*[^;]+(?:\*\s*2)?|["\']R-A-["\']\s*\+\s*\d+\s*\*\s*\d+',
                'severity': 'high',
                'description': 'Analytics ID built at runtime to evade static search - VK Styles Yandex metric pattern',
                'technique': 'Tracking ID evasion'
            },
            {
                'name': 'Hidden Input Enumeration',
                'pattern': r'input\[type=["\']?hidden["\']?\]|querySelectorAll?\s*\([^)]*hidden',
                'severity': 'medium',
                'description': 'Enumerates hidden form fields - often contain session tokens, user IDs, or security parameters',
                'technique': 'Hidden field harvesting'
            },
            {
                'name': 'Email Field Targeting',
                'pattern': r'input\[type=["\']?email["\']?\]|input\[name=["\']?email|querySelectorAll?\s*\([^)]*email',
                'severity': 'high',
                'description': 'Targets email input fields - can harvest email addresses for spam or account takeover',
                'technique': 'Email harvesting'
            },
            # ========== MUTATION OBSERVER ABUSE ==========
            {
                'name': 'MutationObserver on Document Body',
                'pattern': r'MutationObserver[\s\S]{0,200}document\.body|new\s+MutationObserver[\s\S]{0,300}subtree\s*:\s*true',
                'severity': 'high',
                'description': 'Monitors entire DOM tree for changes - can detect and capture dynamically loaded sensitive fields (login forms, payment inputs)',
                'technique': 'DOM surveillance'
            },
            {
                'name': 'MutationObserver Near Credential Keywords',
                'pattern': r'MutationObserver[\s\S]{0,150}(password|credential|card[_-]?number|cvv)',
                'severity': 'high',
                'description': 'MutationObserver used near credential-related keywords. Could indicate DOM monitoring for login/payment forms, or legitimate form handling. Requires manual review.',
                'technique': 'DOM monitoring near sensitive fields'
            },
            # ========== DOM SCRAPING & BULK EXTRACTION ==========
            {
                'name': 'Bulk Text Extraction (innerText)',
                'pattern': r'document\.body\.innerText|document\.documentElement\.innerText',
                'severity': 'high',
                'description': 'Extracts all visible page text - can capture sensitive information displayed on any website',
                'technique': 'Page content theft'
            },
            {
                'name': 'Bulk HTML Extraction (innerHTML)',
                'pattern': r'document\.body\.innerHTML|document\.documentElement\.innerHTML',
                'severity': 'high',
                'description': 'Extracts complete page HTML including hidden data, tokens, and user content',
                'technique': 'Page content theft'
            },
            {
                'name': 'Deep DOM Traversal',
                'pattern': r'querySelectorAll\s*\(\s*["\'][\*]?["\']|getElementsByTagName\s*\(\s*["\'][\*]["\']',
                'severity': 'medium',
                'description': 'Selects all DOM elements - typically used for bulk data collection or page scraping',
                'technique': 'DOM enumeration'
            },
            {
                'name': 'Document TreeWalker',
                'pattern': r'document\.createTreeWalker|createNodeIterator',
                'severity': 'medium',
                'description': 'Uses TreeWalker/NodeIterator for DOM traversal - efficient method for bulk content extraction',
                'technique': 'DOM traversal'
            },
            # ========== FORM INTERCEPTION ==========
            {
                'name': 'Form Submit Interception',
                'pattern': r'addEventListener\s*\(\s*["\']submit["\']|onsubmit\s*=|\.submit\s*\(\s*\)',
                'severity': 'high',
                'description': 'Intercepts form submissions - can capture login credentials, payment info, or personal data before form is sent',
                'technique': 'Form interception'
            },
            {
                'name': 'Form Data Object Creation',
                'pattern': r'new\s+FormData\s*\(\s*\w+\s*\)',
                'severity': 'medium',
                'description': 'Creates FormData from existing form - extracts all form field values including passwords and payment data',
                'technique': 'Form data extraction'
            },
            {
                'name': 'Input Value Direct Access',
                'pattern': r'\.value\s*[=!]=|getElementById\s*\([^)]+\)\.value|querySelector\s*\([^)]+\)\.value',
                'severity': 'low',
                'description': 'Directly accesses input field values - review context to determine if targeting sensitive fields',
                'technique': 'Input value access'
            },
            # ========== AUTOFILL ABUSE ==========
            {
                'name': 'Autofill Attribute Manipulation',
                'pattern': r'autocomplete\s*=\s*["\']?(off|new-password|current-password|cc-number)|setAttribute\s*\([^)]*autocomplete',
                'severity': 'medium',
                'description': 'Manipulates autofill attributes - may be trying to trigger browser autofill to extract saved credentials/cards',
                'technique': 'Autofill manipulation'
            },
            {
                'name': 'Hidden Autofill Trigger',
                'pattern': r'(visibility|display)\s*:\s*(hidden|none)[\s\S]{0,100}autocomplete|autocomplete[\s\S]{0,100}(visibility|display)\s*:\s*(hidden|none)',
                'severity': 'critical',
                'description': 'Hidden form with autofill enabled - AUTOFILL HARVESTING: invisible fields that trigger browser to fill saved data',
                'technique': 'Autofill harvesting'
            },
            # ========== SCRIPT INJECTION VIA DOM ==========
            {
                'name': 'DOM Event Handler Injection',
                'pattern': r'setAttribute\s*\(\s*["\']on(click|load|error|mouseover|focus)',
                'severity': 'high',
                'description': 'Sets event handlers via setAttribute - can inject executable code into DOM elements (MV3 bypass technique)',
                'technique': 'Event handler injection'
            },
            {
                'name': 'innerHTML Script Injection',
                'pattern': r'\.innerHTML\s*=[\s\S]{0,50}<script|\.innerHTML\s*\+=[\s\S]{0,50}<script',
                'severity': 'critical',
                'description': 'Injects script tags via innerHTML - direct code injection into page context',
                'technique': 'Script injection'
            },
            {
                'name': 'Document Write Injection',
                'pattern': r'document\.write\s*\(|document\.writeln\s*\(',
                'severity': 'high',
                'description': 'Uses document.write to inject content - legacy technique for injecting scripts or modifying pages',
                'technique': 'Document write injection'
            },
            # ========== CONTENT SECURITY POLICY MANIPULATION ==========
            {
                'name': 'CSP Header Removal (declarativeNetRequest)',
                'pattern': r'Content-Security-Policy[\s\S]{0,100}remove|removeResponseHeaders[\s\S]{0,100}content-security-policy',
                'severity': 'critical',
                'description': 'REMOVES Content-Security-Policy header - CONFIRMED MALWARE TECHNIQUE that enables remote code execution',
                'technique': 'CSP bypass'
            },
            {
                'name': 'CSP Meta Tag Removal',
                'pattern': r'querySelector\s*\([^)]*meta[\s\S]{0,50}Content-Security-Policy[\s\S]{0,50}(remove|delete)',
                'severity': 'critical',
                'description': 'Attempts to remove CSP meta tag from DOM - trying to bypass security policies',
                'technique': 'CSP bypass'
            },
            # ========== URL/LOCATION TRACKING ==========
            {
                'name': 'URL Change Detection',
                'pattern': r'onhashchange|onpopstate|history\.pushState|history\.replaceState',
                'severity': 'low',
                'description': 'Monitors URL/history changes - may track navigation patterns or trigger actions on specific pages',
                'technique': 'Navigation tracking'
            },
            {
                'name': 'Login Page URL Matching',
                'pattern': r'(location\.href|window\.location|document\.URL|tabs\[\d\]\.url)\s*\.\s*(includes|match|indexOf|search|test)\s*\(\s*["\'/]*(login|signin|sign-in|accounts|auth)',
                'severity': 'medium',
                'description': 'Code checks if current page URL matches login/auth pages. May indicate page-targeted behavior - review what action is triggered.',
                'technique': 'URL-conditional activation'
            },
            {
                'name': 'Financial Page URL Matching',
                'pattern': r'(location\.href|window\.location|document\.URL)\s*\.\s*(includes|match|indexOf|search|test)\s*\(\s*["\'/]*(bank|payment|checkout|paypal)',
                'severity': 'high',
                'description': 'Code checks if current page URL matches banking/payment pages. May indicate page-targeted behavior. Verify what action is triggered on match.',
                'technique': 'URL-conditional activation'
            },
            # ========== SERVICE WORKER ABUSE (MV3) ==========
            {
                'name': 'Service Worker importScripts',
                'pattern': r'importScripts\s*\([^)]*https?:',
                'severity': 'critical',
                'description': 'Loads remote scripts via importScripts in service worker - REMOTE CODE EXECUTION in MV3',
                'technique': 'Remote code loading'
            },
            {
                'name': 'Service Worker Self-Update',
                'pattern': r'self\.skipWaiting\s*\(\s*\)|clients\.claim\s*\(\s*\)',
                'severity': 'medium',
                'description': 'Service worker forces immediate activation - may be used to push malicious updates',
                'technique': 'Service worker manipulation'
            },
            {
                'name': 'Service Worker Fetch Interception',
                'pattern': r'self\.addEventListener\s*\(\s*["\']fetch["\'][\s\S]{0,300}respondWith',
                'severity': 'high',
                'description': 'Service worker intercepts all fetch requests - can modify or steal request/response data',
                'technique': 'Request interception'
            },
            {
                'name': 'Service Worker Cache Poisoning',
                'pattern': r'caches\.open[\s\S]{0,200}cache\.put|caches\.match[\s\S]{0,200}\.clone\(\)',
                'severity': 'high',
                'description': 'Service worker manipulates cache - can serve malicious cached responses',
                'technique': 'Cache manipulation'
            },
            # ========== INDEXEDDB DATA THEFT ==========
            {
                'name': 'IndexedDB Data Harvesting',
                'pattern': r'indexedDB\.open[\s\S]{0,500}(getAll|openCursor|transaction)',
                'severity': 'high',
                'description': 'Opens IndexedDB and reads data - may be harvesting locally stored sensitive data',
                'technique': 'Local data theft'
            },
            {
                'name': 'IndexedDB Bulk Export',
                'pattern': r'objectStore[\s\S]{0,100}getAll\s*\(\s*\)|cursor[\s\S]{0,100}continue\s*\(\s*\)',
                'severity': 'high',
                'description': 'Bulk reads from IndexedDB - extracting all stored data for exfiltration',
                'technique': 'Data extraction'
            },
            {
                'name': 'IndexedDB with Network Sink',
                'pattern': r'indexedDB[\s\S]{0,800}(fetch|XMLHttpRequest|sendBeacon)',
                'severity': 'critical',
                'description': 'IndexedDB access followed by network call - likely exfiltrating local storage data',
                'technique': 'IndexedDB exfiltration'
            },
            # ========== WEBRTC FINGERPRINTING & IP LEAK ==========
            {
                'name': 'WebRTC IP Address Leak',
                'pattern': r'RTCPeerConnection[\s\S]{0,300}(localDescription|icecandidate|candidate)',
                'severity': 'high',
                'description': 'Uses WebRTC to extract real IP address - bypasses VPN to identify user',
                'technique': 'IP fingerprinting'
            },
            {
                'name': 'WebRTC STUN Server Connection',
                'pattern': r'iceServers[\s\S]{0,100}stun:|createOffer[\s\S]{0,100}onicecandidate',
                'severity': 'high',
                'description': 'Connects to STUN server via WebRTC - technique to leak real IP address',
                'technique': 'IP leak'
            },
            {
                'name': 'WebRTC Data Channel',
                'pattern': r'createDataChannel\s*\(|ondatachannel\s*=',
                'severity': 'medium',
                'description': 'Creates WebRTC data channel - can be used for covert C2 communication',
                'technique': 'Covert channel'
            },
            # ========== CANVAS FINGERPRINTING ==========
            {
                'name': 'Canvas Fingerprinting',
                'pattern': r'getContext\s*\(\s*["\']2d["\'][\s\S]{0,500}toDataURL|fillText[\s\S]{0,200}toDataURL',
                'severity': 'high',
                'description': 'Renders text to canvas then extracts data - CANVAS FINGERPRINTING for user tracking',
                'technique': 'Browser fingerprinting'
            },
            {
                'name': 'WebGL Fingerprinting',
                'pattern': r'getContext\s*\(\s*["\']webgl["\'][\s\S]{0,300}(getParameter|getExtension|RENDERER|VENDOR)',
                'severity': 'high',
                'description': 'Extracts WebGL renderer info - WEBGL FINGERPRINTING to identify GPU/browser',
                'technique': 'Browser fingerprinting'
            },
            {
                'name': 'Audio Context Fingerprinting',
                'pattern': r'AudioContext|OfflineAudioContext[\s\S]{0,300}(createOscillator|createDynamicsCompressor)',
                'severity': 'high',
                'description': 'Uses AudioContext for fingerprinting - audio processing uniquely identifies device',
                'technique': 'Audio fingerprinting'
            },
            {
                'name': 'Font Fingerprinting',
                'pattern': r'measureText[\s\S]{0,100}width|offsetWidth[\s\S]{0,50}font',
                'severity': 'medium',
                'description': 'Measures font rendering - detects installed fonts for fingerprinting',
                'technique': 'Font fingerprinting'
            },
            # ========== IDENTITY API ABUSE ==========
            {
                'name': 'Chrome Identity getAuthToken',
                'pattern': r'chrome\.identity\.getAuthToken\s*\(',
                'severity': 'high',
                'description': 'Requests OAuth token - can steal access to user\'s Google account services',
                'technique': 'OAuth token theft'
            },
            {
                'name': 'Chrome Identity launchWebAuthFlow',
                'pattern': r'chrome\.identity\.launchWebAuthFlow\s*\(',
                'severity': 'high',
                'description': 'Initiates OAuth flow - may phish credentials or steal OAuth tokens',
                'technique': 'OAuth phishing'
            },
            {
                'name': 'Chrome Identity getProfileUserInfo',
                'pattern': r'chrome\.identity\.getProfileUserInfo\s*\(',
                'severity': 'medium',
                'description': 'Gets Chrome profile email - harvests user identity information',
                'technique': 'Identity harvesting'
            },
            {
                'name': 'OAuth Token Extraction',
                'pattern': r'access_token|refresh_token|id_token|authorization.?code',
                'severity': 'high',
                'description': 'References OAuth tokens - may be stealing or exfiltrating authentication tokens',
                'technique': 'Token theft'
            },
            # ========== NOTIFICATION PHISHING ==========
            {
                'name': 'Chrome Notification Creation',
                'pattern': r'chrome\.notifications\.create\s*\([^)]*click',
                'severity': 'medium',
                'description': 'Creates clickable notifications - may be used for phishing or malicious redirects',
                'technique': 'Notification phishing'
            },
            {
                'name': 'Notification with External URL',
                'pattern': r'chrome\.notifications[\s\S]{0,300}https?://[^\s"\'}]+',
                'severity': 'high',
                'description': 'Notification with external URL - may redirect users to phishing sites',
                'technique': 'Notification phishing'
            },
            {
                'name': 'Notification Button Handler',
                'pattern': r'chrome\.notifications\.onButtonClicked|chrome\.notifications\.onClicked',
                'severity': 'medium',
                'description': 'Handles notification clicks - review for malicious redirects or downloads',
                'technique': 'Notification interaction'
            },
            # ========== DECLARATIVENETREQUEST ABUSE ==========
            {
                'name': 'DNR Header Modification',
                'pattern': r'declarativeNetRequest[\s\S]{0,200}modifyHeaders|responseHeaders[\s\S]{0,100}(set|remove)',
                'severity': 'high',
                'description': 'Modifies HTTP headers via DeclarativeNetRequest - can remove security headers or inject tracking',
                'technique': 'Header manipulation'
            },
            {
                'name': 'DNR Request Redirect',
                'pattern': r'declarativeNetRequest[\s\S]{0,200}redirect|action[\s\S]{0,50}type[\s\S]{0,50}redirect',
                'severity': 'high',
                'description': 'Redirects requests via DeclarativeNetRequest - can hijack traffic to malicious servers',
                'technique': 'Traffic hijacking'
            },
            {
                'name': 'DNR Cookie Manipulation',
                'pattern': r'declarativeNetRequest[\s\S]{0,300}(set-cookie|cookie)[\s\S]{0,100}(remove|set)',
                'severity': 'critical',
                'description': 'Manipulates cookies via DNR - can steal sessions or inject tracking cookies',
                'technique': 'Cookie manipulation'
            },
            {
                'name': 'DNR All URLs Rule',
                'pattern': r'declarativeNetRequest[\s\S]{0,200}urlFilter[\s\S]{0,50}["\'][*]?["\']',
                'severity': 'high',
                'description': 'DNR rule affects all URLs - broad traffic interception capability',
                'technique': 'Traffic interception'
            },
            # ========== MEDIARECORDER ABUSE ==========
            {
                'name': 'MediaRecorder Screen Recording',
                'pattern': r'new\s+MediaRecorder\s*\(|MediaRecorder\.isTypeSupported',
                'severity': 'high',
                'description': 'Creates MediaRecorder - can record screen, tab, or microphone audio',
                'technique': 'Media recording'
            },
            {
                'name': 'MediaRecorder with getDisplayMedia',
                'pattern': r'getDisplayMedia[\s\S]{0,300}MediaRecorder|MediaRecorder[\s\S]{0,300}getDisplayMedia',
                'severity': 'critical',
                'description': 'Records screen via getDisplayMedia + MediaRecorder - SCREEN RECORDING SURVEILLANCE',
                'technique': 'Screen surveillance'
            },
            {
                'name': 'MediaRecorder Audio Capture',
                'pattern': r'getUserMedia[\s\S]{0,50}audio[\s\S]{0,200}MediaRecorder',
                'severity': 'critical',
                'description': 'Records audio via getUserMedia + MediaRecorder - MICROPHONE SURVEILLANCE',
                'technique': 'Audio surveillance'
            },
            {
                'name': 'MediaRecorder Blob Export',
                'pattern': r'ondataavailable[\s\S]{0,100}(Blob|blob)|MediaRecorder[\s\S]{0,300}\.data',
                'severity': 'high',
                'description': 'Exports recorded media as blob - likely for exfiltration',
                'technique': 'Media exfiltration'
            },
            # ========== EXTENSION MESSAGING EXFILTRATION ==========
            {
                'name': 'External Extension Messaging',
                'pattern': r'chrome\.runtime\.sendMessage\s*\(\s*["\'][a-z]{32}["\']',
                'severity': 'high',
                'description': 'Sends message to external extension by ID - may be exfiltrating data to accomplice extension',
                'technique': 'Cross-extension exfiltration'
            },
            {
                'name': 'External Website Messaging',
                'pattern': r'externally_connectable|chrome\.runtime\.onMessageExternal',
                'severity': 'medium',
                'description': 'Allows messages from external websites - can be used as exfiltration channel',
                'technique': 'External messaging'
            },
            {
                'name': 'Native Messaging Host',
                'pattern': r'chrome\.runtime\.connectNative|chrome\.runtime\.sendNativeMessage',
                'severity': 'critical',
                'description': 'Communicates with native application - can execute arbitrary system commands',
                'technique': 'Native code execution'
            },
            # ========== ADDITIONAL EVASION TECHNIQUES ==========
            {
                'name': 'VM/Sandbox Detection',
                'pattern': r'navigator\.(hardwareConcurrency|deviceMemory|platform)[\s\S]{0,100}(<=?\s*[12]|===?\s*["\'])',
                'severity': 'high',
                'description': 'Checks hardware specs to detect VMs/sandboxes - ANTI-ANALYSIS behavior',
                'technique': 'Sandbox detection'
            },
            {
                'name': 'Headless Browser Detection',
                'pattern': r'navigator\.webdriver|(?:window\.)?(?:_phantom|__nightmare|callPhantom)|selenium|puppeteer',
                'severity': 'high',
                'description': 'Detects automated browsers (webdriver/phantom/selenium/puppeteer) - ANTI-ANALYSIS to evade security scanners',
                'technique': 'Automation detection'
            },
            {
                'name': 'User Interaction Gating',
                'pattern': r'(click|mousemove|keydown|scroll)[\s\S]{0,100}(setTimeout|flag|activate|enable)',
                'severity': 'medium',
                'description': 'Waits for user interaction before activating - evasion technique against automated analysis',
                'technique': 'Interaction gating'
            },
            {
                'name': 'Install Time Delayed Activation',
                'pattern': r'chrome\.runtime\.onInstalled[\s\S]{0,300}(Date\.now|setTimeout|setInterval)',
                'severity': 'high',
                'description': 'Records install time for delayed activation - TIME BOMB pattern to evade initial review',
                'technique': 'Delayed activation'
            },
            # ========== STORAGE API ABUSE ==========
            {
                'name': 'Chrome Storage Sync Abuse',
                'pattern': r'chrome\.storage\.sync\.(get|set)[\s\S]{0,200}(password|credential|token|key|secret)',
                'severity': 'critical',
                'description': 'Stores sensitive data in sync storage - syncs stolen credentials across user devices',
                'technique': 'Credential syncing'
            },
            {
                'name': 'Session Storage Bulk Read',
                'pattern': r'chrome\.storage\.session\.get\s*\(\s*null|chrome\.storage\.local\.get\s*\(\s*null',
                'severity': 'medium',
                'description': 'Reads all storage data - may be extracting everything for exfiltration',
                'technique': 'Storage extraction'
            },
            # ========== PERMISSION ESCALATION ==========
            {
                'name': 'Runtime Permission Request',
                'pattern': r'chrome\.permissions\.request\s*\(',
                'severity': 'medium',
                'description': 'Requests additional permissions at runtime - may escalate access after initial install',
                'technique': 'Permission escalation'
            },
            {
                'name': 'Optional Permissions with Host Access',
                'pattern': r'optional_permissions[\s\S]{0,100}(<all_urls>|\*://)',
                'severity': 'high',
                'description': 'Declares optional host permissions - can request full web access after install review',
                'technique': 'Deferred permission escalation'
            },
            # ========== CRYPTOCURRENCY THEFT PATTERNS ==========
            {
                'name': 'Ethereum Wallet Override',
                'pattern': r'window\s*\.\s*ethereum\s*=|Object\.defineProperty\s*\([^)]*["\']ethereum["\']',
                'severity': 'critical',
                'description': 'Overrides window.ethereum to intercept wallet transactions - CONFIRMED CRYPTO THEFT TECHNIQUE',
                'technique': 'Wallet hijacking'
            },
            {
                'name': 'Solana Wallet Override',
                'pattern': r'window\s*\.\s*(solana|phantom)\s*=|Object\.defineProperty\s*\([^)]*["\']solana["\']',
                'severity': 'critical',
                'description': 'Overrides Solana/Phantom wallet object to intercept transactions',
                'technique': 'Wallet hijacking'
            },
            {
                'name': 'Web3 Provider Override',
                'pattern': r'window\s*\.\s*web3\s*=|Object\.defineProperty\s*\([^)]*["\']web3["\']',
                'severity': 'critical',
                'description': 'Overrides Web3 provider to intercept blockchain transactions',
                'technique': 'Wallet hijacking'
            },
            {
                'name': 'Clipboard Wallet Address Swap',
                'pattern': r'clipboard\.(readText|read)[^}]*?(0x[a-fA-F0-9]|bc1|[13][a-km-zA-HJ-NP-Z])[^}]*?clipboard\.(writeText|write)',
                'severity': 'critical',
                'description': 'Reads clipboard, checks for wallet address, replaces with attacker address - CLIPBOARD HIJACKING',
                'technique': 'Clipboard hijacking'
            },
            {
                'name': 'Ethereum Address Regex',
                'pattern': r'(match|test|exec)\s*\(\s*/\^?0x\[a-fA-F0-9\]\{40\}',
                'severity': 'high',
                'description': 'Regex matching Ethereum addresses - may be wallet address targeting',
                'technique': 'Crypto targeting'
            },
            {
                'name': 'Bitcoin Address Regex',
                'pattern': r'(match|test|exec)\s*\(\s*/\^?\[13\]\[a-km-zA-HJ-NP-Z|bc1\[a-z0-9\]',
                'severity': 'high',
                'description': 'Regex matching Bitcoin addresses - may be wallet address targeting',
                'technique': 'Crypto targeting'
            },
            {
                'name': 'Mnemonic Seed Phrase Detection',
                'pattern': r'(seed|mnemonic|phrase|recovery|backup)\s*[:=]\s*["\'][a-z]+(\s+[a-z]+){11,23}["\']',
                'severity': 'critical',
                'description': 'Accesses or stores wallet recovery seed phrase - CRITICAL THEFT INDICATOR',
                'technique': 'Seed phrase theft'
            },
            {
                'name': 'Private Key Hex String',
                'pattern': r'(privateKey|private_key|privkey|secret)\s*[:=]\s*["\'][0-9a-fA-F]{64}["\']',
                'severity': 'critical',
                'description': 'Contains or assigns 64-char hex string as private key - PRIVATE KEY THEFT',
                'technique': 'Private key theft'
            },
            {
                'name': 'Token Approval Injection',
                'pattern': r'approve\s*\([^)]*(?:MAX_UINT|ffffffff|unlimited|0x[fF]+)',
                'severity': 'critical',
                'description': 'Injects unlimited token approval to drain wallet - APPROVE ATTACK',
                'technique': 'Token drain'
            },
            {
                'name': 'Eth Sign Phishing',
                'pattern': r'eth_sign[^}]*?(input|value|document\.|password)',
                'severity': 'critical',
                'description': 'Requests eth_sign with user input - allows signing arbitrary transactions',
                'technique': 'Signature phishing'
            },
            {
                'name': 'MetaMask Phishing',
                'pattern': r'metamask\.io[^}]*?(login|connect|unlock|password)|metamask[^}]*?phish',
                'severity': 'critical',
                'description': 'Attempts to phish MetaMask credentials or impersonate MetaMask',
                'technique': 'Wallet phishing'
            },
            # ========== ADVANCED OBFUSCATION DETECTION ==========
            {
                'name': 'Eval via Bracket Concatenation',
                'pattern': r'(window|this|self)\s*\[\s*["\'][^"\']+["\']\s*\+\s*["\'][^"\']+["\']\s*\]',
                'severity': 'critical',
                'description': 'Invokes eval via bracket notation with string concatenation (window["ev"+"al"]) - EVASION TECHNIQUE',
                'technique': 'Eval bypass'
            },
            {
                'name': 'Constructor Chain Bypass',
                'pattern': r'\[\s*["\']constructor["\']\s*\]\s*\[\s*["\']constructor["\']\s*\]',
                'severity': 'critical',
                'description': 'Uses constructor chain to execute arbitrary code - ADVANCED EVASION',
                'technique': 'Constructor bypass'
            },
            {
                'name': 'Debugger Anti-Analysis Loop',
                'pattern': r'(while|for)\s*\([^)]*\)\s*\{[^}]*debugger[^}]*\}|setInterval\s*\([^)]*debugger',
                'severity': 'high',
                'description': 'Debugger statements in loops to prevent analysis - ANTI-DEBUGGING',
                'technique': 'Anti-debugging'
            },
            {
                'name': 'String Array Rotation Obfuscation',
                'pattern': r'var\s+\w+\s*=\s*\[[^\]]{500,}\][^;]*;[^}]*(shift|push|splice)',
                'severity': 'high',
                'description': 'Large string array with rotation function - JAVASCRIPT OBFUSCATOR signature',
                'technique': 'Code obfuscation'
            },
            {
                'name': 'Unicode Escape Obfuscation',
                'pattern': r'(?:\\u[0-9a-fA-F]{4}){6,}',
                'severity': 'medium',
                'description': 'Heavy use of Unicode escape sequences (6+ consecutive) to hide code — excludes short i18n strings',
                'technique': 'String obfuscation'
            },
            {
                'name': 'Computed Property Chains',
                'pattern': r'\[["\'][^"\']+["\']\]\s*\[["\'][^"\']+["\']\]\s*\[["\'][^"\']+["\']\]',
                'severity': 'high',
                'description': 'Multiple computed property accesses in chain - obfuscation technique',
                'technique': 'Bracket notation obfuscation'
            },
            # ========== PHISHING & UI HIJACKING ==========
            {
                'name': 'Fullscreen Iframe Overlay',
                'pattern': r'createElement\s*\(["\']iframe["\']\)[^}]*?(100vh|100vw|position\s*:\s*fixed|z-index\s*:\s*\d{4,})',
                'severity': 'critical',
                'description': 'Creates fullscreen iframe overlay for phishing/clickjacking - UI HIJACKING',
                'technique': 'Overlay attack'
            },
            {
                'name': 'Password Field to Background Script',
                'pattern': r'input\[type=["\']?password[^}]*?chrome\.runtime\.sendMessage',
                'severity': 'critical',
                'description': 'Sends password field data to background script - CREDENTIAL THEFT',
                'technique': 'Password exfiltration'
            },
            {
                'name': 'Fake Login Form Injection',
                'pattern': r'innerHTML\s*=[^}]*?(login|signin|password|credential)[^}]*?form',
                'severity': 'critical',
                'description': 'Injects fake login form into page - PHISHING ATTACK',
                'technique': 'Form injection'
            },
            {
                'name': 'Extension UI Element Hiding',
                'pattern': r'(remove|uninstall|disable)[^}]*?(display\s*:\s*none|visibility\s*:\s*hidden)',
                'severity': 'high',
                'description': 'Hides extension management UI elements - prevents user from uninstalling',
                'technique': 'UI manipulation'
            },
            {
                'name': 'Chrome Extensions Page Manipulation',
                'pattern': r'chrome://extensions[^}]*?(insertCSS|style|remove|hide)',
                'severity': 'critical',
                'description': 'Attempts to manipulate chrome://extensions page - SEVERE ABUSE',
                'technique': 'Extension page tampering'
            },
            {
                'name': 'Bank URL Detection',
                'pattern': r'(location\.href|window\.location|document\.URL)[^}]*?(bank|chase|wellsfargo|bankofamerica|citibank|paypal)',
                'severity': 'high',
                'description': 'Code detects banking website URLs - may trigger credential theft on bank sites',
                'technique': 'Banking target detection'
            },
            {
                'name': 'Crypto Exchange URL Detection',
                'pattern': r'(location\.href|window\.location|document\.URL)[^}]*?(binance|coinbase|kraken|crypto\.com|gemini|ftx)',
                'severity': 'high',
                'description': 'Code detects crypto exchange URLs - may trigger wallet/API key theft',
                'technique': 'Crypto exchange targeting'
            },
            # ========== NETWORK SECURITY TAMPERING ==========
            {
                'name': 'X-Frame-Options Removal',
                'pattern': r'x-frame-options[^}]*?(remove|delete|null)',
                'severity': 'critical',
                'description': 'Removes X-Frame-Options header - enables clickjacking attacks',
                'technique': 'Security header removal'
            },
            {
                'name': 'Security URL Blocking',
                'pattern': r'(virustotal|safebrowsing|malwarebytes|kaspersky|norton)[^}]*?(cancel|block|redirect)',
                'severity': 'critical',
                'description': 'Blocks access to security/antivirus websites - DEFENSE EVASION',
                'technique': 'Security site blocking'
            },
            {
                'name': 'Proxy Server Configuration',
                'pattern': r'chrome\.proxy\.settings\.set|proxyType\s*:\s*["\']fixed_servers["\']',
                'severity': 'critical',
                'description': 'Modifies Chrome proxy settings - can route all traffic through attacker server',
                'technique': 'Proxy hijacking'
            },
            {
                'name': 'DNS Override Attempt',
                'pattern': r'dns\s*[:=]\s*["\'][0-9]+\.[0-9]+|chrome\.dns|webRequest[^}]*?dns',
                'severity': 'high',
                'description': 'Attempts to modify or intercept DNS - traffic hijacking indicator',
                'technique': 'DNS manipulation'
            },
            {
                'name': 'Certificate Pinning Bypass',
                'pattern': r'certificateTransparency|publicKeyPinning|HPKP|pinning\s*:\s*false',
                'severity': 'high',
                'description': 'Attempts to bypass certificate pinning - enables MITM attacks',
                'technique': 'Certificate bypass'
            },
            # ========== STEGANOGRAPHY & ADVANCED HIDING ==========
            {
                'name': 'Image Data Extraction',
                'pattern': r'getImageData\s*\([^)]*\)[^}]*?(charCodeAt|fromCharCode|String\.|data\[)',
                'severity': 'high',
                'description': 'Extracts data from image pixels - STEGANOGRAPHY technique to hide code in images',
                'technique': 'Steganography'
            },
            {
                'name': 'Canvas Hidden Data',
                'pattern': r'canvas[^}]*?(getImageData|putImageData)[^}]*?(decode|decrypt|parse|eval)',
                'severity': 'high',
                'description': 'Uses canvas to hide/extract data - steganographic payload delivery',
                'technique': 'Canvas steganography'
            },
            {
                'name': 'Comment-Based Code Hiding',
                'pattern': r'/\*[^*]*\*/.{0,50}(eval|Function|atob)\s*\(',
                'severity': 'high',
                'description': 'Code execution near multi-line comments - may extract code from comments',
                'technique': 'Comment obfuscation'
            },

            # ── Remote Iframe C2 Architecture ──────────────────────────
            {
                'name': 'Remote Iframe UI Injection',
                'pattern': r'createElement\s*\(["\']iframe["\']\)[^}]{0,150}\.src\s*=\s*["\']https?://(?!chrome-extension://)[^"\']+["\']',
                'severity': 'critical',
                'description': 'Extension UI loaded from remote server — enables server-side control without Chrome Store updates. REMOTE C2 ARCHITECTURE.',
                'technique': 'Remote C2 UI'
            },
            {
                'name': 'Fullscreen Remote Iframe',
                'pattern': r'(100vw|100vh|100%)[^}]{0,120}iframe[^}]{0,120}https?://|iframe[^}]{0,120}https?://[^}]{0,120}(100vw|100vh|position\s*:\s*fixed)',
                'severity': 'critical',
                'description': 'Fullscreen iframe to external domain — complete UI takeover with remote control capability',
                'technique': 'Remote C2 UI'
            },
            {
                'name': 'Dynamic Remote Iframe Source',
                'pattern': r'createElement\s*\(["\']iframe["\']\)[^}]{0,150}\.src\s*=\s*[a-zA-Z_$]\w*',
                'severity': 'high',
                'description': 'Iframe created with dynamic/variable source — may load remote C2 UI at runtime',
                'technique': 'Remote C2 UI'
            },
        ]

        # PRE-COMPILE all regex patterns for better performance
        # This is done once at initialization instead of on every scan
        #
        # Wide-gap patterns ([\s\S]{0,N} where N >= 200) are split into
        # a two-pass search: first match the anchor, then search a bounded
        # window for the tail.  This prevents catastrophic backtracking on
        # large files where the [\s\S]{0,N} quantifier would cause the
        # engine to try exponentially many paths before failing.
        self._compiled_patterns = []
        self._WIDE_GAP_RE = re.compile(r'\[\\s\\S\]\{0,(\d+)\}')

        for pattern_def in self.malicious_patterns:
            raw = pattern_def['pattern']
            try:
                # Detect wide-gap patterns that risk catastrophic backtracking
                gap_match = self._WIDE_GAP_RE.search(raw)
                max_gap = int(gap_match.group(1)) if gap_match else 0

                if max_gap >= 50:
                    # Split into anchor + tail for two-pass matching
                    parts = self._WIDE_GAP_RE.split(raw, maxsplit=1)
                    anchor = re.compile(parts[0], re.IGNORECASE)
                    tail = re.compile(parts[2], re.IGNORECASE) if len(parts) > 2 else None
                    self._compiled_patterns.append({
                        'name': pattern_def['name'],
                        'compiled': anchor,
                        'tail': tail,
                        'max_gap': max_gap,
                        'severity': pattern_def['severity'],
                        'description': pattern_def['description'],
                        'technique': pattern_def.get('technique', 'Unknown'),
                        'two_pass': True,
                    })
                else:
                    compiled = re.compile(raw, re.IGNORECASE)
                    self._compiled_patterns.append({
                        'name': pattern_def['name'],
                        'compiled': compiled,
                        'severity': pattern_def['severity'],
                        'description': pattern_def['description'],
                        'technique': pattern_def.get('technique', 'Unknown'),
                        'two_pass': False,
                    })
            except re.error as e:
                print(f"[!] Warning: Failed to compile pattern '{pattern_def['name']}': {e}")

    # Cap file size for pattern-scan read to avoid slow regex/entropy on huge bundles
    _MAX_READ_SIZE_FOR_SCAN = 2 * 1024 * 1024  # 2 MiB (raised so large index.js bundles get more pattern coverage)

    def _read_file_cached(self, file_path):
        """Read file content with caching to avoid multiple reads

        OPTIMIZATION: Files are often read multiple times by different analyzers.
        This cache stores content in memory for the duration of analysis.
        Very large files are truncated to _MAX_READ_SIZE_FOR_SCAN to avoid hangs.

        Args:
            file_path: Path to file

        Returns:
            str: File content or None if read fails
        """
        file_str = str(file_path)

        if file_str in self._file_cache:
            return self._file_cache[file_str]

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read(self._MAX_READ_SIZE_FOR_SCAN)
                self._file_cache[file_str] = content
                return content
        except Exception:
            try:
                with open(file_path, 'r', encoding='latin-1', errors='replace') as f:
                    content = f.read(self._MAX_READ_SIZE_FOR_SCAN)
                    self._file_cache[file_str] = content
                    return content
            except Exception:
                return None

    def _clear_file_cache(self):
        """Clear file cache after analysis to free memory"""
        self._file_cache.clear()

    @staticmethod
    def _get_manifest_referenced_js(extension_dir, manifest):
        """Return set of relative path strings for every JS file referenced in manifest.
        These are security-critical (background, content scripts, service worker, etc.).
        """
        refs = set()
        ext_dir = Path(extension_dir)
        base = ext_dir

        def norm(p):
            s = str(p).replace('\\', '/').lstrip('/')
            return s

        # MV2: background.scripts[]
        bg = manifest.get('background', {})
        if isinstance(bg, dict):
            for script in bg.get('scripts', []):
                if script.endswith('.js'):
                    refs.add(norm(script))
            # MV3: background.service_worker (single JS)
            sw = bg.get('service_worker')
            if isinstance(sw, str) and sw.endswith('.js'):
                refs.add(norm(sw))

        # content_scripts[].js[]
        for cs in manifest.get('content_scripts', []):
            for script in cs.get('js', []):
                if script.endswith('.js'):
                    refs.add(norm(script))

        # devtools_page (can be .js in some edge cases; usually .html)
        dev = manifest.get('devtools_page')
        if dev and isinstance(dev, str) and dev.endswith('.js'):
            refs.add(norm(dev))

        return refs

    def _prioritize_js_files_for_security(self, extension_dir, manifest, max_files=300):
        """Return only manifest-referenced JS files + a small set of high-value
        filenames that attackers commonly use (inject scripts, helpers, loaders).

        Why: Scanning hundreds of bundled library files through AST is slow and
        produces false-positive domains/patterns.  The files that actually carry
        malicious payloads are always referenced in manifest.json (background,
        content_scripts, service_worker) or have recognizable names like
        inject.js, helper.js, loader.js.

        This keeps AST + pattern scanning fast and focused on what matters.
        """
        extension_dir = Path(extension_dir)

        # 1. Start with manifest-referenced JS (the must-scan set)
        manifest_refs = self._get_manifest_referenced_js(extension_dir, manifest)
        seen = set()
        result = []

        def _add(p):
            resolved = p.resolve()
            if resolved not in seen and p.is_file():
                seen.add(resolved)
                result.append(p)

        for ref in manifest_refs:
            candidate = extension_dir / ref
            if candidate.is_file():
                _add(candidate)

        # 2. Also grab high-value filenames that attackers use but may not be
        #    directly listed in manifest (e.g. injected by background.js at runtime)
        _HIGH_VALUE_NAMES = {
            'inject.js', 'injector.js', 'inject-script.js',
            'network-helper.js', 'helper.js', 'loader.js',
            'payload.js', 'stealer.js', 'keylogger.js',
            'c2.js', 'beacon.js', 'exfil.js',
            'find-password.js', 'password.js',
            'manifest.js',
        }
        _HIGH_VALUE_KEYWORDS = {'inject', 'helper', 'payload', 'steal', 'exfil', 'keylog', 'c2', 'beacon'}

        all_js = list(extension_dir.rglob('*.js'))
        for p in all_js:
            if 'node_modules' in p.parts or 'bower_components' in p.parts:
                continue
            name_lower = p.name.lower()
            if name_lower in _HIGH_VALUE_NAMES:
                _add(p)
                continue
            # Check if filename contains any high-value keyword
            stem = p.stem.lower()
            if any(kw in stem for kw in _HIGH_VALUE_KEYWORDS):
                _add(p)

        total_js = len([p for p in all_js if 'node_modules' not in p.parts and 'bower_components' not in p.parts])
        skipped = total_js - len(result)
        if skipped > 0:
            print(f"[+] Focused scan: {len(result)} manifest-referenced + high-value files (skipped {skipped} library/bundled files)")

        return result[:max_files]

    # Known third-party libraries that should have findings downgraded
    KNOWN_LIBRARIES = [
        'regenerator-runtime',
        'regeneratorRuntime',
        '@babel/runtime',
        'mustache.js',
        'mustache.min.js',
        'lodash',
        'underscore',
        'jquery',
        'react',
        'vue',
        'angular',
        'polyfill',
        'core-js',
        'babel-polyfill',
        'lit-html',
        'lit-element',
        'polymer',
        'svelte',
        'preact',
        'ember',
        'backbone',
        'handlebars',
        'htm.module',
    ]

    def _is_first_party_domain(self, context):
        """Check if network call context targets a first-party domain

        First-party domains are legitimate service APIs (Google, Microsoft, etc.)
        that extensions commonly integrate with. Network calls to these are NOT
        exfiltration - they're legitimate service communication.

        Args:
            context: Code context around the network call

        Returns:
            tuple: (is_first_party, domain_found)
        """
        context_lower = context.lower()

        for domain in self.FIRST_PARTY_DOMAINS:
            if domain.lower() in context_lower:
                return True, domain

        # Also check for common first-party URL patterns
        first_party_patterns = [
            'mail.google.com',
            'apis.google.com',
            'www.googleapis.com',
            'graph.microsoft.com',
            'outlook.office.com',
            'api.github.com',
        ]

        for pattern in first_party_patterns:
            if pattern in context_lower:
                return True, pattern

        return False, None

    def _is_library_code(self, code, file_path):
        """Check if code appears to be from a well-known third-party library

        Returns True if:
        - File name matches known library
        - Code contains library header/signature

        Findings in library code should be downgraded (not hidden).
        """
        file_lower = file_path.lower()

        # Check filename
        for lib in self.KNOWN_LIBRARIES:
            if lib.lower() in file_lower:
                return True

        # Check for library signatures in first 2000 chars
        code_header = code[:2000].lower()

        library_signatures = [
            'regenerator-runtime',
            'regeneratorruntime',
            '@babel/runtime',
            '* mustache.js',
            'lodash.js',
            'underscore.js',
            '* jquery',
            'copyright facebook',  # React
            'copyright (c) facebook',
            'vue.js',
            'angular',
            'core-js',
            # lit-html / Polymer / LitElement
            'the polymer project authors',
            'polymer.github.io/patents',
            'lit-html',
            'lit-element',
            '$lit$',
            '{{lit-',
            # Svelte / Preact / other frameworks
            'svelte',
            'copyright (c) jason miller',  # Preact
            'preact',
            'ember.js',
            'backbone.js',
            'handlebars.js',
        ]

        for sig in library_signatures:
            if sig in code_header:
                return True

        # For bundled/webpack files, framework signatures may appear deeper.
        # Check the full content for highly distinctive markers that are
        # unique enough to avoid false positives.
        code_lower = code.lower() if len(code) > 2000 else code_header
        bundled_signatures = [
            'the polymer project authors',
            'polymer.github.io/patents',
            '$lit$',
            '{{lit-',
            'copyright (c) facebook',  # React in bundles
            'copyright facebook, inc',
        ]
        for sig in bundled_signatures:
            if sig in code_lower:
                return True

        return False

    def _resolve_localized_string(self, extension_dir, msg_key, default):
        """
        Resolve localized string from _locales directory
        Args:
            extension_dir: Path to extension directory
            msg_key: The message key (without __MSG_ prefix and __ suffix)
            default: Default value if resolution fails
        Returns:
            Resolved string or default
        """
        locales_dir = extension_dir / '_locales'
        if not locales_dir.exists():
            return default

        # Try common locales in order of preference
        locale_priorities = ['en', 'en_US', 'en_GB', 'de', 'fr', 'es', 'pt', 'zh', 'ja', 'ko']

        # First try prioritized locales
        for locale in locale_priorities:
            messages_path = locales_dir / locale / 'messages.json'
            if messages_path.exists():
                try:
                    with open(messages_path, 'r', encoding='utf-8') as f:
                        messages = json.load(f)
                        if msg_key in messages:
                            return messages[msg_key].get('message', default)
                except Exception:
                    continue

        # If not found, try any locale
        try:
            for locale_folder in locales_dir.iterdir():
                if locale_folder.is_dir():
                    messages_path = locale_folder / 'messages.json'
                    if messages_path.exists():
                        try:
                            with open(messages_path, 'r', encoding='utf-8') as f:
                                messages = json.load(f)
                                if msg_key in messages:
                                    return messages[msg_key].get('message', default)
                        except Exception:
                            continue
        except Exception:
            pass

        return default

    def analyze_extension(self, extension_dir, progress_callback=None):
        """
        Perform complete static analysis on an extension.
        progress_callback: optional callable(phase_percent_0_to_100, detail_str) for UI progress.
        """
        extension_dir = Path(extension_dir)
        
        print(f"\n[+] Analyzing: {extension_dir.name}")
        
        # Read manifest
        manifest_path = extension_dir / "manifest.json"
        if not manifest_path.exists():
            print(f"[[X]] No manifest.json found")
            return None
        
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)

        extension_name = manifest.get('name', 'Unknown')
        extension_desc = manifest.get('description', '')

        # Resolve localized strings (e.g., __MSG_appName__)
        if extension_name.startswith('__MSG_') and extension_name.endswith('__'):
            msg_key = extension_name[6:-2]  # Extract key from __MSG_key__
            extension_name = self._resolve_localized_string(extension_dir, msg_key, extension_name)

        # Resolve localized description
        if extension_desc.startswith('__MSG_') and extension_desc.endswith('__'):
            msg_key = extension_desc[6:-2]
            extension_desc = self._resolve_localized_string(extension_dir, msg_key, extension_desc)

        print(f"[+] Extension: {extension_name}")
        print(f"[+] Version: {manifest.get('version', 'Unknown')}")
        
        # Extract extension icon (largest available)
        icon_base64 = None
        icons = manifest.get('icons', {})
        if icons:
            # Get largest icon (prefer 128, then 64, then 48, then 32, then 16)
            for size in ['128', '96', '64', '48', '32', '16']:
                if size in icons:
                    icon_path = extension_dir / icons[size]
                    if icon_path.exists():
                        try:
                            import base64
                            with open(icon_path, 'rb') as icon_file:
                                icon_data = icon_file.read()
                                icon_base64 = base64.b64encode(icon_data).decode('utf-8')
                                # Determine mime type
                                if str(icon_path).lower().endswith('.png'):
                                    icon_base64 = f"data:image/png;base64,{icon_base64}"
                                elif str(icon_path).lower().endswith('.jpg') or str(icon_path).lower().endswith('.jpeg'):
                                    icon_base64 = f"data:image/jpeg;base64,{icon_base64}"
                                else:
                                    icon_base64 = f"data:image/png;base64,{icon_base64}"
                                print(f"[+] Icon extracted: {icons[size]}")
                                break
                        except Exception as e:
                            print(f"[!] Failed to extract icon: {e}")

        # Initialize results
        results = {
            'extension_id': extension_dir.name,
            'name': extension_name,
            'version': manifest.get('version'),
            'manifest_version': manifest.get('manifest_version'),
            'description': extension_desc,
            'icon_base64': icon_base64,
            'permissions': {},
            'malicious_patterns': [],
            'external_scripts': [],
            'obfuscation_indicators': {},
            'settings_overrides': {},
            'campaign_attribution': None,
            'domain_analysis': [],
            'virustotal_results': [],
            'ast_results': {},
            'risk_score': 0,
            'risk_level': 'UNKNOWN',
            'urls_in_code': [],
            'manifest_urls': [],
        }
        # Extract manifest URLs (privacy policy, homepage, update) for C2/domain detection
        for key in ('privacy_policy_url', 'homepage_url', 'update_url'):
            u = manifest.get(key)
            if u and isinstance(u, str) and (u.startswith('http://') or u.startswith('https://')):
                try:
                    host = urlparse(u).netloc.split(':')[0]
                    if host:
                        results['manifest_urls'].append({'url': u, 'host': host})
                except Exception:
                    pass

        # Compute file hashes (for VT file-hash lookup)
        results['file_hashes'] = self._compute_file_hashes(extension_dir, manifest)

        # Analyze permissions with details
        results['permissions'] = self.analyze_permissions(manifest)
        
        # Analyze settings overrides
        results['settings_overrides'] = self.analyze_settings_overrides(manifest)

        # Analyze extension's own CSP policy
        results['csp_analysis'] = self._analyze_csp_policy(manifest)

        # Security-prioritized file list: manifest-referenced (background, content_scripts, etc.) first, then by relevance
        js_files = self._prioritize_js_files_for_security(extension_dir, manifest, max_files=300)
        all_js_count = len(list(extension_dir.rglob('*.js')))
        if len(js_files) < all_js_count:
            print(f"[+] Scanning {len(js_files)} security-relevant JS files (manifest + app logic; {all_js_count - len(js_files)} excluded)")
        else:
            print(f"[+] Scanning {len(js_files)} JavaScript files...")
        # Run AST analysis (CRITICAL - shows exact POST destinations)
        print(f"[+] Running AST analysis...")
        _total_files = len(js_files)
        if progress_callback:
            progress_callback(0, "Running AST analysis...")
        try:
            from tqdm import tqdm
            _use_progress = True
        except ImportError:
            _use_progress = False
        if _use_progress:
            # One progress bar for static analysis: 0-50% AST, 50-100% pattern scan
            _total_steps = 2 * _total_files
            _pbar = tqdm(total=_total_steps, desc="Static analysis", unit="file", leave=True, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} ({percentage:3.0f}%)")
            _pbar.update(0)
            results['ast_results'] = self.ast_analyzer.analyze_directory(extension_dir, progress_callback=lambda: _pbar.update(1), js_file_list=js_files)
        else:
            results['ast_results'] = self.ast_analyzer.analyze_directory(extension_dir, js_file_list=js_files)
        if progress_callback:
            progress_callback(50, "AST complete. Scanning files for patterns...")
        
        # Merge AST findings into malicious_patterns
        for exfil in results['ast_results'].get('data_exfiltration', []):
            results['malicious_patterns'].append({
                'name': exfil['type'],
                'severity': 'high',
                'description': f"Sends data to {exfil['destination']}",
                'technique': 'Data Exfiltration',
                'file': exfil.get('file', 'Unknown'),
                'line': exfil.get('line', 0),
                'context': exfil.get('evidence', ''),
                'evidence': exfil.get('evidence', ''),  # Add evidence field for code snippet
                'destination': exfil.get('destination'),  # IMPORTANT: exact URL
                'method': exfil.get('method'),
                'data_source': exfil.get('data_source')
            })
        
        # OPTIMIZED: Read files once and cache them for all analysis passes
        results['scan_coverage'] = {'total_js_files': len(js_files), 'files_with_scan_errors': 0, 'files_fully_scanned': 0}
        for idx, js_file in enumerate(js_files):
            try:
                code = self._read_file_cached(js_file)
                if code is None:
                    continue

                relative_path = str(js_file.relative_to(extension_dir))

                used_fallback = False
                try:
                    patterns_found = self.scan_code(code, relative_path)
                except Exception as scan_err:
                    results['scan_coverage']['files_with_scan_errors'] += 1
                    used_fallback = True
                    print(f"[!] Error scanning {js_file.name}: {scan_err} (using fallback pattern scan)")
                    patterns_found = self._scan_code_minimal(code, relative_path)
                    results['malicious_patterns'].append({
                        'name': 'Obfuscated or minified bundle (full context scan failed)',
                        'severity': 'medium',
                        'description': 'Parser failed on this file; only pattern-based scan was run. Minified/obfuscated bundles often break AST and slicing.',
                        'technique': 'Obfuscation / Parse failure',
                        'file': relative_path,
                        'line': 1,
                        'context': '(fallback scan used)',
                        'fallback_scan': True
                    })
                if not used_fallback:
                    results['scan_coverage']['files_fully_scanned'] += 1
                results['malicious_patterns'].extend(patterns_found)

                try:
                    external = self.find_external_scripts(code, relative_path)
                    results['external_scripts'].extend(external)
                except Exception:
                    pass

                try:
                    obfuscation = self.detect_obfuscation(code)
                    if obfuscation['is_obfuscated']:
                        results['obfuscation_indicators'][relative_path] = obfuscation
                except Exception:
                    pass
                # Extract all URLs and host-like strings from code (closes C2 detection gap, e.g. mcp-browser.qubecare.ai)
                try:
                    extracted = self._extract_urls_and_hosts_from_code(code, relative_path)
                    results['urls_in_code'].extend(extracted)
                except Exception:
                    pass
                if _use_progress:
                    _pbar.update(1)
                if progress_callback and _total_files:
                    phase_pct = 50 + 50 * (idx + 1) // _total_files
                    progress_callback(min(phase_pct, 99), f"File {idx + 1}/{_total_files}")
            except Exception as e:
                results['scan_coverage']['files_with_scan_errors'] += 1
                print(f"[!] Error scanning {js_file.name}: {e}")
                if _use_progress:
                    _pbar.update(1)
                if progress_callback and _total_files:
                    phase_pct = 50 + 50 * (idx + 1) // _total_files
                    progress_callback(min(phase_pct, 99), f"File {idx + 1}/{_total_files}")

        if results['scan_coverage']['files_with_scan_errors']:
            print(f"[i] Scan coverage: {results['scan_coverage']['files_fully_scanned']}/{results['scan_coverage']['total_js_files']} files fully scanned, {results['scan_coverage']['files_with_scan_errors']} with fallback/errors")
        if _use_progress:
            _pbar.close()

        # Deduplicate and suppress noisy informational patterns
        raw_count = len(results['malicious_patterns'])
        results['malicious_patterns'] = self._deduplicate_and_suppress_findings(results['malicious_patterns'])
        deduped_count = len(results['malicious_patterns'])
        if raw_count != deduped_count:
            print(f"[+] Findings: {raw_count} raw -> {deduped_count} after deduplication & noise suppression")

        # Clear file cache after analysis to free memory
        self._clear_file_cache()

        # Sinkhole/localhost detection and infrastructure signals (C2, exfil endpoints, beaconing)
        infra_signals = self._detect_sinkhole_and_infra_signals(results)
        results['infra_signals'] = infra_signals
        if infra_signals.get('sinkhole_or_lab_c2'):
            results['sinkhole_or_lab_c2'] = True
            results['lab_malware_context'] = (
                'All C2/exfil destinations are sinkhole domains (localhost / 127.0.0.1). '
                'Used only to validate that the rule engine detects malicious behavior — not real C2; no data leaves the host.'
            )
            print(f"[i] SINKHOLE: {results['lab_malware_context'][:85]}...")
        
        # Check for known campaign membership
        results['campaign_attribution'] = self.detect_campaign_membership(
            manifest, 
            results['settings_overrides'],
            results['domain_analysis']
        )
        
        # Calculate risk score (ENHANCED - will be updated after VT check)
        results['risk_score'] = self.calculate_enhanced_risk_score(results)
        results['risk_level'] = self.get_risk_level(results['risk_score'])
        
        print(f"[+] Initial Risk Score: {results['risk_score']:.1f}/10 ({results['risk_level']})")
        
        if results['campaign_attribution']:
            campaign = results['campaign_attribution']
            print(f"[!] CAMPAIGN DETECTED: {campaign['name']} (Confidence: {campaign['confidence']})")
        
        return results
    
    def analyze_permissions(self, manifest):
        """Analyze extension permissions with detailed explanations"""
        permissions = manifest.get('permissions', [])
        host_permissions = manifest.get('host_permissions', [])
        optional_permissions = manifest.get('optional_permissions', [])
        
        all_permissions = permissions + host_permissions + optional_permissions
        
        print(f"[+] Permissions: {len(all_permissions)} found")
        
        permission_analysis = {
            'total': len(all_permissions),
            'high_risk': [],
            'medium_risk': [],
            'low_risk': [],
            'all': all_permissions,
            'details': {}
        }
        
        for perm in all_permissions:
            # Get permission details
            perm_info = self.dangerous_permissions.get(perm, None)
            
            if perm_info:
                risk_score = perm_info['score']
                permission_analysis['details'][perm] = perm_info
            elif perm.startswith('http'):
                # Host permission
                if perm in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*']:
                    risk_score = 9
                    permission_analysis['details'][perm] = {
                        'score': 9,
                        'description': f'Access to all websites',
                        'risk': 'CRITICAL - Can read/modify all web pages'
                    }
                else:
                    risk_score = 3
                    permission_analysis['details'][perm] = {
                        'score': 3,
                        'description': f'Access to {perm}',
                        'risk': 'MEDIUM - Limited site access'
                    }
            else:
                risk_score = 0
                permission_analysis['details'][perm] = {
                    'score': 0,
                    'description': perm,
                    'risk': 'LOW - Standard permission'
                }
            
            if risk_score >= 7:
                permission_analysis['high_risk'].append(perm)
                print(f"  [FLAG] HIGH RISK: {perm}")
            elif risk_score >= 4:
                permission_analysis['medium_risk'].append(perm)
                print(f"  [!]  MEDIUM: {perm}")
            else:
                permission_analysis['low_risk'].append(perm)

        # ========== PERMISSION COMBINATION WARNINGS ==========
        # Check for dangerous permission combinations that indicate malicious intent
        permission_set = set(p.lower() if isinstance(p, str) else '' for p in all_permissions)
        permission_analysis['combination_warnings'] = []

        # tabs + storage = URL harvesting pattern
        if 'tabs' in permission_set and 'storage' in permission_set:
            permission_analysis['combination_warnings'].append({
                'name': 'URL Harvesting Pattern',
                'permissions': ['tabs', 'storage'],
                'severity': 'HIGH',
                'description': 'Can harvest visited URLs via tabs API and store them for later exfiltration'
            })
            print("  [FLAG] COMBO WARNING: tabs + storage (URL harvesting pattern)")

        # tabs + <all_urls> = Screen capture capability
        has_all_urls = any(p in ['<all_urls>', '*://*/*', 'http://*/*', 'https://*/*'] for p in all_permissions)
        if 'tabs' in permission_set and has_all_urls:
            permission_analysis['combination_warnings'].append({
                'name': 'Screen Capture Capability',
                'permissions': ['tabs', '<all_urls>'],
                'severity': 'CRITICAL',
                'description': 'Can capture screenshots of any website via captureVisibleTab API'
            })
            print("  [FLAG] COMBO WARNING: tabs + <all_urls> (screen capture capable)")

        # webRequest + <all_urls> = Traffic interception
        if ('webrequest' in permission_set or 'webrequestblocking' in permission_set) and has_all_urls:
            permission_analysis['combination_warnings'].append({
                'name': 'Traffic Interception',
                'permissions': ['webRequest', '<all_urls>'],
                'severity': 'CRITICAL',
                'description': 'Can intercept, modify, or block ALL web traffic including credentials'
            })
            print("  [FLAG] COMBO WARNING: webRequest + <all_urls> (traffic interception)")

        # scripting + <all_urls> = Universal code injection
        if 'scripting' in permission_set and has_all_urls:
            permission_analysis['combination_warnings'].append({
                'name': 'Universal Code Injection',
                'permissions': ['scripting', '<all_urls>'],
                'severity': 'CRITICAL',
                'description': 'Can inject JavaScript into ANY webpage - severe data theft risk'
            })
            print("  [FLAG] COMBO WARNING: scripting + <all_urls> (universal code injection)")

        # clipboardRead + storage = Clipboard theft pattern
        if 'clipboardread' in permission_set and 'storage' in permission_set:
            permission_analysis['combination_warnings'].append({
                'name': 'Clipboard Theft Pattern',
                'permissions': ['clipboardRead', 'storage'],
                'severity': 'HIGH',
                'description': 'Can steal clipboard contents (passwords, crypto addresses) and store for exfiltration'
            })
            print("  [FLAG] COMBO WARNING: clipboardRead + storage (clipboard theft pattern)")

        # history + storage = Browsing history theft
        if 'history' in permission_set and 'storage' in permission_set:
            permission_analysis['combination_warnings'].append({
                'name': 'Browsing History Theft',
                'permissions': ['history', 'storage'],
                'severity': 'HIGH',
                'description': 'Can steal complete browsing history and store for exfiltration'
            })
            print("  [FLAG] COMBO WARNING: history + storage (browsing history theft)")

        # cookies + <all_urls> = Session hijacking
        if 'cookies' in permission_set and has_all_urls:
            permission_analysis['combination_warnings'].append({
                'name': 'Session Hijacking Capability',
                'permissions': ['cookies', '<all_urls>'],
                'severity': 'CRITICAL',
                'description': 'Can steal session cookies from ANY website - account takeover risk'
            })
            print("  [FLAG] COMBO WARNING: cookies + <all_urls> (session hijacking capable)")

        # management = Can disable other extensions (including security extensions)
        if 'management' in permission_set:
            permission_analysis['combination_warnings'].append({
                'name': 'Extension Control',
                'permissions': ['management'],
                'severity': 'HIGH',
                'description': 'Can disable other extensions including security/privacy tools'
            })
            print("  [FLAG] COMBO WARNING: management (can disable security extensions)")

        # proxy = Can route all traffic through attacker server
        if 'proxy' in permission_set:
            permission_analysis['combination_warnings'].append({
                'name': 'Traffic Routing Control',
                'permissions': ['proxy'],
                'severity': 'HIGH',
                'description': 'Can route ALL browser traffic through attacker-controlled proxy server'
            })
            print("  [FLAG] COMBO WARNING: proxy (traffic routing control)")

        # ========== PERMISSION ATTACK-PATH SCORING ==========
        # Score dangerous permission combinations that enable specific attack paths.
        # Each path maps to a real-world attack capability.
        attack_paths = []
        attack_path_score = 0.0

        # 1. Universal Session Theft: cookies + all_urls
        if 'cookies' in permission_set and has_all_urls:
            attack_paths.append({
                'name': 'Universal Session Theft',
                'permissions': ['cookies', '<all_urls>'],
                'severity': 'CRITICAL',
                'score': 3.0,
                'description': 'Can steal session cookies from ANY website for account takeover',
            })
            attack_path_score += 3.0

        # 2. Universal Code Injection: scripting + all_urls
        if 'scripting' in permission_set and has_all_urls:
            attack_paths.append({
                'name': 'Universal Code Injection',
                'permissions': ['scripting', '<all_urls>'],
                'severity': 'CRITICAL',
                'score': 3.0,
                'description': 'Can inject arbitrary JavaScript into ANY webpage',
            })
            attack_path_score += 3.0

        # 3. Traffic Interception/MitM: webRequest + webRequestBlocking + all_urls
        has_blocking = 'webrequestblocking' in permission_set
        if ('webrequest' in permission_set or has_blocking) and has_all_urls:
            path_score = 3.0 if has_blocking else 2.0
            attack_paths.append({
                'name': 'Traffic Interception' + (' / MitM' if has_blocking else ''),
                'permissions': ['webRequest', 'webRequestBlocking', '<all_urls>'] if has_blocking else ['webRequest', '<all_urls>'],
                'severity': 'CRITICAL' if has_blocking else 'HIGH',
                'score': path_score,
                'description': 'Can intercept' + (', modify, or block' if has_blocking else '') + ' ALL web traffic',
            })
            attack_path_score += path_score

        # 4. Extension Kill Chain: management + scripting
        if 'management' in permission_set and ('scripting' in permission_set or has_all_urls):
            attack_paths.append({
                'name': 'Extension Kill Chain',
                'permissions': ['management', 'scripting'],
                'severity': 'HIGH',
                'score': 2.0,
                'description': 'Can disable security extensions and inject replacement code',
            })
            attack_path_score += 2.0

        # 5. Crypto Address Swap: clipboardRead + clipboardWrite
        if 'clipboardread' in permission_set and 'clipboardwrite' in permission_set:
            attack_paths.append({
                'name': 'Crypto Address Swap',
                'permissions': ['clipboardRead', 'clipboardWrite'],
                'severity': 'HIGH',
                'score': 1.5,
                'description': 'Can read clipboard for wallet addresses and replace with attacker address',
            })
            attack_path_score += 1.5

        # 6. System Escape: nativeMessaging + any dangerous capability
        if 'nativemessaging' in permission_set:
            attack_paths.append({
                'name': 'Native System Escape',
                'permissions': ['nativeMessaging'],
                'severity': 'HIGH',
                'score': 2.0,
                'description': 'Can communicate with native binaries, escaping browser sandbox',
            })
            attack_path_score += 2.0

        # 7. Full Surveillance: tabs + all_urls + history
        if 'tabs' in permission_set and has_all_urls and 'history' in permission_set:
            attack_paths.append({
                'name': 'Full Browsing Surveillance',
                'permissions': ['tabs', '<all_urls>', 'history'],
                'severity': 'HIGH',
                'score': 2.0,
                'description': 'Can monitor all tab activity, URL history, and page content',
            })
            attack_path_score += 2.0

        # 8. Screen Recording: desktopCapture OR tabCapture
        if 'desktopcapture' in permission_set or 'tabcapture' in permission_set:
            attack_paths.append({
                'name': 'Screen / Tab Recording',
                'permissions': ['desktopCapture' if 'desktopcapture' in permission_set else 'tabCapture'],
                'severity': 'HIGH',
                'score': 2.0,
                'description': 'Can record screen or tab content including sensitive information',
            })
            attack_path_score += 2.0

        permission_analysis['attack_paths'] = attack_paths
        permission_analysis['attack_path_score'] = min(attack_path_score, 10.0)

        if attack_paths:
            print(f"\n  [ATTACK PATHS] {len(attack_paths)} enabled:")
            for ap in attack_paths:
                print(f"    [{ap['severity']}] {ap['name']} (score +{ap['score']})")

        return permission_analysis
    
    def _analyze_csp_policy(self, manifest):
        """Parse and score the extension's own Content Security Policy.

        A lax or absent CSP enables eval-based attacks and remote code loading.
        Returns dict with findings list and a 0-5 risk score.
        """
        # MV2: string, MV3: dict with extension_pages / sandbox
        raw_csp = manifest.get('content_security_policy', '')
        mv3_csp = ''
        if isinstance(raw_csp, dict):
            mv3_csp = raw_csp.get('extension_pages', '')
            sandbox_csp = raw_csp.get('sandbox', '')
            raw_csp = mv3_csp or sandbox_csp
        csp = raw_csp if isinstance(raw_csp, str) else ''

        findings = []
        score = 0

        mv = manifest.get('manifest_version', 2)

        if not csp:
            # MV2 without CSP is risky; MV3 has default strict CSP
            if mv == 2:
                findings.append({
                    'name': 'No Content Security Policy defined (MV2)',
                    'severity': 'high',
                    'description': (
                        'Manifest V2 extension has no CSP. Default MV2 CSP allows '
                        'unsafe-eval. Define a strict CSP to prevent code injection.'
                    ),
                    'technique': 'CSP weakness',
                })
                score += 3
            else:
                # MV3 has strict default - absence is fine
                findings.append({
                    'name': 'Default CSP (MV3 strict)',
                    'severity': 'low',
                    'description': 'Using MV3 default CSP which blocks unsafe-eval.',
                    'technique': 'CSP policy',
                })
        else:
            # Parse directives
            csp_lower = csp.lower()

            if "'unsafe-eval'" in csp_lower or 'unsafe-eval' in csp_lower:
                findings.append({
                    'name': 'CSP allows unsafe-eval',
                    'severity': 'high',
                    'description': (
                        "Extension's CSP includes 'unsafe-eval', enabling eval(), "
                        'new Function(), and other dynamic code execution. This '
                        'defeats the primary protection against code injection.'
                    ),
                    'technique': 'CSP weakness',
                })
                score += 3

            if "'unsafe-inline'" in csp_lower or 'unsafe-inline' in csp_lower:
                findings.append({
                    'name': 'CSP allows unsafe-inline',
                    'severity': 'medium',
                    'description': (
                        "Extension's CSP includes 'unsafe-inline', allowing inline "
                        'scripts. This weakens XSS protections.'
                    ),
                    'technique': 'CSP weakness',
                })
                score += 1

            # Wildcard or overly broad script-src
            if "script-src *" in csp_lower or "script-src https:" in csp_lower:
                findings.append({
                    'name': 'CSP allows wildcard script sources',
                    'severity': 'high',
                    'description': (
                        'CSP script-src allows scripts from any HTTPS source. '
                        'Attacker can load malicious scripts from any domain.'
                    ),
                    'technique': 'CSP weakness',
                })
                score += 2

            # Check for data: URI in script-src (enables inline base64 scripts)
            if "data:" in csp_lower and "script-src" in csp_lower:
                findings.append({
                    'name': 'CSP allows data: URI scripts',
                    'severity': 'medium',
                    'description': (
                        'CSP allows data: URIs in script-src, enabling base64-encoded '
                        'inline scripts which can bypass content filtering.'
                    ),
                    'technique': 'CSP weakness',
                })
                score += 1

            # Strict CSP is a positive signal
            if score == 0 and csp:
                findings.append({
                    'name': 'Strict CSP defined',
                    'severity': 'low',
                    'description': 'Extension defines a restrictive CSP without unsafe directives.',
                    'technique': 'CSP policy',
                })

        return {
            'raw_csp': csp,
            'manifest_version': mv,
            'findings': findings,
            'score': min(score, 5),
        }

    def analyze_settings_overrides(self, manifest):
        """Analyze chrome_settings_overrides for hijacking"""
        overrides = manifest.get('chrome_settings_overrides', {})
        url_overrides = manifest.get('chrome_url_overrides', {})
        
        findings = {
            'has_overrides': False,
            'search_hijacking': None,
            'homepage_hijacking': None,
            'startup_hijacking': None,
            'newtab_hijacking': None,
            'severity': 'NONE'
        }
        
        if 'search_provider' in overrides:
            findings['has_overrides'] = True
            search_provider = overrides['search_provider']
            search_url = search_provider.get('search_url', '')
            
            affiliate_params = self._detect_affiliate_params(search_url)
            
            findings['search_hijacking'] = {
                'search_url': search_url,
                'name': search_provider.get('name', 'Unknown'),
                'has_affiliate_params': bool(affiliate_params),
                'affiliate_params': affiliate_params,
                'severity': 'CRITICAL' if affiliate_params else 'HIGH'
            }
            
            print(f"  [ALERT] SEARCH HIJACKING DETECTED: {search_url}")
            if affiliate_params:
                print(f"     Affiliate params: {', '.join(affiliate_params)}")
        
        if 'homepage' in overrides:
            findings['has_overrides'] = True
            findings['homepage_hijacking'] = {
                'url': overrides['homepage'],
                'severity': 'HIGH'
            }
            print(f"  [ALERT] HOMEPAGE HIJACKING: {overrides['homepage']}")
        
        if 'startup_pages' in overrides:
            findings['has_overrides'] = True
            findings['startup_hijacking'] = {
                'urls': overrides['startup_pages'],
                'severity': 'HIGH'
            }
            print(f"  [ALERT] STARTUP HIJACKING: {len(overrides['startup_pages'])} pages")
        
        if 'newtab' in url_overrides:
            findings['has_overrides'] = True
            findings['newtab_hijacking'] = {
                'url': url_overrides['newtab'],
                'severity': 'MEDIUM'
            }
            print(f"  [!]  NEW TAB OVERRIDE: {url_overrides['newtab']}")
        
        if findings['search_hijacking']:
            findings['severity'] = findings['search_hijacking']['severity']
        elif findings['homepage_hijacking'] or findings['startup_hijacking']:
            findings['severity'] = 'HIGH'
        elif findings['newtab_hijacking']:
            findings['severity'] = 'MEDIUM'
        
        return findings
    
    def _detect_affiliate_params(self, url):
        """Detect affiliate/tracking parameters in URL"""
        found_params = []
        for marker in self.affiliate_markers:
            if marker in url:
                found_params.append(marker.rstrip('='))
        return found_params

    @staticmethod
    def _safe_slice(text, start, end):
        """Slice text with start/end; coerce to int to avoid 'slice indices must be integers' on minified/bundled code."""
        try:
            start = int(start) if start is not None else 0
            end = int(end) if end is not None else len(text)
            start = max(0, min(start, len(text)))
            end = max(0, min(end, len(text)))
            return text[start:end]
        except (TypeError, ValueError):
            return text

    @staticmethod
    def _safe_int(val, default=0, min_val=None, max_val=None):
        """Coerce to int for use as slice/index; avoid float/None from parsers or regex."""
        try:
            i = int(val)
            if min_val is not None:
                i = max(min_val, i)
            if max_val is not None:
                i = min(max_val, i)
            return i
        except (TypeError, ValueError):
            return default

    def _is_in_comment(self, code, position):
        """Check if a position in code is inside a comment

        Returns True if the position is:
        - After // on the same line (single-line comment)
        - Inside /* ... */ (multi-line comment)
        """
        position = self._safe_int(position, 0, 0, len(code))
        line_start = code.rfind('\n', 0, position) + 1
        line_content = self._safe_slice(code, line_start, position)

        # Check if preceded by // on same line (but not part of URL like https://)
        if '//' in line_content:
            # Make sure it's not a URL (https://, http://)
            comment_pos = line_content.rfind('//')
            before_comment = line_content[:comment_pos]
            if not before_comment.rstrip().endswith((':', '"', "'")):
                return True

        # Check if inside /* */ comment
        last_open = code.rfind('/*', 0, position)
        if last_open != -1:
            last_close = code.rfind('*/', 0, position)
            if last_close < last_open:
                return True

        return False

    @staticmethod
    def _safe_pattern_finditer(code, anchor_re, tail_re, max_gap):
        """Two-pass regex matching that avoids catastrophic backtracking.

        Instead of a single regex with a wide [\\s\\S]{0,N} gap (N >= 200),
        we first find all anchor matches, then search a bounded window
        after each anchor for the tail pattern.  This keeps the regex engine
        workload linear in file size.
        """
        for anchor_match in anchor_re.finditer(code):
            a_end = EnhancedStaticAnalyzer._safe_int(anchor_match.end(), 0, 0, len(code))
            window_end = min(a_end + max_gap, len(code))
            window = EnhancedStaticAnalyzer._safe_slice(code, a_end, window_end)
            tail_match = tail_re.search(window)
            if tail_match:
                full_start = EnhancedStaticAnalyzer._safe_int(anchor_match.start(), 0, 0, len(code))
                full_end = min(len(code), a_end + EnhancedStaticAnalyzer._safe_int(tail_match.end(), 0, 0, len(window)))
                snippet = EnhancedStaticAnalyzer._safe_slice(code, full_start, full_end)
                yield type('_M', (), {
                    'start': lambda s=full_start: s,
                    'end':   lambda e=full_end: e,
                    'group': lambda n=0, t=snippet: t if n == 0 else '',
                })()

    def scan_code(self, code, file_path):
        """Scan code for malicious patterns with extended context for code snippets

        OPTIMIZED: Uses pre-compiled regex patterns for ~3-5x speedup on large files
        FALSE POSITIVE REDUCTION:
        - Skips matches found inside comments
        - Flags matches in known library code (downgraded severity)
        """
        found_patterns = []
        lines = code.split('\n')

        # Check if this is library code (findings will be flagged)
        is_library = self._is_library_code(code, file_path)

        # Use pre-compiled patterns for better performance
        for pattern_def in self._compiled_patterns:
            # Two-pass matching for wide-gap patterns to avoid backtracking
            if pattern_def.get('two_pass') and pattern_def.get('tail'):
                matches = self._safe_pattern_finditer(
                    code, pattern_def['compiled'],
                    pattern_def['tail'], pattern_def['max_gap'])
            else:
                matches = pattern_def['compiled'].finditer(code)

            for match in matches:
                start_pos = self._safe_int(match.start(), 0, 0, len(code))
                if self._is_in_comment(code, start_pos):
                    continue

                line_num = self._safe_int(self._safe_slice(code, 0, start_pos).count('\n') + 1, 1, 1, len(lines))

                # Get 3 lines before and 3 lines after (7 lines total context)
                context_start = self._safe_int(line_num - 4, 0, 0, len(lines))
                context_end = self._safe_int(line_num + 3, 0, 0, len(lines))
                context_end = min(context_end, len(lines))

                # Build context with line numbers for display
                context_lines = []
                for i in range(context_start, context_end):
                    line_indicator = '>>>' if i == line_num - 1 else '   '
                    context_lines.append(f"{line_indicator} {i + 1:4d} | {lines[i]}")

                context_with_numbers = '\n'.join(context_lines)

                # Also keep raw context for other uses
                raw_context = '\n'.join(lines[context_start:context_end])

                # Get the matched text itself
                matched_text = match.group(0)[:100]  # Limit match preview

                # Downgrade severity for library code
                effective_severity = pattern_def['severity']
                downgrade_reason = None

                if is_library and effective_severity in ['high', 'critical']:
                    effective_severity = 'low'
                    downgrade_reason = 'library_code'

                # Check for first-party domain in network-related patterns
                is_first_party = False
                first_party_domain = None
                network_techniques = ['Network request', 'Authenticated request', 'Network communication', 'Data exfiltration']

                if pattern_def.get('technique') in network_techniques:
                    is_first_party, first_party_domain = self._is_first_party_domain(raw_context)
                    if is_first_party and effective_severity in ['high', 'medium']:
                        effective_severity = 'low'
                        downgrade_reason = f'first_party_domain:{first_party_domain}'

                # ── FP suppression: skip findings that need extra context we can check here ──
                pname = pattern_def.get('name', '')
                if pname == 'Keystroke Buffer Array':
                    if not re.search(r'addEventListener\s*\(\s*["\']key(down|up|press)', code, re.IGNORECASE):
                        continue  # No keyboard listener in file → library/metadata usage, not keylogger
                if pname == 'Input Value Direct Access':
                    combined = (raw_context or '') + (matched_text or '')
                    if not re.search(r'(password|credit|card|ssn|cvv|fetch\s*\(|XMLHttpRequest|sendBeacon)', combined, re.IGNORECASE):
                        continue  # No sensitive field or exfil in context → generic form handling
                if pname == 'Chrome Storage Sync Abuse':
                    combined = (raw_context or '') + (matched_text or '')
                    has_benign = bool(re.search(r'(analytics|settings|preferences|config|options|theme|enabled|whitelist|blocklist)', combined, re.IGNORECASE))
                    has_sensitive = bool(re.search(r'(password|credential|cookie|token|session|auth|credit|card)', combined, re.IGNORECASE))
                    if has_benign and not has_sensitive:
                        continue  # Only storing settings/analytics, not credentials

                found_patterns.append({
                    'name': pattern_def['name'],
                    'severity': effective_severity,
                    'original_severity': pattern_def['severity'] if (is_library or is_first_party) else None,
                    'description': pattern_def['description'],
                    'technique': pattern_def.get('technique', 'Unknown'),
                    'file': file_path,
                    'line': line_num,
                    'context': raw_context[:500],
                    'context_with_lines': context_with_numbers,
                    'matched_text': matched_text,
                    'context_start_line': context_start + 1,
                    'context_end_line': context_end,
                    'is_library_code': is_library,
                    'is_first_party': is_first_party,
                    'first_party_domain': first_party_domain,
                    'downgrade_reason': downgrade_reason
                })

        return found_patterns

    # ── Patterns that are purely informational / too noisy to keep at volume ──
    _INFORMATIONAL_NOISE = frozenset({
        'localStorage Access',
        'Prototype Reference (Informational)',
        'Tab URL Access (Informational)',
        'XMLHttpRequest (Informational)',
    })

    # ── Patterns that are contextual — only meaningful when paired with other signals.
    #    We keep at most MAX_PER_NAME occurrences per extension to prevent report flooding.
    _CONTEXTUAL_CAP_PATTERNS = frozenset({
        'Input Value Direct Access',
        'Fetch POST Request (Review Destination)',
        'Unicode Escape Obfuscation',
        'Comment-Based Code Hiding',
        'Headless Browser Detection',
        'Background Worker',
        'Random ID Generation for Tracking',
        'Autofill Attribute Manipulation',
    })
    _MAX_PER_NAME = 3  # keep at most 3 instances of capped patterns

    def _deduplicate_and_suppress_findings(self, patterns):
        """Deduplicate and suppress noisy findings.

        1. **Suppress informational noise** — patterns that are standard web APIs
           (localStorage, __proto__, tab.url, XHR) are dropped entirely; their signal
           is already captured by the behavioral engine if combined with real threats.
        2. **Deduplicate exact repeats** — same (pattern_name, file) pair is kept once;
           a ``duplicate_count`` field records how many were collapsed.
        3. **Cap contextual patterns** — patterns that are only meaningful with context
           are capped at _MAX_PER_NAME per extension to stop report flooding.
        """
        # Step 1: Remove pure informational noise
        filtered = [p for p in patterns if p.get('name') not in self._INFORMATIONAL_NOISE]

        # Step 2: Deduplicate by (name, file)
        seen = {}  # (name, file) -> index in output list
        deduped = []
        for p in filtered:
            key = (p.get('name', ''), p.get('file', ''))
            if key in seen:
                idx = seen[key]
                deduped[idx]['duplicate_count'] = deduped[idx].get('duplicate_count', 1) + 1
            else:
                seen[key] = len(deduped)
                p['duplicate_count'] = 1
                deduped.append(p)

        # Step 3: Cap contextual / volume patterns
        name_counts = {}
        capped = []
        for p in deduped:
            name = p.get('name', '')
            if name in self._CONTEXTUAL_CAP_PATTERNS:
                cnt = name_counts.get(name, 0)
                if cnt >= self._MAX_PER_NAME:
                    # Still count for severity but don't add to list
                    # Update the last kept occurrence's count
                    for prev in reversed(capped):
                        if prev.get('name') == name:
                            prev['duplicate_count'] = prev.get('duplicate_count', 1) + p.get('duplicate_count', 1)
                            break
                    continue
                name_counts[name] = cnt + 1
            capped.append(p)

        return capped

    def _scan_code_minimal(self, code, file_path):
        """Fallback when full scan_code fails: pattern match only, no context. Avoids silent skip of critical files."""
        found = []
        for pattern_def in self._compiled_patterns:
            try:
                if pattern_def.get('two_pass') and pattern_def.get('tail'):
                    matches = self._safe_pattern_finditer(
                        code, pattern_def['compiled'],
                        pattern_def['tail'], pattern_def['max_gap'])
                else:
                    matches = pattern_def['compiled'].finditer(code)
                for match in matches:
                    start_pos = self._safe_int(match.start(), 0, 0, len(code))
                    line_num = self._safe_int(
                        self._safe_slice(code, 0, start_pos).count('\n') + 1, 1, 1, 2**31 - 1)
                    found.append({
                        'name': pattern_def['name'],
                        'severity': pattern_def['severity'],
                        'description': pattern_def['description'],
                        'technique': pattern_def.get('technique', 'Unknown'),
                        'file': file_path,
                        'line': line_num,
                        'context': '(fallback scan - context unavailable)',
                        'context_with_lines': '',
                        'matched_text': (match.group(0) or '')[:100],
                        'is_library_code': False,
                        'fallback_scan': True
                    })
            except Exception:
                continue
        return found

    def find_external_scripts(self, code, file_path):
        """Find external script URLs"""
        external = []
        url_pattern = r'https?://[^\s\'"<>]+'
        matches = re.finditer(url_pattern, code)
        
        for match in matches:
            url = match.group(0)
            if any(cdn in url for cdn in ['googleapis.com', 'cdnjs.cloudflare.com', 'unpkg.com']):
                continue
            start_pos = self._safe_int(match.start(), 0, 0, len(code))
            line_num = self._safe_slice(code, 0, start_pos).count('\n') + 1
            external.append({
                'url': url,
                'file': file_path,
                'line': self._safe_int(line_num, 1, 1, 2**31 - 1)
            })
        
        return external
    
    # Max sample size for obfuscation checks (avoids ReDoS on huge minified bundles)
    _OBFUSCATION_SAMPLE_SIZE = 300 * 1024  # 300 KiB

    def detect_obfuscation(self, code):
        """Detect if code is obfuscated. Samples large files to avoid ReDoS/slowness."""
        sample = code[:self._OBFUSCATION_SAMPLE_SIZE] if len(code) > self._OBFUSCATION_SAMPLE_SIZE else code
        entropy = self.calculate_entropy(sample)
        hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', sample))
        unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', sample))
        long_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]{50,}\b', sample))
        single_letters = len(re.findall(r'\b[a-zA-Z_$]\b', sample))
        total_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b', sample))
        single_letter_ratio = single_letters / max(total_vars, 1)
        
        is_obfuscated = (
            entropy > 4.5 or
            hex_escapes > 50 or
            unicode_escapes > 50 or
            long_vars > 10 or
            single_letter_ratio > 0.3
        )
        
        return {
            'is_obfuscated': is_obfuscated,
            'entropy': entropy,
            'hex_escapes': hex_escapes,
            'unicode_escapes': unicode_escapes,
            'long_variables': long_vars,
            'single_letter_ratio': single_letter_ratio
        }
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data. O(n) single-pass (was O(256*n))."""
        if not data:
            return 0
        try:
            raw = data.encode('utf-8', errors='ignore')
        except Exception:
            return 0
        n = len(raw)
        if n == 0:
            return 0
        counts = [0] * 256
        for b in raw:
            counts[b] += 1
        entropy = 0
        for c in counts:
            if c > 0:
                p_x = c / n
                entropy += -p_x * math.log2(p_x)
        return entropy

    # Hosts that indicate sinkhole (localhost only — used for rule-engine validation, not real C2)
    _LOCALHOST_PATTERNS = re.compile(
        r'127\.0\.0\.1|::1|\blocalhost\b|\[::1\]',
        re.I
    )

    def _normalize_host(self, url_or_host):
        """Extract host from URL or return as-is if already a host. Returns None if not parseable."""
        if not url_or_host or not isinstance(url_or_host, str):
            return None
        s = url_or_host.strip()
        if not s:
            return None
        if '://' in s:
            try:
                return urlparse(s).hostname
            except Exception:
                return None
        if '/' in s:
            return s.split('/')[0].split(':')[0]
        return s.split(':')[0] if ':' in s else s

    def _is_localhost_host(self, host):
        """True if host is 127.0.0.1, ::1, or localhost."""
        if not host:
            return False
        return bool(self._LOCALHOST_PATTERNS.search(host))

    # Valid public TLDs / ccTLDs (most common). If last label isn't here, reject.
    _VALID_TLDS = frozenset({
        'com', 'org', 'net', 'io', 'ai', 'co', 'dev', 'app', 'xyz', 'info',
        'biz', 'me', 'tv', 'cc', 'us', 'uk', 'de', 'fr', 'ru', 'cn', 'jp',
        'br', 'in', 'au', 'ca', 'es', 'it', 'nl', 'se', 'no', 'fi', 'pl',
        'cz', 'at', 'ch', 'be', 'pt', 'dk', 'ie', 'nz', 'kr', 'sg', 'hk',
        'tw', 'id', 'th', 'ph', 'my', 'vn', 'mx', 'ar', 'cl', 'za', 'ng',
        'ke', 'ua', 'ro', 'hu', 'bg', 'hr', 'sk', 'si', 'lt', 'lv', 'ee',
        'top', 'icu', 'email', 'cloud', 'site', 'online', 'store', 'tech',
        'live', 'today', 'space', 'fun', 'website', 'shop', 'pro', 'click',
        'link', 'club', 'pw', 'tk', 'ml', 'ga', 'cf', 'gq', 'ws', 'buzz',
        'one', 'gg', 'ly', 'to', 'sh', 'eu', 'edu', 'gov', 'mil', 'int',
    })

    # CamelCase pattern: two or more uppercase-starting segments = JS identifier, not a domain
    _CAMEL_CASE_RE = re.compile(r'[A-Z][a-z]+[A-Z]')

    # Known browser/extension API namespaces that are NOT domains
    _API_NAMESPACE_PREFIXES = (
        'chrome.', 'browser.', 'window.', 'document.', 'console.',
        'Permissions.', 'InternalAnalytics.', 'BlockElementModule.',
        'AntiMaleWare.', 'AdBlock.', 'ABP.', 'FilterStorage.',
        'Math.', 'JSON.', 'Object.', 'Array.', 'Promise.',
        'Error.', 'RegExp.', 'Date.', 'Number.', 'String.',
        'Map.', 'Set.', 'WeakMap.', 'WeakSet.', 'Symbol.',
        'Reflect.', 'Proxy.', 'Intl.', 'WebAssembly.',
    )

    def _is_plausible_host(self, host):
        """True if string looks like a real network hostname (not a JS identifier
        or API namespace like 'Permissions.PermissionsAdded').

        Rejects:
          - Code fragments with < > + spaces
          - CamelCase identifiers (e.g. InternalAnalytics.TrackEvent)
          - Known browser API namespaces (chrome.*, Permissions.*, etc.)
          - Strings whose last label is not a valid public TLD
        """
        if not host or not isinstance(host, str):
            return False
        h = host.strip()
        if not h or len(h) > 253:
            return False
        # Reject code fragments
        if '<' in h or '>' in h or '+' in h or ' ' in h or '=' in h or '(' in h:
            return False
        # Localhost is always valid
        if self._LOCALHOST_PATTERNS.search(h):
            return True
        # Reject known API namespaces
        for prefix in self._API_NAMESPACE_PREFIXES:
            if h.startswith(prefix):
                return False
        # Reject CamelCase identifiers (e.g. BlockElementModule.Options)
        if self._CAMEL_CASE_RE.search(h):
            return False
        # Must match hostname charset
        if not re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9.\-]*[a-zA-Z0-9])?$', h):
            return False
        # Must have at least one dot (single-label strings are not domains)
        parts = h.split('.')
        if len(parts) < 2:
            return False
        # Last label must be a known TLD
        tld = parts[-1].lower()
        if tld not in self._VALID_TLDS:
            return False
        return True

    # Regex to find URLs and quoted FQDNs in code (closes gap for C2 domains like mcp-browser.qubecare.ai)
    _URL_IN_CODE_PATTERN = re.compile(
        r'https?://([^\s\'"<>)\]\},;]+)|wss?://([^\s\'"<>)\]\},;]+)',
        re.IGNORECASE
    )
    _QUOTED_FQDN_PATTERN = re.compile(
        r'["\']([a-zA-Z0-9](?:[-a-zA-Z0-9.]*[a-zA-Z0-9])?\.[a-zA-Z]{2,})["\']'
    )

    # ── File hash computation ─────────────────────────────────────

    def _compute_file_hashes(self, extension_dir, manifest):
        """
        Compute SHA-256 hashes of the files that actually carry malicious
        payloads and are most likely to already exist in VT's database.

        Only the high-value targets:
          - manifest.json  — unique extension fingerprint
          - manifest.js    — dynamic config loader (if present)
          - Background scripts / service worker — C2, beaconing, exfil logic
          - Content scripts — injected into victim pages, credential theft

        Popup JS and web-accessible resources are excluded: they are almost
        never the primary payload and waste VT API calls.

        Returns list of dicts: [{sha256, filename, file_path}, ...]
        """
        hashes = []
        seen_paths = set()

        def _hash_file(fpath):
            """Read file and return SHA-256 hex digest, or None on error."""
            try:
                data = fpath.read_bytes()
                return hashlib.sha256(data).hexdigest()
            except Exception as e:
                print(f"[!] Hash error for {fpath.name}: {e}")
                return None

        def _add(fpath, label=None):
            resolved = fpath.resolve()
            if resolved in seen_paths or not fpath.is_file():
                return
            seen_paths.add(resolved)
            digest = _hash_file(fpath)
            if digest:
                hashes.append({
                    'sha256': digest,
                    'filename': label or fpath.name,
                    'file_path': str(fpath),
                })

        # 1. manifest.json — always; extension fingerprint
        _add(extension_dir / 'manifest.json')

        # 2. manifest.js — dynamic config loader (if present)
        manifest_js = extension_dir / 'manifest.js'
        if manifest_js.is_file():
            _add(manifest_js)

        # 3. Background: MV3 service worker
        bg = manifest.get('background', {})
        sw = bg.get('service_worker')
        if sw:
            _add(extension_dir / sw, f'background/{sw}')

        # 4. Background: MV2 scripts / page
        for script in bg.get('scripts', []):
            _add(extension_dir / script, f'background/{script}')
        bg_page = bg.get('page')
        if bg_page:
            _add(extension_dir / bg_page, f'background/{bg_page}')

        # 5. Content scripts — page-injected payloads
        for cs_block in manifest.get('content_scripts', []):
            for js in cs_block.get('js', []):
                _add(extension_dir / js, f'content_script/{js}')

        if hashes:
            print(f"[+] Computed SHA-256 hashes for {len(hashes)} key file(s)")

        return hashes

    def _extract_urls_and_hosts_from_code(self, code, file_path):
        """Extract all URL and host-like literals from code for C2/domain detection. Returns list of {url, host, file, line}."""
        out = []
        if not code or not isinstance(code, str):
            return out
        lines = code.split('\n')
        for idx, line in enumerate(lines, 1):
            # Full URLs (http/https/ws/wss)
            for m in self._URL_IN_CODE_PATTERN.finditer(line):
                g1, g2 = m.group(1), m.group(2)
                host = (g1 or g2 or '').strip()
                if host:
                    host = host.split('/')[0].split(':')[0]
                if host and self._is_plausible_host(host):
                    full = m.group(0)
                    out.append({'url': full, 'host': host, 'file': file_path, 'line': idx})
            # Quoted FQDN-only strings (e.g. "mcp-browser.qubecare.ai")
            for m in self._QUOTED_FQDN_PATTERN.finditer(line):
                host = (m.group(1) or '').strip()
                if host and self._is_plausible_host(host):
                    out.append({'url': host, 'host': host, 'file': file_path, 'line': idx})
        return out

    def _detect_sinkhole_and_infra_signals(self, results):
        """
        Detect (1) if all C2/exfil destinations are sinkhole domains (localhost only —
        used to validate the rule engine, not real C2) and (2) infrastructure signals
        for risk: exfil endpoint count, WebSocket C2, beaconing.
        Returns dict with sinkhole_or_lab_c2, exfil_endpoint_count, has_websocket_c2, has_beaconing.
        """
        hosts = set()
        endpoints_seen = set()
        has_websocket_c2 = False
        has_beaconing = False

        # From AST data_exfiltration and network_calls
        ast_results = results.get('ast_results', {})
        for exfil in ast_results.get('data_exfiltration', []):
            dest = exfil.get('destination', '') or ''
            if dest:
                endpoints_seen.add(dest)
            host = self._normalize_host(dest)
            if host and self._is_plausible_host(host):
                hosts.add(host)
        for call in ast_results.get('network_calls', []):
            url = call.get('url', '') or call.get('destination', '') or ''
            if url:
                endpoints_seen.add(url)
            host = self._normalize_host(url)
            if host and self._is_plausible_host(host):
                hosts.add(host)
            if (call.get('type') or '').lower() == 'websocket':
                has_websocket_c2 = True

        # From malicious_patterns (destination, context)
        for p in results.get('malicious_patterns', []):
            dest = p.get('destination', '') or ''
            ctx = p.get('context', '') or p.get('evidence', '') or ''
            if dest:
                endpoints_seen.add(dest)
                h = self._normalize_host(dest)
                if h and self._is_plausible_host(h):
                    hosts.add(h)
            if 'WebSocket' in (p.get('technique') or ''):
                has_websocket_c2 = True
            # Scan context for URLs/hosts
            for part in (dest, ctx):
                if not part:
                    continue
                if self._LOCALHOST_PATTERNS.search(part):
                    hosts.add('127.0.0.1')
                match = re.search(r'https?://([^\s\'"<>/]+)', part)
                if match:
                    h = match.group(1).split(':')[0]
                    if self._is_plausible_host(h):
                        hosts.add(h)
                match = re.search(r'ws[s]?://([^\s\'"<>/]+)', part, re.I)
                if match:
                    h = match.group(1).split(':')[0]
                    if self._is_plausible_host(h):
                        hosts.add(h)
                    has_websocket_c2 = True
            # Beaconing: setInterval + fetch
            if 'setInterval' in ctx and ('fetch' in ctx or 'ping' in ctx or 'beacon' in ctx.lower()):
                has_beaconing = True

        # From whole-file URL/host extraction (closes gap for C2 like mcp-browser.qubecare.ai)
        for item in results.get('urls_in_code', []):
            url = item.get('url') or ''
            host = item.get('host') or ''
            if url:
                endpoints_seen.add(url)
            if host and self._is_plausible_host(host):
                hosts.add(host)
        # From manifest URLs (privacy_policy_url, homepage_url, update_url)
        for item in results.get('manifest_urls', []):
            url = item.get('url') or ''
            host = item.get('host') or ''
            if url:
                endpoints_seen.add(url)
            if host and self._is_plausible_host(host):
                hosts.add(host)

        # From permissions (host_permissions / all)
        perm_all = results.get('permissions', {}).get('all', [])
        for perm in perm_all:
            if isinstance(perm, str) and ('://' in perm or '127.0.0.1' in perm or 'localhost' in perm):
                host = self._normalize_host(perm)
                if host and self._is_plausible_host(host):
                    hosts.add(host)
                elif isinstance(perm, str) and self._LOCALHOST_PATTERNS.search(perm):
                    hosts.add('127.0.0.1')

        # Sinkhole: we have at least one network destination and all are localhost
        only_localhost = bool(hosts) and all(self._is_localhost_host(h) for h in hosts)
        # Fallback: if we have exfil/C2 and localhost appears in permissions or code, treat as lab
        has_localhost_in_perms = any(
            isinstance(p, str) and self._LOCALHOST_PATTERNS.search(p)
            for p in perm_all
        )
        has_localhost_in_code = any(
            self._LOCALHOST_PATTERNS.search((p.get('context') or '') + (p.get('evidence') or '') + (p.get('destination') or ''))
            for p in results.get('malicious_patterns', [])
        )
        if (endpoints_seen or has_websocket_c2) and (has_localhost_in_perms or has_localhost_in_code):
            hosts.add('127.0.0.1')
            only_localhost = True
        else:
            only_localhost = bool(hosts) and all(self._is_localhost_host(h) for h in hosts)

        return {
            'sinkhole_or_lab_c2': only_localhost,
            'exfil_endpoint_count': len(endpoints_seen),
            'has_websocket_c2': has_websocket_c2,
            'has_beaconing': has_beaconing,
            'all_hosts_localhost': only_localhost,
        }

    def detect_campaign_membership(self, manifest, settings_overrides, domain_analysis):
        """Check if extension matches known malicious campaigns"""
        
        if settings_overrides.get('search_hijacking'):
            search_info = settings_overrides['search_hijacking']
            search_url = search_info['search_url'].lower()
            
            if ('yahoo.com/search' in search_url and 'fr=' in search_url):
                return {
                    'name': 'DarkSpectre / ZoomStealer',
                    'confidence': 'HIGH',
                    'indicators': [
                        'Yahoo search hijacking with affiliate parameter (fr=)',
                        'Known DarkSpectre campaign pattern'
                    ],
                    'description': 'Part of campaign that infected 7.8M+ browsers',
                    'reference': 'https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers',
                    'severity': 'CRITICAL'
                }
            
            if ('bing.com/search' in search_url and 'pc=' in search_url.lower()):
                return {
                    'name': 'DarkSpectre / ZoomStealer',
                    'confidence': 'HIGH',
                    'indicators': [
                        'Bing search hijacking with affiliate parameter (PC=)',
                        'Known DarkSpectre campaign pattern'
                    ],
                    'description': 'Part of campaign that infected 7.8M+ browsers',
                    'reference': 'https://www.koi.ai/blog/darkspectre-unmasking-the-threat-actor-behind-7-8-million-infected-browsers',
                    'severity': 'CRITICAL'
                }
        
        if settings_overrides.get('has_overrides'):
            affiliate_params = []
            if settings_overrides.get('search_hijacking'):
                affiliate_params = settings_overrides['search_hijacking'].get('affiliate_params', [])
            
            if affiliate_params:
                return {
                    'name': 'Search Hijacking Campaign (Generic)',
                    'confidence': 'MEDIUM',
                    'indicators': [
                        f'Search hijacking with affiliate tracking ({", ".join(affiliate_params)})',
                        'Monetization through search redirection'
                    ],
                    'description': 'Affiliate fraud via search engine override',
                    'severity': 'HIGH'
                }
        
        return None
    
    def calculate_enhanced_risk_score(self, results):
        """
        Multi-component risk scoring model.

        Components (0-10 total):
          - Permission risk     (0-2.5): Attack-path based + individual scores
          - Code analysis       (0-2.5): Severity-weighted pattern + AST findings
          - Behavioral corr.    (0-3.0): Compound threat pattern scores
          - Infrastructure      (0-2.0): Settings overrides + campaign + CSP

        Adjustments:
          - Positive signals: Clean store metadata, narrow scope -> up to -1.5
          - Malice floor: Critical behavioral correlation -> minimum 5.0
        """
        breakdown = {}

        # ---------- Component 1: Permission Risk (0-2.5) ----------
        perms = results.get('permissions', {})
        attack_path_score = perms.get('attack_path_score', 0)
        individual_perm = (
            len(perms.get('high_risk', [])) * 0.4 +
            len(perms.get('medium_risk', [])) * 0.15
        )
        # Blend attack-path and individual: attack-path dominates
        perm_component = min(attack_path_score * 0.4 + individual_perm, 2.5)
        breakdown['permissions'] = round(perm_component, 2)

        # ---------- Component 2: Code Analysis (0-2.5) ----------
        patterns = results.get('malicious_patterns', [])
        crit_count = sum(1 for p in patterns if p.get('severity') == 'critical')
        high_count = sum(1 for p in patterns if p.get('severity') == 'high')
        med_count = sum(1 for p in patterns if p.get('severity') == 'medium')

        code_raw = crit_count * 0.5 + high_count * 0.2 + med_count * 0.05
        # Density bonus: count significant findings only (medium+)
        significant = sum(1 for p in patterns if p.get('severity') in ('critical', 'high', 'medium'))
        if significant > 20:
            code_raw += 0.5
        elif significant > 10:
            code_raw += 0.25

        code_component = min(code_raw, 2.5)
        breakdown['code_analysis'] = round(code_component, 2)

        # ---------- Component 3: Behavioral Correlations (0-3.0) ----------
        bc = results.get('behavioral_correlations', {})
        bc_summary = bc.get('summary', {}) if isinstance(bc, dict) else {}
        bc_crit = bc_summary.get('critical', 0)
        bc_high = bc_summary.get('high', 0)
        bc_med = bc_summary.get('medium', 0)

        bc_raw = bc_crit * 1.2 + bc_high * 0.6 + bc_med * 0.2
        bc_component = min(bc_raw, 3.0)
        breakdown['behavioral_correlations'] = round(bc_component, 2)

        # ---------- Component 4: Infrastructure (0-2.0) ----------
        infra = 0.0

        # Settings overrides
        settings = results.get('settings_overrides', {})
        if settings.get('search_hijacking'):
            if settings['search_hijacking'].get('has_affiliate_params'):
                infra += 1.5
            else:
                infra += 1.0
        elif settings.get('homepage_hijacking') or settings.get('startup_hijacking'):
            infra += 0.8

        # C2 / exfil / beacon signals (infrastructure-heavy malware)
        infra_signals = results.get('infra_signals', {})
        exfil_count = infra_signals.get('exfil_endpoint_count', 0)
        if exfil_count >= 4:
            infra += 1.0
        elif exfil_count >= 2:
            infra += 0.5
        if infra_signals.get('has_websocket_c2'):
            infra += 0.5
        if infra_signals.get('has_beaconing'):
            infra += 0.3

        # Campaign attribution
        if results.get('campaign_attribution'):
            campaign = results['campaign_attribution']
            if campaign.get('confidence') == 'HIGH':
                infra += 0.5
            else:
                infra += 0.25

        # CSP weakness
        csp = results.get('csp_analysis', {})
        csp_score = csp.get('score', 0)
        if csp_score >= 3:
            infra += 0.5
        elif csp_score >= 1:
            infra += 0.2

        infra_component = min(infra, 2.0)
        breakdown['infrastructure'] = round(infra_component, 2)

        # ---------- Positive Signals (discount for trust) ----------
        positive_reduction = 0.0
        store = results.get('store_metadata', {})
        author = (store.get('author') or '').strip()
        author_lower = author.lower()
        # First token (e.g. "Google" from "Google LLC") for matching
        author_first = author_lower.split()[0].rstrip(',') if author_lower else ''
        # Chrome Web Store verified badge OR known legitimate publisher names
        author_verified = store.get('author_verified', False)
        trusted_publishers = frozenset({
            'google', 'microsoft', 'mozilla', 'apple', 'adobe', 'opera', 'brave',
            'duckduckgo', 'meta', 'facebook', 'grammarly', 'lastpass', 'bitwarden',
            '1password', 'dropbox', 'notion', 'slack', 'zoom', 'cisco', 'vmware',
            'atlassian', 'jetbrains', 'github', 'gitlab', 'cloudflare', 'akamai',
        })
        is_trusted_publisher = author_verified or (author_lower in trusted_publishers) or (author_first in trusted_publishers)

        # High user count = more trust
        user_count = store.get('user_count', 0) or 0
        if user_count > 100000:
            positive_reduction += 0.5
        elif user_count > 10000:
            positive_reduction += 0.3

        # Verified or trusted publisher: stronger discount so legitimate devs (e.g. Google Translate) score lower
        if author_verified:
            positive_reduction += 0.3
        if (author_lower in trusted_publishers) or (author_first in trusted_publishers):
            positive_reduction += 0.4  # Known legitimate publisher

        # Very narrow permission scope (no high-risk perms, no attack paths)
        if not perms.get('high_risk') and not perms.get('attack_paths'):
            positive_reduction += 0.3

        # Suppress positive signals if critical correlations or critical code findings exist (don't trust store when code is malicious)
        if bc_crit > 0:
            positive_reduction = 0.0
        if crit_count > 0:
            positive_reduction = 0.0  # Critical code finding (eval, remote script, etc.) — no trust discount
        # Trusted publisher cap: allow up to -2.5 so medium-risk drops to LOW when no critical behavior
        max_reduction = 2.5 if is_trusted_publisher else 1.5
        positive_reduction = min(positive_reduction, max_reduction)
        breakdown['positive_signals'] = round(-positive_reduction, 2)
        if is_trusted_publisher:
            breakdown['trusted_publisher'] = author or 'verified'

        # ---------- Combine ----------
        raw_score = (perm_component + code_component + bc_component
                     + infra_component - positive_reduction)

        # ---------- Malice Floor (V3 — tighter) ----------
        # Critical code finding (eval, remote script injection, etc.) → at least MEDIUM
        if crit_count >= 1:
            raw_score = max(raw_score, 4.0)
        # Behavioral correlation floors
        if bc_crit >= 2:
            raw_score = max(raw_score, 7.0)  # At least HIGH
        elif bc_crit >= 1:
            raw_score = max(raw_score, 5.5)  # Solid MEDIUM
        elif bc_high >= 2:
            raw_score = max(raw_score, 4.0)  # At least MEDIUM

        # Attack narrative confidence floor
        narrative = results.get('attack_narrative', {})
        if narrative.get('confidence') == 'high':
            raw_score = max(raw_score, 7.0)
        elif narrative.get('confidence') == 'medium':
            raw_score = max(raw_score, 5.0)

        # Remote C2 architecture = automatic HIGH
        bc_data = results.get('behavioral_correlations', {})
        bc_corrs = bc_data.get('correlations', []) if isinstance(bc_data, dict) else []
        if any(c.get('attack_type') == 'remote_c2_extension' for c in bc_corrs):
            raw_score = max(raw_score, 7.5)

        # Sensitive target multiplier
        sensitive = results.get('sensitive_targets', {})
        st_multiplier = sensitive.get('risk_multiplier', 1.0) if isinstance(sensitive, dict) else 1.0
        if st_multiplier > 1.0 and raw_score >= 3.0:
            raw_score = min(raw_score * st_multiplier, 10.0)
        breakdown['sensitive_target_multiplier'] = st_multiplier

        final_score = min(max(raw_score, 0), 10.0)

        # Store breakdown for debugging
        results['risk_breakdown'] = breakdown
        # First-party: trusted publisher (Google, Microsoft, etc.)
        results['first_party'] = bool(breakdown.get('trusted_publisher'))

        return round(final_score, 1)
    
    def get_risk_level(self, score):
        """Convert risk score to level"""
        if score >= 8:
            return 'CRITICAL'
        elif score >= 6:
            return 'HIGH'
        elif score >= 4:
            return 'MEDIUM'
        elif score >= 2:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def generate_attack_narrative(self, results):
        """Synthesize findings into an attack-chain narrative.

        Maps: Permissions -> Data Collection -> Exfiltration -> Infrastructure -> Impact.
        Returns a dict with ``attack_chain``, ``data_flow``, ``impact_summary``,
        and ``confidence`` (low / medium / high).
        """
        narrative = {
            'attack_chain': [],
            'data_flow': [],
            'impact_summary': '',
            'confidence': 'low',
        }

        perms = results.get('permissions', {})
        patterns = results.get('malicious_patterns', [])
        techniques = set(p.get('technique', '') for p in patterns)
        domains = results.get('domain_analysis', [])
        sensitive = results.get('sensitive_targets', {})
        sensitive_targets = sensitive.get('targets', []) if isinstance(sensitive, dict) else []

        # ── Stage 1: ACCESS ──
        has_all_urls = '<all_urls>' in perms.get('all', [])
        if has_all_urls:
            narrative['attack_chain'].append({
                'stage': 'ACCESS',
                'capability': 'Can access ALL websites including authenticated sessions',
                'risk': 'critical',
            })
        elif sensitive_targets:
            targeted = ', '.join(set(t['domain'] for t in sensitive_targets[:5]))
            narrative['attack_chain'].append({
                'stage': 'ACCESS',
                'capability': f'Targets sensitive services: {targeted}',
                'risk': 'high',
            })

        # ── Stage 2: COLLECT ──
        collection_techniques = techniques & {
            'DOM surveillance', 'Form interception', 'Keystroke logging',
            'Screen capture/surveillance', 'Cookie theft', 'Page content theft',
            'Input monitoring', 'CSS keylogging', 'Hidden field harvesting',
            'Credential theft', 'Token theft', 'Autofill manipulation',
        }
        if collection_techniques:
            narrative['attack_chain'].append({
                'stage': 'COLLECT',
                'capability': f'Harvests data via: {", ".join(sorted(collection_techniques))}',
                'risk': 'high',
            })

        # ── Stage 3: EXFILTRATE ──
        exfil_techniques = techniques & {
            'Data exfiltration', 'Beacon exfiltration', 'WebSocket exfiltration',
            'Network request', 'Remote C2 UI', 'Binary data exfiltration',
            'Encrypted exfiltration', 'Screenshot exfiltration',
        }
        if exfil_techniques:
            ext_domains = [d for d in domains if not d.get('is_first_party')]
            destinations = [d.get('domain', '?') for d in ext_domains[:5]]
            narrative['attack_chain'].append({
                'stage': 'EXFILTRATE',
                'capability': f'Sends data externally via: {", ".join(sorted(exfil_techniques))}',
                'destinations': destinations,
                'risk': 'critical',
            })

        # ── Stage 4: PERSIST / C2 ──
        persist_techniques = techniques & {
            'Remote C2 UI', 'Delayed activation', 'Anti-debugging',
            'Sandbox detection', 'Automation detection',
        }
        if persist_techniques:
            narrative['attack_chain'].append({
                'stage': 'PERSIST',
                'capability': f'Evasion / persistence via: {", ".join(sorted(persist_techniques))}',
                'risk': 'high',
            })

        # ── Confidence & summary ──
        chain_len = len(narrative['attack_chain'])
        if chain_len >= 3:
            narrative['confidence'] = 'high'
            coll_str = ', '.join(sorted(collection_techniques)[:3]) if collection_techniques else 'unknown'
            narrative['impact_summary'] = (
                f'COMPLETE SURVEILLANCE PIPELINE: Extension can access '
                f'{"ALL websites" if has_all_urls else "targeted services"} -> '
                f'collect {coll_str} -> '
                f'exfiltrate to external servers. '
                f'This enables theft of corporate data, credentials, and browsing activity.'
            )
        elif chain_len >= 2:
            narrative['confidence'] = 'medium'
            narrative['impact_summary'] = (
                'PARTIAL ATTACK CAPABILITY: Multiple components of a data theft '
                'pipeline detected. Manual review recommended to assess actual risk.'
            )
        elif chain_len == 1:
            narrative['impact_summary'] = (
                'Single-stage capability detected. May be benign, but warrants review.'
            )

        return narrative

    def classify_threat(self, results):
        """Classify the extension into a threat archetype based on all findings.

        Returns dict with classification, summary, and dominant attack types.
        """
        bc = results.get('behavioral_correlations', {})
        correlations = bc.get('correlations', []) if isinstance(bc, dict) else []
        attack_types = [c.get('attack_type') for c in correlations]
        attack_set = set(attack_types)

        # Map attack types to threat archetypes
        archetype_map = {
            'session_hijacking': 'SESSION_HIJACKER',
            'credential_theft': 'CREDENTIAL_STEALER',
            'surveillance': 'SURVEILLANCE_AGENT',
            'data_exfiltration': 'DATA_EXFILTRATOR',
            'remote_code_exec': 'REMOTE_CODE_EXEC',
            'wallet_hijack': 'CRYPTO_THIEF',
            'search_hijack': 'SEARCH_HIJACKER',
            'fingerprinting': 'TRACKER',
            'tracking': 'TRACKER',
            'extension_manipulation': 'EXTENSION_MANIPULATOR',
            'staged_payload': 'STAGED_MALWARE',
            'phishing_overlay': 'PHISHING_ATTACKER',
            'traffic_mitm': 'TRAFFIC_INTERCEPTOR',
            'c2_channel': 'C2_AGENT',
            'evasive_malware': 'EVASIVE_MALWARE',
            'system_escape': 'SYSTEM_COMPROMISER',
            'oauth_theft': 'CREDENTIAL_STEALER',
            'remote_c2_extension': 'REMOTE_C2_LOADER',
        }

        # Determine primary archetype (highest severity first)
        primary = 'UNKNOWN'
        for corr in sorted(correlations,
                           key=lambda c: {'critical': 3, 'high': 2, 'medium': 1}.get(
                               c.get('severity', ''), 0),
                           reverse=True):
            at = corr.get('attack_type', '')
            if at in archetype_map:
                primary = archetype_map[at]
                break

        # Secondary archetypes
        all_archetypes = list(set(
            archetype_map.get(at, 'UNKNOWN') for at in attack_types
            if at in archetype_map
        ))

        # Risk level influences classification
        risk_level = results.get('risk_level', 'UNKNOWN')

        if not correlations:
            if risk_level in ('CRITICAL', 'HIGH'):
                classification = 'SUSPICIOUS_HIGH_RISK'
                summary = ('High risk score from individual findings but no compound '
                           'threat patterns detected. Manual review recommended.')
            elif risk_level == 'MEDIUM':
                classification = 'MODERATE_RISK'
                summary = 'Moderate risk signals detected. Review recommended.'
            else:
                classification = 'LOW_RISK'
                # First-party / trusted publisher — explain why low risk
                first_party = results.get('first_party') or bool(results.get('risk_breakdown', {}).get('trusted_publisher'))
                if first_party:
                    summary = ('First-party or trusted publisher; limited permissions and no critical '
                              'behavioral findings. Low risk consistent with legitimate extension.')
                else:
                    summary = 'No significant threat indicators detected.'
        else:
            crit_count = sum(1 for c in correlations if c['severity'] == 'critical')
            if crit_count >= 2:
                classification = 'MALICIOUS_INDICATORS'
                summary = (f'Multiple critical threat chains detected: '
                           f'{", ".join(all_archetypes[:3])}. '
                           f'Strong indicators of malicious intent.')
            elif crit_count == 1:
                classification = 'HIGH_RISK_SUSPICIOUS'
                summary = (f'Critical threat pattern detected ({primary}). '
                           f'Extension exhibits capabilities consistent with malware.')
            else:
                classification = 'ELEVATED_RISK'
                summary = (f'Behavioral patterns detected ({", ".join(all_archetypes[:2])}). '
                           f'Capabilities warrant investigation.')

        out = {
            'classification': classification,
            'primary_archetype': primary,
            'all_archetypes': all_archetypes,
            'summary': summary,
            'attack_types': list(attack_set),
            'correlation_count': len(correlations),
        }
        # Sinkhole C2: destinations are localhost only — used to validate rule engine, not real exfil
        if results.get('sinkhole_or_lab_c2'):
            out['environment_classification'] = 'LAB_SIMULATION'
            out['environment_summary'] = (
                'C2/exfil endpoints are sinkhole domains (localhost). '
                'Used to verify the rule engine works; not real C2 — no data is sent to the internet.'
            )
            out['summary'] = summary + ' ' + out['environment_summary']
        return out

    def update_risk_with_virustotal(self, results, vt_results):
        """Update risk score based on VirusTotal results.

        Scoring requires vendor consensus to avoid false positives.
        Domains flagged by only 1-2 of 90+ vendors (e.g. huggingface.co,
        fb.me) are given LOW_CONFIDENCE tags and minimal penalty.
        """
        results['virustotal_results'] = vt_results

        vt_penalty = 0

        for vt_result in vt_results:
            if not vt_result.get('available') or not vt_result.get('known'):
                continue

            threat_level = vt_result.get('threat_level', 'CLEAN')
            if threat_level == 'CLEAN':
                continue

            # Use actual detection count for graduated penalty
            stats = vt_result.get('stats', {})
            malicious_count = stats.get('malicious', 0)

            if threat_level == 'MALICIOUS':
                if malicious_count >= 5:
                    vt_penalty += 3.0   # Strong consensus — real threat
                elif malicious_count >= 3:
                    vt_penalty += 1.5   # Moderate signal
                    vt_result['confidence'] = 'MODERATE'
                else:
                    vt_penalty += 0.5   # Weak signal — flag but don't nuke score
                    vt_result['confidence'] = 'LOW'
            elif threat_level == 'SUSPICIOUS':
                vt_penalty += 0.5

        results['risk_score'] = min(results['risk_score'] + vt_penalty, 10)
        results['risk_level'] = self.get_risk_level(results['risk_score'])

        return results
    
    def save_report(self, results, output_dir='reports'):
        """Save analysis report to JSON"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        report_path = output_dir / f"{results['extension_id']}_analysis.json"
        
        with open(report_path, 'w', encoding='utf-8') as f:
            json.dump(results, f, indent=2, ensure_ascii=False)
        
        print(f"[+] Report saved: {report_path}")
        return report_path