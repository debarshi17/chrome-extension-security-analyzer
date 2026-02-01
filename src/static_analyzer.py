"""
Enhanced Static Analysis Engine with VirusTotal Integration
Detects malicious Chrome extensions including campaign attribution
Based on DarkSpectre/ZoomStealer campaign analysis
"""

import json
import re
from pathlib import Path
from collections import defaultdict
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
                'pattern': r'WebAssembly\.',
                'severity': 'medium',
                'description': 'Uses WebAssembly (can be used for crypto mining)',
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
                'pattern': r'csrf|_token|authenticity_token|__RequestVerificationToken|xsrf',
                'severity': 'high',
                'description': 'Accesses CSRF tokens - can be used to forge authenticated requests on behalf of the user',
                'technique': 'CSRF token theft'
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
                'pattern': r'navigator\.webdriver|window\.chrome\.runtime|phantom|selenium|puppeteer',
                'severity': 'high',
                'description': 'Detects automated browsers - ANTI-ANALYSIS to evade security scanners',
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
        ]

        # PRE-COMPILE all regex patterns for better performance
        # This is done once at initialization instead of on every scan
        self._compiled_patterns = []
        for pattern_def in self.malicious_patterns:
            try:
                compiled = re.compile(pattern_def['pattern'], re.IGNORECASE)
                self._compiled_patterns.append({
                    'name': pattern_def['name'],
                    'compiled': compiled,
                    'severity': pattern_def['severity'],
                    'description': pattern_def['description'],
                    'technique': pattern_def.get('technique', 'Unknown')
                })
            except re.error as e:
                print(f"[!] Warning: Failed to compile pattern '{pattern_def['name']}': {e}")

    def _read_file_cached(self, file_path):
        """Read file content with caching to avoid multiple reads

        OPTIMIZATION: Files are often read multiple times by different analyzers.
        This cache stores content in memory for the duration of analysis.

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
                content = f.read()
                self._file_cache[file_str] = content
                return content
        except Exception as e:
            return None

    def _clear_file_cache(self):
        """Clear file cache after analysis to free memory"""
        self._file_cache.clear()

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

    def analyze_extension(self, extension_dir):
        """
        Perform complete static analysis on an extension
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
            'risk_level': 'UNKNOWN'
        }
        
        # Analyze permissions with details
        results['permissions'] = self.analyze_permissions(manifest)
        
        # Analyze settings overrides
        results['settings_overrides'] = self.analyze_settings_overrides(manifest)
        
        # Scan code files
        js_files = list(extension_dir.rglob('*.js'))
        print(f"[+] Scanning {len(js_files)} JavaScript files...")
        # Run AST analysis (CRITICAL - shows exact POST destinations)
        print(f"[+] Running AST analysis...")
        results['ast_results'] = self.ast_analyzer.analyze_directory(extension_dir)
        
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
        for js_file in js_files:
            try:
                # Use cached file reader to avoid multiple reads
                code = self._read_file_cached(js_file)
                if code is None:
                    continue

                relative_path = str(js_file.relative_to(extension_dir))

                # Check for malicious patterns (uses pre-compiled regex)
                patterns_found = self.scan_code(code, relative_path)
                results['malicious_patterns'].extend(patterns_found)

                # Check for external scripts
                external = self.find_external_scripts(code, relative_path)
                results['external_scripts'].extend(external)

                # Check for obfuscation
                obfuscation = self.detect_obfuscation(code)
                if obfuscation['is_obfuscated']:
                    results['obfuscation_indicators'][relative_path] = obfuscation

            except Exception as e:
                print(f"[!] Error scanning {js_file.name}: {e}")

        # Clear file cache after analysis to free memory
        self._clear_file_cache()
        
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

        return permission_analysis
    
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
    
    def _is_in_comment(self, code, position):
        """Check if a position in code is inside a comment

        Returns True if the position is:
        - After // on the same line (single-line comment)
        - Inside /* ... */ (multi-line comment)
        """
        # Find line start
        line_start = code.rfind('\n', 0, position) + 1
        line_content = code[line_start:position]

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
            matches = pattern_def['compiled'].finditer(code)

            for match in matches:
                # Skip matches inside comments to reduce false positives
                if self._is_in_comment(code, match.start()):
                    continue

                line_num = code[:match.start()].count('\n') + 1

                # Get 3 lines before and 3 lines after (7 lines total context)
                context_start = max(0, line_num - 4)  # 3 lines before (0-indexed adjustment)
                context_end = min(len(lines), line_num + 3)  # 3 lines after

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
    
    def find_external_scripts(self, code, file_path):
        """Find external script URLs"""
        external = []
        url_pattern = r'https?://[^\s\'"<>]+'
        matches = re.finditer(url_pattern, code)
        
        for match in matches:
            url = match.group(0)
            if any(cdn in url for cdn in ['googleapis.com', 'cdnjs.cloudflare.com', 'unpkg.com']):
                continue
            
            external.append({
                'url': url,
                'file': file_path,
                'line': code[:match.start()].count('\n') + 1
            })
        
        return external
    
    def detect_obfuscation(self, code):
        """Detect if code is obfuscated"""
        entropy = self.calculate_entropy(code)
        hex_escapes = len(re.findall(r'\\x[0-9a-fA-F]{2}', code))
        unicode_escapes = len(re.findall(r'\\u[0-9a-fA-F]{4}', code))
        long_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]{50,}\b', code))
        single_letters = len(re.findall(r'\b[a-zA-Z_$]\b', code))
        total_vars = len(re.findall(r'\b[a-zA-Z_$][a-zA-Z0-9_$]*\b', code))
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
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(chr(x)) / len(data)
            if p_x > 0:
                entropy += - p_x * math.log2(p_x)
        
        return entropy
    
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
        """Enhanced risk calculation (will be updated after VT check)"""
        score = 0
        
        # Settings Override = CRITICAL (0-5 points)
        settings = results.get('settings_overrides', {})
        if settings.get('search_hijacking'):
            if settings['search_hijacking'].get('has_affiliate_params'):
                score += 5
            else:
                score += 4
        elif settings.get('homepage_hijacking') or settings.get('startup_hijacking'):
            score += 3
        elif settings.get('newtab_hijacking'):
            score += 2
        
        # Campaign Attribution (0-2 points)
        if results.get('campaign_attribution'):
            campaign = results['campaign_attribution']
            if campaign['confidence'] == 'HIGH':
                score += 2
            else:
                score += 1
        
        # Permission risk (0-2 points)
        perm_score = (
            len(results['permissions']['high_risk']) * 0.5 +
            len(results['permissions']['medium_risk']) * 0.2
        )
        score += min(perm_score, 2)
        
        # Malicious patterns (0-1 point)
        pattern_score = sum(
            2 if p['severity'] == 'high' else 1 if p['severity'] == 'medium' else 0.5
            for p in results['malicious_patterns']
        ) / 10
        score += min(pattern_score, 1)
        
        return min(score, 10)
    
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
    
    def update_risk_with_virustotal(self, results, vt_results):
        """Update risk score based on VirusTotal results"""
        
        # Add VT results to analysis
        results['virustotal_results'] = vt_results
        
        # Recalculate risk based on VT findings
        vt_penalty = 0
        
        for vt_result in vt_results:
            if not vt_result.get('available') or not vt_result.get('known'):
                continue
            
            threat_level = vt_result.get('threat_level', 'CLEAN')
            
            if threat_level == 'MALICIOUS':
                vt_penalty += 3  # CRITICAL penalty
            elif threat_level == 'SUSPICIOUS':
                vt_penalty += 1.5
        
        # Update risk score
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