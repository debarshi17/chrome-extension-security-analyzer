import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.analyzer import ChromeExtensionAnalyzer


def test_skip_vt_short_circuit():
    analyzer = ChromeExtensionAnalyzer()
    analyzer.skip_vt = True

    # Create a dummy results with one external script (would normally trigger VT)
    results = {
        'external_scripts': [
            {'url': 'https://example.com/api'}
        ]
    }

    vt_results = analyzer._check_virustotal(results)
    assert vt_results == []


if __name__ == '__main__':
    test_skip_vt_short_circuit()
    print('skip-vt test passed')