import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.analyzer import parse_cli_args, ChromeExtensionAnalyzer


def test_parse_fast():
    args = parse_cli_args(['--fast'])
    assert args.fast is True


def test_fast_short_circuit_vt():
    analyzer = ChromeExtensionAnalyzer()
    analyzer.skip_vt = True

    results = {
        'external_scripts': [
            {'url': 'https://example.com/api'}
        ]
    }

    assert analyzer._check_virustotal(results) == []


if __name__ == '__main__':
    test_parse_fast()
    test_fast_short_circuit_vt()
    print('fast-flag tests passed')
