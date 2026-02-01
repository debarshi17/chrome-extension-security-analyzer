import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
# Also include src directory so local imports like `from ioc_manager import IOCManager` succeed
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from src.professional_report import ProfessionalReportGenerator
import json

REPORT_JSON = 'reports/cjpalhdlnbpafiamejdnhcphjbkeiagm_analysis.json'

def main():
    with open(REPORT_JSON, 'r', encoding='utf-8') as f:
        r = json.load(f)
    g = ProfessionalReportGenerator()
    g.save_professional_report(r)

if __name__ == '__main__':
    main()
