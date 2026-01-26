"""
Professional Threat Intelligence Report Generator - FIXED VERSION
Shows exact POST destinations, data sources, and VirusTotal cross-references
Modern design inspired by Mandiant, CrowdStrike, Unit 42
"""

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import json

class ProfessionalReportGenerator:
    """Generates professional threat intelligence reports"""
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_threat_intel_report(self, results):
        """Generate professional threat intelligence report"""
        
        extension_name = results.get('name', 'Unknown Extension')
        extension_id = results.get('extension_id', 'unknown')
        risk_score = results.get('risk_score', 0)
        risk_level = results.get('risk_level', 'UNKNOWN')
        campaign = results.get('campaign_attribution')
        settings_overrides = results.get('settings_overrides', {})
        domain_intel = results.get('domain_intelligence', [])
        vt_results = results.get('virustotal_results', [])
        
        # Threat classification
        threat_class = self._classify_threat(results)
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report - {extension_name}</title>
    <style>
        :root {{
            --color-critical: #dc2626;
            --color-high: #ea580c;
            --color-medium: #f59e0b;
            --color-low: #84cc16;
            --color-info: #3b82f6;
            --color-dark: #1e293b;
            --color-gray: #64748b;
            --color-light-bg: #f8fafc;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: #1e293b;
            background: #f1f5f9;
        }}
        
        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
        }}
        
        /* Header Section */
        .report-header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: white;
            padding: 40px 50px;
            border-bottom: 4px solid {self._get_risk_color(risk_level)};
        }}
        
        .header-top {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 20px;
        }}
        
        .report-title {{
            flex: 1;
        }}
        
        .report-title h1 {{
            font-size: 28px;
            font-weight: 700;
            margin-bottom: 8px;
            letter-spacing: -0.5px;
        }}
        
        .report-title .subtitle {{
            font-size: 14px;
            opacity: 0.8;
            font-weight: 400;
        }}
        
        .classification-badge {{
            background: {self._get_risk_color(risk_level)};
            padding: 12px 24px;
            border-radius: 6px;
            font-weight: 700;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 1px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.3);
        }}
        
        .header-meta {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 20px;
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid rgba(255,255,255,0.1);
        }}
        
        .meta-item {{
            text-align: center;
        }}
        
        .meta-label {{
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            opacity: 0.7;
            margin-bottom: 6px;
        }}
        
        .meta-value {{
            font-size: 18px;
            font-weight: 600;
        }}
        
        /* Campaign Alert */
        .campaign-alert {{
            background: linear-gradient(135deg, #7f1d1d 0%, #991b1b 100%);
            padding: 30px 50px;
            border-left: 6px solid #dc2626;
            color: white;
        }}
        
        .campaign-alert h2 {{
            font-size: 20px;
            font-weight: 700;
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .campaign-alert p {{
            margin: 8px 0;
            font-size: 15px;
            line-height: 1.7;
        }}
        
        .campaign-alert .indicators {{
            margin: 15px 0;
            padding-left: 20px;
        }}
        
        .campaign-alert .indicators li {{
            margin: 6px 0;
            font-size: 14px;
        }}
        
        .campaign-reference {{
            margin-top: 15px;
            padding-top: 15px;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 13px;
        }}
        
        .campaign-reference a {{
            color: #fca5a5;
            text-decoration: none;
            border-bottom: 1px solid #fca5a5;
        }}
        
        /* Executive Summary */
        .executive-summary {{
            background: linear-gradient(to right, #fffbeb, #fef3c7);
            border-left: 6px solid #f59e0b;
            padding: 35px 50px;
            margin: 0;
        }}
        
        .executive-summary.critical {{
            background: linear-gradient(to right, #fef2f2, #fee2e2);
            border-left-color: #dc2626;
        }}
        
        .executive-summary h2 {{
            font-size: 20px;
            font-weight: 700;
            color: #92400e;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .executive-summary.critical h2 {{
            color: #991b1b;
        }}
        
        .bluf {{
            font-size: 16px;
            font-weight: 600;
            line-height: 1.8;
            color: #78350f;
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(255,255,255,0.5);
            border-radius: 6px;
        }}
        
        .executive-summary.critical .bluf {{
            color: #7f1d1d;
        }}
        
        .key-findings {{
            display: grid;
            gap: 12px;
        }}
        
        .finding-item {{
            display: flex;
            align-items: flex-start;
            gap: 12px;
            padding: 12px;
            background: rgba(255,255,255,0.6);
            border-radius: 6px;
        }}
        
        .finding-icon {{
            flex-shrink: 0;
            width: 24px;
            height: 24px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
        }}
        
        .finding-text {{
            flex: 1;
            font-size: 14px;
            color: #78350f;
        }}
        
        /* Content Sections */
        .content {{
            padding: 0;
        }}
        
        .section {{
            padding: 40px 50px;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .section-header {{
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 25px;
        }}
        
        .section-icon {{
            width: 40px;
            height: 40px;
            background: var(--color-info);
            color: white;
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            font-size: 20px;
        }}
        
        .section-title {{
            font-size: 22px;
            font-weight: 700;
            color: var(--color-dark);
        }}
        
        /* IOC Section */
        .ioc-grid {{
            display: grid;
            gap: 20px;
        }}
        
        .ioc-category {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
        }}
        
        .ioc-category-title {{
            font-size: 16px;
            font-weight: 700;
            color: var(--color-dark);
            margin-bottom: 12px;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .ioc-list {{
            display: grid;
            gap: 8px;
        }}
        
        .ioc-item {{
            padding: 10px 14px;
            background: white;
            border: 1px solid #e2e8f0;
            border-left: 3px solid var(--color-critical);
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            color: #1e293b;
        }}
        
        /* Domain Intelligence */
        .domain-card {{
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}
        
        .domain-card.threat-critical {{
            border-left: 4px solid var(--color-critical);
            background: #fef2f2;
        }}
        
        .domain-card.threat-high {{
            border-left: 4px solid var(--color-high);
            background: #fff7ed;
        }}
        
        .domain-card.threat-medium {{
            border-left: 4px solid var(--color-medium);
            background: #fffbeb;
        }}
        
        .domain-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 12px;
        }}
        
        .domain-name {{
            font-family: 'Monaco', monospace;
            font-size: 16px;
            font-weight: 600;
            color: #1e293b;
        }}
        
        .threat-badge {{
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .threat-badge.critical {{
            background: var(--color-critical);
            color: white;
        }}
        
        .threat-badge.high {{
            background: var(--color-high);
            color: white;
        }}
        
        .threat-badge.medium {{
            background: var(--color-medium);
            color: white;
        }}
        
        .threat-badge.low {{
            background: var(--color-low);
            color: white;
        }}
        
        .threat-badge.benign {{
            background: #10b981;
            color: white;
        }}
        
        .domain-classification {{
            font-size: 14px;
            font-weight: 600;
            color: #dc2626;
            margin-bottom: 10px;
        }}
        
        .domain-indicators {{
            display: grid;
            gap: 6px;
        }}
        
        .indicator-tag {{
            padding: 6px 10px;
            background: white;
            border-radius: 4px;
            font-size: 13px;
            border-left: 3px solid #ef4444;
        }}
        
        /* Technical Details */
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}
        
        .detail-card {{
            background: #f8fafc;
            padding: 20px;
            border-radius: 8px;
            border: 1px solid #e2e8f0;
        }}
        
        .detail-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--color-gray);
            margin-bottom: 6px;
        }}
        
        .detail-value {{
            font-size: 15px;
            font-weight: 600;
            color: var(--color-dark);
        }}
        
        /* Threat Analysis - ENHANCED TO SHOW POST DESTINATIONS */
        .threat-item {{
            background: white;
            border: 1px solid #e2e8f0;
            border-left: 4px solid #ef4444;
            border-radius: 6px;
            padding: 18px;
            margin-bottom: 12px;
        }}
        
        .threat-item.high {{
            border-left-color: #ef4444;
        }}
        
        .threat-item.medium {{
            border-left-color: #f59e0b;
        }}
        
        .threat-item.low {{
            border-left-color: #64748b;
        }}
        
        .threat-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        
        .threat-name {{
            font-size: 15px;
            font-weight: 700;
            color: #1e293b;
        }}
        
        .threat-severity {{
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}
        
        .threat-severity.high {{
            background: #fee2e2;
            color: #991b1b;
        }}
        
        .threat-severity.medium {{
            background: #fef3c7;
            color: #92400e;
        }}
        
        .threat-description {{
            font-size: 14px;
            color: var(--color-gray);
            margin-bottom: 8px;
        }}
        
        .threat-destination {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            border-radius: 6px;
            padding: 12px;
            margin: 10px 0;
            font-family: 'Monaco', monospace;
            font-size: 13px;
        }}
        
        .threat-destination-label {{
            font-weight: 700;
            color: #991b1b;
            margin-bottom: 6px;
        }}
        
        .threat-destination-url {{
            color: #dc2626;
            word-break: break-all;
        }}
        
        .threat-metadata {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 12px 0;
            padding: 12px;
            background: #f8fafc;
            border-radius: 6px;
        }}
        
        .threat-meta-item {{
            font-size: 13px;
        }}
        
        .threat-meta-label {{
            font-weight: 600;
            color: #64748b;
            margin-bottom: 4px;
        }}
        
        .threat-meta-value {{
            color: #1e293b;
            font-family: 'Monaco', monospace;
        }}
        
        .threat-location {{
            font-size: 12px;
            color: #94a3b8;
            font-family: 'Monaco', monospace;
        }}
        
        .vt-cross-ref {{
            margin-top: 10px;
            padding: 10px;
            background: #fffbeb;
            border-left: 3px solid #f59e0b;
            border-radius: 4px;
            font-size: 13px;
        }}
        
        .vt-cross-ref-icon {{
            color: #f59e0b;
            font-weight: 700;
        }}
        
        /* Recommendations */
        .recommendations {{
            background: linear-gradient(135deg, #ecfdf5 0%, #d1fae5 100%);
            border-left: 6px solid #10b981;
            padding: 30px;
            border-radius: 8px;
        }}
        
        .recommendations.critical {{
            background: linear-gradient(135deg, #fee2e2 0%, #fecaca 100%);
            border-left-color: #dc2626;
        }}
        
        .recommendations h3 {{
            font-size: 18px;
            font-weight: 700;
            color: #065f46;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .recommendations.critical h3 {{
            color: #991b1b;
        }}
        
        .rec-list {{
            display: grid;
            gap: 10px;
        }}
        
        .rec-item {{
            padding: 12px 16px;
            background: rgba(255,255,255,0.7);
            border-radius: 6px;
            font-size: 14px;
            line-height: 1.6;
            color: #047857;
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }}
        
        .recommendations.critical .rec-item {{
            color: #7f1d1d;
        }}
        
        .rec-icon {{
            flex-shrink: 0;
            margin-top: 2px;
        }}
        
        /* Footer */
        .report-footer {{
            background: #f8fafc;
            padding: 30px 50px;
            text-align: center;
            color: var(--color-gray);
            font-size: 13px;
            border-top: 1px solid #e2e8f0;
        }}
        
        .footer-logo {{
            font-weight: 700;
            color: var(--color-dark);
            margin-bottom: 8px;
        }}
        
        /* No data states */
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #10b981;
            font-size: 15px;
            background: #ecfdf5;
            border-radius: 8px;
            border: 1px solid #d1fae5;
        }}
        
        /* Enhanced Code Snippets - KOI Style */
        .code-snippet-container {{
            margin: 15px 0;
            background: #1e1e1e;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #333;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }}
        
        .code-snippet-header {{
            background: #2d2d2d;
            padding: 10px 15px;
            border-bottom: 1px solid #3a3a3a;
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        
        .code-snippet-header-dots {{
            display: flex;
            gap: 6px;
        }}
        
        .code-snippet-header-dot {{
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }}
        
        .dot-red {{ background: #ff5f56; }}
        .dot-yellow {{ background: #ffbd2e; }}
        .dot-green {{ background: #27c93f; }}
        
        .code-snippet-filename {{
            color: #a0a0a0;
            font-size: 13px;
            margin-left: auto;
            font-family: 'Monaco', monospace;
        }}
        
        .code-snippet-body {{
            padding: 20px;
            overflow-x: auto;
            max-height: 500px;
            overflow-y: auto;
        }}
        
        .code-snippet-body pre {{
            margin: 0;
            font-family: 'Monaco', 'Menlo', 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.6;
            color: #d4d4d4;
        }}
        
        .code-line {{
            display: block;
        }}
        
        .code-line-number {{
            display: inline-block;
            min-width: 45px;
            color: #858585;
            text-align: right;
            padding-right: 20px;
            user-select: none;
            border-right: 1px solid #3a3a3a;
            margin-right: 15px;
        }}
        
        .code-line-content {{
            display: inline;
        }}
        
        .code-line-highlight {{
            background: rgba(255, 95, 86, 0.15);
            display: block;
            margin: 0 -20px;
            padding: 0 20px;
            border-left: 3px solid #ff5f56;
        }}
        
        /* Syntax highlighting */
        .code-keyword {{ color: #569cd6; font-weight: 600; }}
        .code-function {{ color: #dcdcaa; }}
        .code-string {{ color: #ce9178; }}
        .code-comment {{ color: #6a9955; font-style: italic; }}
        .code-const {{ color: #4fc1ff; }}
        .code-variable {{ color: #9cdcfe; }}
        .code-operator {{ color: #d4d4d4; }}
        .code-punctuation {{ color: #808080; }}
        
        /* Print Styles */
        @media print {{
            body {{ background: white; }}
            .report-container {{ box-shadow: none; }}
            .section {{ page-break-inside: avoid; }}
            .code-snippet-container {{ page-break-inside: avoid; }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <!-- Header -->
        <div class="report-header">
            <div class="header-top">
                <div class="report-title">
                    <h1>🛡️ Chrome Extension Threat Intelligence Report</h1>
                    <div class="subtitle">Comprehensive Security Analysis • {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}</div>
                </div>
                <div class="classification-badge">{risk_level} RISK</div>
            </div>
            
            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">Extension</div>
                    <div class="meta-value">{extension_name}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Risk Score</div>
                    <div class="meta-value">{risk_score:.1f}/10</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Threat Class</div>
                    <div class="meta-value">{threat_class}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Confidence</div>
                    <div class="meta-value">{self._calculate_confidence(results)}%</div>
                </div>
            </div>
        </div>
"""
        
        # Campaign Alert
        if campaign:
            html += self._generate_campaign_alert(campaign)
        
        # Executive Summary
        html += self._generate_executive_summary(results, threat_class)
        
        html += '<div class="content">'
        
        # IOC Section
        html += self._generate_ioc_section(results)

        # VirusTotal Results (CRITICAL)
        if vt_results:
            html += self._generate_virustotal_section(vt_results)

        # Advanced Malware Detection (NEW)
        advanced_detection = results.get('advanced_detection')
        if advanced_detection:
            html += self._generate_advanced_detection_section(advanced_detection)

        # PII/Data Classification (NEW)
        pii_classification = results.get('pii_classification')
        if pii_classification:
            html += self._generate_pii_classification_section(pii_classification)

        # IOC Database Cross-Reference (NEW)
        extension_id = results.get('extension_id', 'unknown')
        from ioc_manager import IOCManager
        ioc_manager = IOCManager()
        html += self._generate_ioc_database_section(extension_id, ioc_manager)

        # Domain Intelligence
        if domain_intel:
            html += self._generate_domain_intelligence_section(domain_intel)

        # Technical Details
        html += self._generate_technical_details(results)
        
        # Threat Analysis - ENHANCED VERSION
        html += self._generate_threat_analysis_enhanced(results)
        
        # Recommendations
        html += self._generate_recommendations_section(results, threat_class)
        
        html += '</div>'
        
        # Footer
        html += f"""
        <div class="report-footer">
            <div class="footer-logo">Chrome Extension Security Analyzer</div>
            <div>Professional Threat Intelligence • Powered by VirusTotal & AST Analysis</div>
            <div style="margin-top: 10px; font-size: 11px;">
                Campaign attribution based on research from KOI Security, Unit 42, and open-source threat intelligence
            </div>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _get_risk_color(self, risk_level):
        """Get color for risk level"""
        colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#f59e0b',
            'LOW': '#84cc16',
            'MINIMAL': '#22c55e'
        }
        return colors.get(risk_level, '#64748b')
    
    def _classify_threat(self, results):
        """Classify the threat type"""
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        
        if vt_malicious:
            return 'Confirmed Malware'
        elif campaign:
            return campaign.get('name', 'Malware Campaign')
        elif settings.get('search_hijacking'):
            return 'Browser Hijacker'
        elif len(results.get('malicious_patterns', [])) > 10:
            return 'Infostealer'
        else:
            return 'Suspicious Extension'
    
    def _calculate_confidence(self, results):
        """Calculate analysis confidence"""
        confidence = 70
        
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        if vt_malicious:
            confidence += 25
        elif results.get('campaign_attribution'):
            confidence += 20
        
        if results.get('settings_overrides', {}).get('has_overrides'):
            confidence += 10
        
        return min(confidence, 95)
    
    def _generate_campaign_alert(self, campaign):
        """Generate campaign alert section"""
        html = f"""
        <div class="campaign-alert">
            <h2>🚨 THREAT CAMPAIGN IDENTIFIED</h2>
            <p><strong>Campaign:</strong> {campaign['name']}</p>
            <p><strong>Confidence:</strong> {campaign['confidence']} | <strong>Severity:</strong> {campaign['severity']}</p>
            <p><strong>Assessment:</strong> {campaign.get('description', 'N/A')}</p>
            
            <p><strong>Attribution Indicators:</strong></p>
            <ul class="indicators">
"""
        
        for indicator in campaign.get('indicators', []):
            html += f"<li>• {indicator}</li>"
        
        html += "</ul>"
        
        if campaign.get('reference'):
            html += f"""
            <div class="campaign-reference">
                <strong>Reference:</strong> <a href="{campaign['reference']}" target="_blank">{campaign['reference']}</a>
            </div>
"""
        
        html += "</div>"
        return html
    
    def _generate_executive_summary(self, results, threat_class):
        """Generate executive summary with BLUF"""
        
        risk_level = results.get('risk_level')
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        
        summary_class = 'critical' if risk_level in ['CRITICAL', 'HIGH'] or vt_malicious else ''
        
        # BLUF (Bottom Line Up Front)
        if vt_malicious:
            bluf = f"VirusTotal confirmed malicious activity: {len(vt_malicious)} domain(s) flagged by security vendors. Immediate action required."
        elif campaign:
            bluf = f"This extension is part of the {campaign['name']} malicious campaign. Immediate action required."
        elif settings.get('search_hijacking'):
            bluf = "This extension hijacks browser settings for affiliate fraud. High security risk detected."
        elif risk_level == 'CRITICAL':
            bluf = "Critical security vulnerabilities detected. Extension poses immediate threat to user data and privacy."
        elif risk_level == 'HIGH':
            bluf = "Significant security concerns identified. Manual review required before deployment."
        else:
            bluf = "Extension analysis completed. Review findings below for detailed security assessment."
        
        html = f"""
        <div class="executive-summary {summary_class}">
            <h2>📋 Executive Summary</h2>
            <div class="bluf"><strong>BLUF:</strong> {bluf}</div>
            <div class="key-findings">
"""
        
        # Key findings
        findings = []
        
        if vt_malicious:
            findings.append(('🛡️', f"VirusTotal: {len(vt_malicious)} malicious domain(s) detected"))
        
        if campaign:
            findings.append(('🎯', f"Attributed to {campaign['name']} campaign"))
        
        if settings.get('search_hijacking'):
            search = settings['search_hijacking']
            if search.get('has_affiliate_params'):
                findings.append(('💰', f"Affiliate fraud detected: {', '.join(search['affiliate_params'])}"))
            else:
                findings.append(('🔍', "Search engine hijacking detected"))
        
        permissions = results.get('permissions', {})
        if permissions.get('high_risk'):
            findings.append(('🚩', f"{len(permissions['high_risk'])} dangerous permissions requested"))
        
        patterns = results.get('malicious_patterns', [])
        high_patterns = [p for p in patterns if p['severity'] == 'high']
        if high_patterns:
            findings.append(('⚠️', f"{len(high_patterns)} critical security issues in code"))
        
        domain_intel = results.get('domain_intelligence', [])
        threats = [d for d in domain_intel if d.get('threat_level') in ['CRITICAL', 'HIGH']]
        if threats:
            findings.append(('🌐', f"{len(threats)} suspicious/malicious domains detected"))
        
        if not findings:
            findings.append(('✅', "No significant threats detected"))
        
        for icon, text in findings:
            html += f"""
                <div class="finding-item">
                    <div class="finding-icon">{icon}</div>
                    <div class="finding-text">{text}</div>
                </div>
"""
        
        html += """
            </div>
        </div>
"""
        return html
    
    def _generate_ioc_section(self, results):
        """Generate Indicators of Compromise section"""
        
        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔍</div>
                <div class="section-title">Indicators of Compromise (IOCs)</div>
            </div>
            <div class="ioc-grid">
"""
        
        # Extension ID
        html += f"""
            <div class="ioc-category">
                <div class="ioc-category-title">📌 Extension Identifier</div>
                <div class="ioc-list">
                    <div class="ioc-item">{results['extension_id']}</div>
                </div>
            </div>
"""
        
        # Search Hijacking URLs
        settings = results.get('settings_overrides', {})
        if settings.get('search_hijacking'):
            search = settings['search_hijacking']
            html += f"""
            <div class="ioc-category">
                <div class="ioc-category-title">🔗 Malicious URLs</div>
                <div class="ioc-list">
                    <div class="ioc-item">{search['search_url']}</div>
                </div>
            </div>
"""
        
        # Malicious Domains from VirusTotal
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        if vt_malicious:
            html += """
            <div class="ioc-category">
                <div class="ioc-category-title">🌐 Malicious Domains (VirusTotal Confirmed)</div>
                <div class="ioc-list">
"""
            for domain in vt_malicious[:10]:
                html += f'<div class="ioc-item">{domain["domain"]}</div>'
            html += """
                </div>
            </div>
"""
        
        # Data Exfiltration Destinations (FROM AST ANALYSIS)
        ast_results = results.get('ast_results', {})
        exfil_destinations = set()
        for exfil in ast_results.get('data_exfiltration', []):
            dest = exfil.get('destination', 'Unknown')
            if dest != 'Unknown' and not dest.startswith('<'):
                exfil_destinations.add(dest)
        
        if exfil_destinations:
            html += """
            <div class="ioc-category">
                <div class="ioc-category-title">🚨 Data Exfiltration Destinations</div>
                <div class="ioc-list">
"""
            for dest in sorted(exfil_destinations):
                html += f'<div class="ioc-item">{dest}</div>'
            html += """
                </div>
            </div>
"""
        
        html += """
            </div>
        </div>
"""
        return html
    
    def _generate_virustotal_section(self, vt_results):
        """Generate VirusTotal results section"""
        
        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🛡️</div>
                <div class="section-title">VirusTotal Domain Reputation</div>
            </div>
"""
        
        # Separate by threat level
        malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']
        suspicious = [r for r in vt_results if r.get('threat_level') == 'SUSPICIOUS']
        clean = [r for r in vt_results if r.get('threat_level') == 'CLEAN']
        unknown = [r for r in vt_results if not r.get('known')]
        
        # Show malicious first (CRITICAL)
        if malicious:
            html += '<h3 style="color: #dc2626; margin-bottom: 20px; font-size: 20px; font-weight: 700;">🚨 MALICIOUS DOMAINS DETECTED</h3>'
            
            for result in malicious:
                vendors = result.get('malicious_vendors', [])
                stats = result.get('stats', {})
                votes = result.get('votes', {})
                
                html += f"""
            <div class="domain-card threat-critical">
                <div class="domain-header">
                    <div class="domain-name">🚨 {result['domain']}</div>
                    <div class="threat-badge critical">MALICIOUS</div>
                </div>
                <div class="domain-classification">⚠️ Flagged by {stats.get('malicious', 0)} security vendor(s)</div>
                
                <div style="margin: 15px 0; padding: 15px; background: white; border-radius: 6px;">
                    <div style="margin-bottom: 10px;">
                        <strong>Detection Statistics:</strong>
                    </div>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 10px; font-size: 14px;">
                        <div>🔴 Malicious: <strong>{stats.get('malicious', 0)}</strong></div>
                        <div>🟡 Suspicious: <strong>{stats.get('suspicious', 0)}</strong></div>
                        <div>🟢 Harmless: <strong>{stats.get('harmless', 0)}</strong></div>
                        <div>⚪ Undetected: <strong>{stats.get('undetected', 0)}</strong></div>
                    </div>
                </div>
                
                <div style="margin: 15px 0; padding: 15px; background: white; border-radius: 6px;">
                    <div style="margin-bottom: 10px;">
                        <strong>Community Votes:</strong>
                    </div>
                    <div style="font-size: 14px;">
                        👎 Malicious: <strong>{votes.get('malicious', 0)}</strong> | 
                        👍 Harmless: <strong>{votes.get('harmless', 0)}</strong>
                    </div>
                </div>
"""
                
                if vendors:
                    html += """
                <div style="margin: 15px 0; padding: 15px; background: white; border-radius: 6px;">
                    <div style="margin-bottom: 10px;">
                        <strong>Security Vendors Flagging This Domain:</strong>
                    </div>
                    <div style="display: grid; gap: 8px;">
"""
                    for vendor in vendors[:10]:
                        html += f"""
                        <div style="padding: 8px; background: #fee2e2; border-left: 3px solid #dc2626; border-radius: 4px; font-size: 13px;">
                            <strong>{vendor['vendor']}</strong>: {vendor['result']}
                        </div>
"""
                    html += """
                    </div>
                </div>
"""
                
                html += f"""
                <div style="margin-top: 15px; font-size: 13px; color: #64748b;">
                    <a href="{result.get('url', '#')}" target="_blank" style="color: #3b82f6; text-decoration: none;">
                        🔗 View full VirusTotal report →
                    </a>
                </div>
            </div>
"""
        
        # Show suspicious
        if suspicious:
            html += '<h3 style="color: #f59e0b; margin: 30px 0 20px 0; font-size: 18px; font-weight: 700;">⚠️ SUSPICIOUS DOMAINS</h3>'
            
            for result in suspicious:
                stats = result.get('stats', {})
                html += f"""
            <div class="domain-card threat-medium">
                <div class="domain-header">
                    <div class="domain-name">⚠️ {result['domain']}</div>
                    <div class="threat-badge medium">SUSPICIOUS</div>
                </div>
                <div style="font-size: 14px; color: #92400e;">
                    {stats.get('suspicious', 0)} suspicious detection(s), Reputation: {result.get('reputation', 'N/A')}
                </div>
                <div style="margin-top: 10px; font-size: 13px;">
                    <a href="{result.get('url', '#')}" target="_blank" style="color: #3b82f6; text-decoration: none;">
                        🔗 View VirusTotal report →
                    </a>
                </div>
            </div>
"""
        
        # Show clean/unknown summary
        if clean or unknown:
            html += f"""
            <div style="margin-top: 30px; padding: 20px; background: #ecfdf5; border-radius: 8px; border: 1px solid #d1fae5;">
                <div style="font-size: 15px; color: #065f46;">
                    ✅ <strong>{len(clean)}</strong> domain(s) checked and found clean
                </div>
"""
            if unknown:
                html += f"""
                <div style="font-size: 14px; color: #64748b; margin-top: 8px;">
                    ℹ️ {len(unknown)} domain(s) not found in VirusTotal database
                </div>
"""
            html += """
            </div>
"""
        
        html += """
        </div>
"""
        return html
    
    def _generate_domain_intelligence_section(self, domain_intel):
        """Generate domain intelligence section"""
        
        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🌐</div>
                <div class="section-title">Domain Intelligence Analysis</div>
            </div>
"""
        
        # Show only suspicious/malicious domains
        threats = [d for d in domain_intel if d.get('threat_level') != 'BENIGN']
        
        if not threats:
            html += '<div class="no-data">✅ No malicious domains detected</div>'
        else:
            for domain in threats[:10]:
                threat_level = domain.get('threat_level', 'UNKNOWN').lower()
                classification = domain.get('classification', 'Unknown Threat')
                
                html += f"""
            <div class="domain-card threat-{threat_level}">
                <div class="domain-header">
                    <div class="domain-name">🌐 {domain['domain']}</div>
                    <div class="threat-badge {threat_level}">{domain['threat_level']}</div>
                </div>
                <div class="domain-classification">{classification}</div>
                <div class="domain-indicators">
"""
                
                for indicator in domain.get('indicators', []):
                    html += f'<div class="indicator-tag">• {indicator.get("description", "Unknown indicator")}</div>'
                
                html += """
                </div>
            </div>
"""
        
        html += """
        </div>
"""
        return html
    
    def _generate_technical_details(self, results):
        """Generate technical details section"""
        
        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚙️</div>
                <div class="section-title">Technical Details</div>
            </div>
            <div class="detail-grid">
                <div class="detail-card">
                    <div class="detail-label">Extension ID</div>
                    <div class="detail-value" style="font-family: monospace; font-size: 13px;">{results['extension_id']}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Version</div>
                    <div class="detail-value">{results.get('version', 'Unknown')}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Manifest Version</div>
                    <div class="detail-value">{results.get('manifest_version', 'Unknown')}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Permissions</div>
                    <div class="detail-value">{results['permissions']['total']}</div>
                </div>
            </div>
            
            <div style="margin-top: 30px;">
                <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 15px; color: #1e293b;">📋 Dangerous Permissions</h3>
"""
        
        # Show permission details
        permissions = results.get('permissions', {})
        perm_details = permissions.get('details', {})
        
        if permissions.get('high_risk'):
            html += '<div style="display: grid; gap: 12px;">'
            
            for perm in permissions['high_risk']:
                details = perm_details.get(perm, {})
                html += f"""
                <div style="background: #fef2f2; border-left: 4px solid #dc2626; padding: 15px; border-radius: 6px;">
                    <div style="font-weight: 700; font-size: 15px; color: #991b1b; margin-bottom: 6px;">
                        🚩 {perm}
                    </div>
                    <div style="font-size: 14px; color: #7f1d1d; margin-bottom: 4px;">
                        {details.get('description', 'No description')}
                    </div>
                    <div style="font-size: 13px; color: #991b1b; font-weight: 600;">
                        {details.get('risk', 'Unknown risk')}
                    </div>
                </div>
"""
            
            html += '</div>'
        else:
            html += '<div class="no-data">✅ No high-risk permissions detected</div>'
        
        html += """
            </div>
        </div>
"""
        return html
    
    def _generate_threat_analysis_enhanced(self, results):
        """
        ENHANCED THREAT ANALYSIS - Shows exact POST destinations
        This is the FIXED version that displays:
        - Exact URL being POSTed to
        - HTTP method
        - Data source (what's being stolen)
        - VirusTotal cross-reference
        """
        
        patterns = results.get('malicious_patterns', [])
        vt_results = results.get('virustotal_results', [])
        
        # Create VT lookup map for cross-referencing
        vt_map = {}
        for vt in vt_results:
            if vt.get('known'):
                vt_map[vt.get('domain')] = vt
        
        # Deduplicate patterns by destination URL
        seen_destinations = set()
        unique_patterns = []
        
        for pattern in patterns:
            dest = pattern.get('destination', 'Unknown')
            if dest not in seen_destinations:
                seen_destinations.add(dest)
                unique_patterns.append(pattern)
        
        high_patterns = [p for p in unique_patterns if p.get('severity') == 'high'][:10]
        medium_patterns = [p for p in unique_patterns if p.get('severity') == 'medium'][:5]
        
        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚠️</div>
                <div class="section-title">Threat Analysis</div>
            </div>
"""
        
        if not high_patterns and not medium_patterns:
            html += '<div class="no-data">✅ No malicious code patterns detected</div>'
        else:
            for threat in high_patterns + medium_patterns:
                html += f"""
            <div class="threat-item {threat.get('severity', 'medium')}">
                <div class="threat-header">
                    <div class="threat-name">🚨 {threat.get('name', 'Unknown Threat')}</div>
                    <div class="threat-severity {threat.get('severity', 'medium')}">{threat.get('severity', 'medium')}</div>
                </div>
                <div class="threat-description">{threat.get('description', 'No description available')}</div>
"""
                
                # CRITICAL: Show exact POST destination
                destination = threat.get('destination')
                method = threat.get('method')
                data_source = threat.get('data_source')
                
                if destination and destination != 'Unknown' and not destination.startswith('<'):
                    html += f"""
                <div class="threat-destination">
                    <div class="threat-destination-label">🎯 Exfiltration Destination:</div>
                    <div class="threat-destination-url">{destination}</div>
                </div>
"""
                    
                    # Show metadata
                    if method or data_source:
                        html += '<div class="threat-metadata">'
                        
                        if method:
                            html += f"""
                        <div class="threat-meta-item">
                            <div class="threat-meta-label">HTTP Method</div>
                            <div class="threat-meta-value">{method}</div>
                        </div>
"""
                        
                        if data_source and data_source != 'Unknown':
                            html += f"""
                        <div class="threat-meta-item">
                            <div class="threat-meta-label">Data Source</div>
                            <div class="threat-meta-value">{data_source}</div>
                        </div>
"""
                        
                        # Extract domain for VT cross-reference
                        try:
                            parsed_url = urlparse(destination)
                            dest_domain = parsed_url.netloc
                            
                            if dest_domain in vt_map:
                                vt_info = vt_map[dest_domain]
                                threat_level = vt_info.get('threat_level', 'UNKNOWN')
                                html += f"""
                        <div class="threat-meta-item">
                            <div class="threat-meta-label">VirusTotal</div>
                            <div class="threat-meta-value">{threat_level}</div>
                        </div>
"""
                        except:
                            pass
                        
                        html += '</div>'
                    
                    # VirusTotal cross-reference details
                    try:
                        parsed_url = urlparse(destination)
                        dest_domain = parsed_url.netloc
                        
                        if dest_domain in vt_map:
                            vt_info = vt_map[dest_domain]
                            if vt_info.get('threat_level') == 'MALICIOUS':
                                stats = vt_info.get('stats', {})
                                html += f"""
                <div class="vt-cross-ref">
                    <span class="vt-cross-ref-icon">🛡️ VirusTotal Alert:</span> This domain was flagged as MALICIOUS by {stats.get('malicious', 0)} security vendor(s)
                </div>
"""
                    except:
                        pass
                
                # Show technique and file location
                html += f"""
                <div style="font-size: 13px; color: #64748b; margin: 8px 0;">
                    <strong>Technique:</strong> {threat.get('technique', 'Unknown')}
                </div>
"""
                
                # Add code snippet if evidence exists
                evidence = threat.get('evidence', '') or threat.get('context', '')
                if evidence and len(evidence) > 20:
                    file_name = threat.get('file', 'unknown.js')
                    line_num = threat.get('line', 0)
                    html += self._generate_code_snippet(evidence, file_name, line_num)
                
                html += f"""
                <div class="threat-location">📍 {threat.get('file', 'Unknown file')} : Line {threat.get('line', 0)}</div>
            </div>
"""
        
        html += """
                </div>
            </div>
        </div>
"""
        return html
    
    def _generate_code_snippet(self, code, filename, highlight_line):
        """Generate beautiful code snippet like KOI report"""
        
        lines = code.strip().split('\n')
        
        # Calculate starting line number (highlight_line - context)
        total_lines = len(lines)
        
        html = f"""
                <div class="code-snippet-container">
                    <div class="code-snippet-header">
                        <div class="code-snippet-header-dots">
                            <div class="code-snippet-header-dot dot-red"></div>
                            <div class="code-snippet-header-dot dot-yellow"></div>
                            <div class="code-snippet-header-dot dot-green"></div>
                        </div>
                        <div class="code-snippet-filename">{filename}</div>
                    </div>
                    <div class="code-snippet-body">
                        <pre>"""
        
        # Add each line with line numbers
        for i, line in enumerate(lines, start=max(1, highlight_line - 2)):
            # Escape HTML
            line_escaped = line.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            
            # Simple syntax highlighting
            line_highlighted = self._apply_syntax_highlighting(line_escaped)
            
            # Check if this is the highlight line
            is_highlight = (i == highlight_line)
            line_class = ' code-line-highlight' if is_highlight else ''
            
            html += f"""<span class="code-line{line_class}"><span class="code-line-number">{i}</span><span class="code-line-content">{line_highlighted}</span></span>
"""
        
        html += """</pre>
                    </div>
                </div>
"""
        return html
    
    def _apply_syntax_highlighting(self, code_line):
        """Apply basic syntax highlighting to code"""
        import re
        
        # Keywords
        keywords = ['const', 'let', 'var', 'function', 'async', 'await', 'if', 'else', 'return', 'new', 'this', 'try', 'catch']
        for kw in keywords:
            code_line = re.sub(rf'\b({kw})\b', r'<span class="code-keyword">\1</span>', code_line)
        
        # Function calls (word followed by ()
        code_line = re.sub(r'\b(\w+)(?=\()', r'<span class="code-function">\1</span>', code_line)
        
        # Strings
        code_line = re.sub(r'(["\'])([^"\']*)\1', r'<span class="code-string">\1\2\1</span>', code_line)
        code_line = re.sub(r'(`[^`]*`)', r'<span class="code-string">\1</span>', code_line)
        
        # Comments
        code_line = re.sub(r'(//.*$)', r'<span class="code-comment">\1</span>', code_line)
        
        return code_line

    def _generate_pii_classification_section(self, pii_data):
        """Generate PII/Data Classification section"""

        if not pii_data or pii_data.get('data_types_count', 0) == 0:
            return ""

        overall_risk = pii_data.get('overall_risk', 'LOW')
        risk_color = self._get_risk_color(overall_risk)
        classifications = pii_data.get('classifications', [])
        recommendation = pii_data.get('recommendation', {})
        destination = pii_data.get('destination', 'Unknown')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔐</div>
                <div class="section-title">PII/Sensitive Data Classification</div>
            </div>
            <div class="subsection">
                <div class="alert alert-{overall_risk.lower()}">
                    <div class="alert-icon">{'🚨' if overall_risk == 'CRITICAL' else '⚠️'  if overall_risk in ['HIGH', 'MEDIUM'] else 'ℹ️'}</div>
                    <div>
                        <strong>Overall Risk:</strong> {overall_risk}<br>
                        <strong>Destination:</strong> <code>{destination}</code><br>
                        <strong>Data Types Detected:</strong> {pii_data.get('data_types_count', 0)}<br>
                        <strong>Total Severity Score:</strong> {pii_data.get('total_severity_score', 0)}/10
                    </div>
                </div>

                <h3 style="margin-top: 20px;">Classified Data Types</h3>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 15px;">
"""

        for classification in classifications:
            category = classification['category']
            risk = classification['risk']
            severity = classification['severity_score']
            description = classification['description']
            impact = classification['impact']

            risk_badge_color = self._get_risk_color(risk)

            html += f"""
                    <div class="finding-card" style="border-left: 4px solid {risk_badge_color};">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <h4 style="margin: 0; font-size: 14px; font-weight: 600;">{category.replace('_', ' ')}</h4>
                            <span class="badge" style="background: {risk_badge_color}; color: white; padding: 4px 10px; border-radius: 4px; font-size: 11px; font-weight: 600;">{risk} ({severity}/10)</span>
                        </div>
                        <p style="margin: 8px 0; font-size: 13px; color: #64748b;"><strong>Risk:</strong> {description}</p>
                        <p style="margin: 0; font-size: 12px; color: #94a3b8;"><strong>Impact:</strong> {impact}</p>
"""

            # Show detection method
            if classification.get('matched_api'):
                html += f'<p style="margin-top: 8px; font-size: 12px;"><strong>Detected via:</strong> <code style="background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 11px;">chrome.{classification["matched_api"]}</code></p>'
            elif classification.get('matched_patterns'):
                patterns = ', '.join(classification['matched_patterns'][:2])
                html += f'<p style="margin-top: 8px; font-size: 12px;"><strong>Matched patterns:</strong> <code style="background: #f1f5f9; padding: 2px 6px; border-radius: 3px; font-size: 11px;">{patterns}</code></p>'

            html += """
                    </div>
"""

        html += f"""
                </div>

                <div class="alert alert-{overall_risk.lower()}" style="margin-top: 20px;">
                    <div class="alert-icon">🛡️</div>
                    <div>
                        <h4 style="margin: 0 0 8px 0; font-size: 14px; font-weight: 600;">Recommendation</h4>
                        <p style="margin: 0; font-size: 13px;"><strong>Action:</strong> {recommendation.get('action', 'REVIEW')}</p>
                        <p style="margin: 5px 0; font-size: 13px;"><strong>Priority:</strong> {recommendation.get('priority', 'Unknown')}</p>
                        <p style="margin: 5px 0 10px 0; font-size: 13px;">{recommendation.get('rationale', '')}</p>
                        <p style="margin: 0; font-size: 12px; font-weight: 600;">Next Steps:</p>
                        <ul style="margin: 5px 0 0 20px; font-size: 12px;">
"""

        for step in recommendation.get('next_steps', []):
            html += f'<li style="margin: 3px 0;">{step}</li>'

        html += """
                        </ul>
                    </div>
                </div>
            </div>
        </div>
"""
        return html

    def _generate_advanced_detection_section(self, advanced_data):
        """Generate Advanced Malware Detection section"""

        if not advanced_data:
            return ""

        summary = advanced_data.get('summary', {})
        total = summary.get('total_findings', 0)

        if total == 0:
            return ""

        verdict = summary.get('verdict', 'CLEAN')
        critical = summary.get('critical_findings', 0)
        high = summary.get('high_findings', 0)

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔬</div>
                <div class="section-title">Advanced Malware Detection</div>
            </div>
            <div class="subsection">
                <div class="alert alert-{'critical' if critical > 0 else 'high' if high > 0 else 'medium'}">
                    <div class="alert-icon">{'🚨' if critical > 0 else '⚠️'}</div>
                    <div>
                        <strong>Detection Verdict:</strong> {verdict}<br>
                        <strong>Total Findings:</strong> {total} ({critical} critical, {high} high)<br>
                        <strong>Analysis:</strong> Based on Wladimir Palant's advanced malware research
                    </div>
                </div>
"""

        # CSP Manipulation
        csp_findings = advanced_data.get('csp_manipulation', [])
        if csp_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-critical);">⛔ CSP Manipulation Attack (CONFIRMED MALWARE)</h3>
                <p style="margin: 10px 0; font-size: 13px;">Removes Content-Security-Policy headers to enable remote code injection. This is a <strong>confirmed malicious technique</strong>.</p>
"""
            for finding in csp_findings[:3]:
                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical); background: #fef2f2;">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px; color: var(--color-critical);">{finding['type']}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Severity:</strong> {finding['severity']}</p>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Impact:</strong> {finding['impact']}</p>
                    <p style="margin: 5px 0; font-size: 12px; background: #f1f5f9; padding: 8px; border-radius: 4px;"><strong>Evidence:</strong> {finding['evidence'].get('file', 'N/A')}</p>
                    <p style="margin: 5px 0; font-size: 12px; color: var(--color-critical); font-weight: 600;">{finding['recommendation']}</p>
                </div>
"""

        # DOM Event Injection
        dom_findings = advanced_data.get('dom_event_injection', [])
        if dom_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-critical);">🚨 DOM Event Injection (Remote Code Execution)</h3>
                <p style="margin: 10px 0; font-size: 13px;">Uses DOM event handlers to execute remote code, bypassing Manifest V3 restrictions.</p>
"""
            for finding in dom_findings[:2]:
                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding['type']}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Technique:</strong> {finding.get('technique', 'N/A')}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Indicators:</strong> {', '.join(finding['evidence'].get('indicators_found', []))}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>File:</strong> <code>{finding['evidence'].get('file', 'N/A')}</code></p>
                </div>
"""

        # WebSocket C2
        ws_findings = advanced_data.get('websocket_c2', [])
        if ws_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-high);">📡 WebSocket Command & Control</h3>
"""
            for finding in ws_findings[:3]:
                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-high);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding['type']}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>WebSocket URL:</strong> <code>{finding['evidence'].get('websocket_url', 'N/A')}</code></p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Suspicion Reasons:</strong> {', '.join(finding['evidence'].get('suspicion_reasons', []))}</p>
                </div>
"""

        # Delayed Activation
        delay_findings = advanced_data.get('delayed_activation', [])
        if delay_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-high);">⏰ Delayed Activation (Time Bomb)</h3>
"""
            for finding in delay_findings[:2]:
                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-high);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding['type']}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Impact:</strong> {finding['impact']}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Indicators:</strong> {', '.join(finding['evidence'].get('indicators_found', []))}</p>
                </div>
"""

        # Obfuscation
        obf_findings = advanced_data.get('obfuscation', [])
        if obf_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-medium);">🔒 Code Obfuscation</h3>
"""
            for finding in obf_findings[:2]:
                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-medium);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding['type']}</h4>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Techniques:</strong> {', '.join(finding['evidence'].get('obfuscation_techniques', []))}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>File:</strong> <code>{finding['evidence'].get('file', 'N/A')}</code></p>
                </div>
"""

        html += """
            </div>
        </div>
"""
        return html

    def _generate_ioc_database_section(self, extension_id, ioc_manager):
        """Generate IOC Database Cross-Reference section"""

        try:
            # Check if extension is in IOC database
            extension_ioc = ioc_manager.check_extension(extension_id)

            if not extension_ioc:
                return ""  # Don't show section if not in IOC database

            html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">📊</div>
                <div class="section-title">IOC Database Cross-Reference</div>
            </div>
            <div class="subsection">
                <div class="alert alert-critical">
                    <div class="alert-icon">🚨</div>
                    <div>
                        <strong>WARNING:</strong> This extension has been previously flagged in our IOC database<br>
                        <strong>First Analyzed:</strong> {extension_ioc.get('first_analyzed', 'Unknown')}<br>
                        <strong>Risk Score:</strong> {extension_ioc.get('risk_score', 0):.1f}/10
                    </div>
                </div>

                <h3 style="margin-top: 20px;">Previous Findings</h3>
                <div class="finding-card">
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Malicious Domains:</strong> {len(extension_ioc.get('malicious_domains', []))}</p>
                    <div style="margin: 10px 0;">
"""

            for domain in extension_ioc.get('malicious_domains', [])[:5]:
                html += f'<code style="display: block; margin: 3px 0; padding: 6px; background: #fef2f2; border-radius: 4px; font-size: 12px;">{domain}</code>'

            html += f"""
                    </div>
                    <p style="margin: 10px 0 5px 0; font-size: 13px;"><strong>Dangerous Permissions:</strong></p>
                    <ul style="margin: 0 0 0 20px; font-size: 12px;">
"""

            for perm in extension_ioc.get('dangerous_permissions', [])[:5]:
                html += f'<li>{perm}</li>'

            html += """
                    </ul>
                </div>
            </div>
        </div>
"""
            return html
        except:
            return ""

    def _generate_recommendations_section(self, results, threat_class):
        """Generate recommendations"""
        
        risk_level = results.get('risk_level')
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_malicious = [r for r in results.get('virustotal_results', []) if r.get('threat_level') == 'MALICIOUS']
        
        rec_class = 'critical' if risk_level in ['CRITICAL', 'HIGH'] or vt_malicious else ''
        
        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🎯</div>
                <div class="section-title">Security Recommendations</div>
            </div>
            <div class="recommendations {rec_class}">
                <h3>{'🚨' if rec_class == 'critical' else '✅'} Immediate Actions Required</h3>
                <div class="rec-list">
"""
        
        if vt_malicious:
            recs = [
                f"<strong>CRITICAL:</strong> VirusTotal confirmed {len(vt_malicious)} malicious domain(s)",
                f"Block extension ID {results['extension_id']} across all endpoints immediately",
                "Remove from approved extension lists",
                "Investigate all systems with this extension installed",
                "Check for signs of data exfiltration (network logs, browser history)",
                "Reset passwords for affected users",
                "Report to Chrome Web Store immediately"
            ]
        elif campaign:
            recs = [
                f"<strong>CRITICAL:</strong> Block extension ID {results['extension_id']} across all endpoints",
                "Remove from approved extension lists immediately",
                "Notify all users who have installed this extension",
                "Investigate potential data compromise (search history, credentials)",
                "Report to Chrome Web Store if extension is still publicly available",
                "Document incident for security team awareness"
            ]
        elif settings.get('has_overrides'):
            recs = [
                "<strong>IMMEDIATE:</strong> Block this extension enterprise-wide",
                "Reset browser settings on affected machines",
                "Review affiliate fraud revenue trail",
                "Add extension ID to blocklist",
                "User awareness training on browser hijacking"
            ]
        elif risk_level == 'CRITICAL':
            recs = [
                "Conduct detailed security review before any deployment",
                "Test in isolated sandbox environment only",
                "Monitor network traffic for data exfiltration",
                "Review all permissions for legitimacy"
            ]
        elif risk_level == 'HIGH':
            recs = [
                "Manual code review required",
                "Limit to non-production environments",
                "Monitor for suspicious behavior",
                "Consider alternative extensions"
            ]
        else:
            recs = [
                "Extension appears relatively safe for deployment",
                "Implement version pinning",
                "Periodic re-assessment recommended",
                "Monitor for future updates"
            ]
        
        for rec in recs:
            html += f'<div class="rec-item"><div class="rec-icon">▸</div><div>{rec}</div></div>'
        
        html += """
                </div>
            </div>
        </div>
"""
        return html
    
    def save_professional_report(self, results, output_dir='reports'):
        """Save professional report"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        html = self.generate_threat_intel_report(results)
        
        extension_id = results.get('extension_id', 'unknown')
        html_path = output_dir / f"{extension_id}_threat_intel_report.html"
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] Professional threat intel report saved: {html_path}")
        return html_path