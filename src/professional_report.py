"""
Professional Threat Intelligence Report Generator - FIXED VERSION
Shows exact POST destinations, data sources, and VirusTotal cross-references
Modern design inspired by Mandiant, CrowdStrike, Unit 42
"""

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import json
import html as html_module  # For escaping permission strings that contain angle brackets like <all_urls>

class ProfessionalReportGenerator:
    """Generates professional threat intelligence reports"""
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_threat_intel_report(self, results):
        """Generate professional threat intelligence report"""
        
        extension_name = results.get('name', 'Unknown Extension')
        extension_id = results.get('extension_id', 'unknown')
        extension_desc = results.get('description', '')
        icon_base64 = results.get('icon_base64', '')
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
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #22c55e;
            --color-info: #3b82f6;
            --color-dark: #0f172a;
            --color-gray: #94a3b8;
            --color-light-bg: #1e293b;
            --bg-primary: #0f172a;
            --bg-secondary: #1e293b;
            --bg-card: #334155;
            --text-primary: #f1f5f9;
            --text-secondary: #94a3b8;
            --border-color: #475569;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            line-height: 1.6;
            color: var(--text-primary);
            background: var(--bg-primary);
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
            background: var(--bg-secondary);
            box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
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
            background: linear-gradient(135deg, rgba(234, 179, 8, 0.15) 0%, rgba(234, 179, 8, 0.05) 100%);
            border-left: 6px solid #eab308;
            padding: 35px 50px;
            margin: 0;
        }}

        .executive-summary.critical {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(239, 68, 68, 0.05) 100%);
            border-left-color: #ef4444;
        }}

        .executive-summary h2 {{
            font-size: 20px;
            font-weight: 700;
            color: #fcd34d;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .executive-summary.critical h2 {{
            color: #fca5a5;
        }}

        .bluf {{
            font-size: 16px;
            font-weight: 600;
            line-height: 1.8;
            color: var(--text-primary);
            margin-bottom: 20px;
            padding: 15px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }}

        .executive-summary.critical .bluf {{
            color: var(--text-primary);
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
            background: rgba(0,0,0,0.2);
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
            color: var(--text-primary);
        }}
        
        /* Content Sections */
        .content {{
            padding: 0;
        }}

        .section {{
            padding: 40px 50px;
            border-bottom: 1px solid var(--border-color);
            background: var(--bg-secondary);
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
            background: var(--bg-card);
            color: var(--text-primary);
            display: flex;
            align-items: center;
            justify-content: center;
            border-radius: 8px;
            font-size: 20px;
        }}

        .section-title {{
            font-size: 22px;
            font-weight: 700;
            color: var(--text-primary);
        }}
        
        /* IOC Section */
        .ioc-grid {{
            display: grid;
            gap: 20px;
        }}

        .ioc-category {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}

        .ioc-category-title {{
            font-size: 16px;
            font-weight: 700;
            color: var(--text-primary);
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
            background: rgba(255,255,255,0.05);
            border: 1px solid var(--border-color);
            border-left: 3px solid var(--color-critical);
            border-radius: 4px;
            font-family: 'Monaco', 'Courier New', monospace;
            font-size: 13px;
            color: #fca5a5;
        }}
        
        /* Domain Intelligence */
        .domain-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }}

        .domain-card.threat-critical {{
            border-left: 4px solid var(--color-critical);
            background: rgba(239, 68, 68, 0.1);
        }}

        .domain-card.threat-high {{
            border-left: 4px solid var(--color-high);
            background: rgba(249, 115, 22, 0.1);
        }}

        .domain-card.threat-medium {{
            border-left: 4px solid var(--color-medium);
            background: rgba(234, 179, 8, 0.1);
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
            color: var(--text-primary);
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
            color: #fca5a5;
            margin-bottom: 10px;
        }}

        .domain-indicators {{
            display: grid;
            gap: 6px;
        }}

        .indicator-tag {{
            padding: 6px 10px;
            background: rgba(255,255,255,0.05);
            border-radius: 4px;
            font-size: 13px;
            color: var(--text-secondary);
            border-left: 3px solid #ef4444;
        }}
        
        /* Technical Details */
        .detail-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
        }}

        .detail-card {{
            background: var(--bg-card);
            padding: 20px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .detail-label {{
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: var(--text-secondary);
            margin-bottom: 6px;
        }}

        .detail-value {{
            font-size: 15px;
            font-weight: 600;
            color: var(--text-primary);
        }}

        /* Threat Analysis - ENHANCED TO SHOW POST DESTINATIONS */
        .threat-item {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-left: 4px solid #ef4444;
            border-radius: 6px;
            padding: 18px;
            margin-bottom: 12px;
        }}

        .threat-item.high {{
            border-left-color: #ef4444;
        }}

        .threat-item.medium {{
            border-left-color: #eab308;
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
            color: var(--text-primary);
        }}

        .threat-severity {{
            padding: 3px 10px;
            border-radius: 10px;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
        }}

        .threat-severity.high {{
            background: rgba(239, 68, 68, 0.2);
            color: #fca5a5;
        }}

        .threat-severity.medium {{
            background: rgba(234, 179, 8, 0.2);
            color: #fcd34d;
        }}

        .threat-description {{
            font-size: 14px;
            color: var(--text-secondary);
            margin-bottom: 8px;
        }}

        .threat-destination {{
            background: rgba(239, 68, 68, 0.1);
            border: 1px solid rgba(239, 68, 68, 0.3);
            border-radius: 6px;
            padding: 12px;
            margin: 10px 0;
            font-family: 'Monaco', monospace;
            font-size: 13px;
        }}

        .threat-destination-label {{
            font-weight: 700;
            color: #fca5a5;
            margin-bottom: 6px;
        }}

        .threat-destination-url {{
            color: #f87171;
            word-break: break-all;
        }}

        .threat-metadata {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 12px;
            margin: 12px 0;
            padding: 12px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
        }}

        .threat-meta-item {{
            font-size: 13px;
        }}

        .threat-meta-label {{
            font-weight: 600;
            color: var(--text-secondary);
            margin-bottom: 4px;
        }}

        .threat-meta-value {{
            color: var(--text-primary);
            font-family: 'Monaco', monospace;
        }}

        .threat-location {{
            font-size: 12px;
            color: var(--text-secondary);
            font-family: 'Monaco', monospace;
        }}

        .vt-cross-ref {{
            margin-top: 10px;
            padding: 10px;
            background: rgba(234, 179, 8, 0.1);
            border-left: 3px solid #eab308;
            border-radius: 4px;
            font-size: 13px;
        }}

        .vt-cross-ref-icon {{
            color: #fcd34d;
            font-weight: 700;
        }}

        /* Recommendations */
        .recommendations {{
            background: linear-gradient(135deg, rgba(16, 185, 129, 0.15) 0%, rgba(16, 185, 129, 0.05) 100%);
            border-left: 6px solid #10b981;
            padding: 30px;
            border-radius: 8px;
        }}

        .recommendations.critical {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2) 0%, rgba(239, 68, 68, 0.05) 100%);
            border-left-color: #ef4444;
        }}

        .recommendations h3 {{
            font-size: 18px;
            font-weight: 700;
            color: #34d399;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
        }}

        .recommendations.critical h3 {{
            color: #fca5a5;
        }}

        .rec-list {{
            display: grid;
            gap: 10px;
        }}

        .rec-item {{
            padding: 12px 16px;
            background: rgba(0,0,0,0.2);
            border-radius: 6px;
            font-size: 14px;
            line-height: 1.6;
            color: var(--text-primary);
            display: flex;
            align-items: flex-start;
            gap: 10px;
        }}

        .recommendations.critical .rec-item {{
            color: var(--text-primary);
        }}

        .rec-icon {{
            flex-shrink: 0;
            margin-top: 2px;
        }}
        
        /* Footer */
        .report-footer {{
            background: var(--bg-primary);
            padding: 30px 50px;
            text-align: center;
            color: var(--text-secondary);
            font-size: 13px;
            border-top: 1px solid var(--border-color);
        }}

        .footer-logo {{
            font-weight: 700;
            color: var(--text-primary);
            margin-bottom: 8px;
        }}

        /* No data states */
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #34d399;
            font-size: 15px;
            background: rgba(16, 185, 129, 0.1);
            border-radius: 8px;
            border: 1px solid rgba(16, 185, 129, 0.2);
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
        
        /* Subsection */
        .subsection {{
            padding: 20px 0;
        }}

        /* Finding Cards */
        .finding-card {{
            background: var(--bg-card);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
        }}

        /* Alert Styles */
        .alert {{
            display: flex;
            gap: 15px;
            padding: 20px;
            border-radius: 8px;
            margin: 15px 0;
        }}

        .alert-icon {{
            font-size: 24px;
            flex-shrink: 0;
        }}

        .alert-critical {{
            background: rgba(239, 68, 68, 0.15);
            border: 1px solid rgba(239, 68, 68, 0.3);
            color: #fca5a5;
        }}

        .alert-high {{
            background: rgba(249, 115, 22, 0.15);
            border: 1px solid rgba(249, 115, 22, 0.3);
            color: #fdba74;
        }}

        .alert-medium {{
            background: rgba(234, 179, 8, 0.15);
            border: 1px solid rgba(234, 179, 8, 0.3);
            color: #fcd34d;
        }}

        .alert-low {{
            background: rgba(34, 197, 94, 0.15);
            border: 1px solid rgba(34, 197, 94, 0.3);
            color: #86efac;
        }}

        /* Print Styles */
        @media print {{
            body {{ background: #1e293b; color: white; }}
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
                <div class="report-title" style="display: flex; align-items: center; gap: 20px;">
                    {'<img src="' + icon_base64 + '" alt="Extension Icon" style="width: 64px; height: 64px; border-radius: 12px; box-shadow: 0 4px 12px rgba(0,0,0,0.3);">' if icon_base64 else '<div style="width: 64px; height: 64px; background: var(--bg-card); border-radius: 12px; display: flex; align-items: center; justify-content: center; font-size: 28px;">🧩</div>'}
                    <div>
                        <h1 style="font-size: 24px; margin-bottom: 4px;">{extension_name}</h1>
                        <div class="subtitle" style="font-size: 12px; opacity: 0.7; margin-bottom: 2px;">{extension_id}</div>
                        <div class="subtitle">Threat Intelligence Report • {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}</div>
                    </div>
                </div>
                <div class="classification-badge">{risk_level} RISK</div>
            </div>

            <div class="header-meta">
                <div class="meta-item">
                    <div class="meta-label">Risk Score</div>
                    <div class="meta-value" style="font-size: 24px; color: {self._get_risk_color(risk_level)};">{risk_score:.1f}/10</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Threat Class</div>
                    <div class="meta-value">{threat_class}</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Analysis Confidence</div>
                    <div class="meta-value">{self._calculate_confidence(results)}%</div>
                </div>
                <div class="meta-item">
                    <div class="meta-label">Manifest Version</div>
                    <div class="meta-value">MV{results.get('manifest_version', '?')}</div>
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

        # Host Permissions Analysis (NEW)
        host_permissions = results.get('host_permissions')
        if host_permissions:
            html += self._generate_host_permissions_section(host_permissions)

        # VirusTotal Results (CRITICAL)
        if vt_results:
            html += self._generate_virustotal_section(vt_results)

        # Dynamic Network Capture
        network_capture = results.get('network_capture', {})
        if network_capture.get('available'):
            html += self._generate_network_capture_section(network_capture)

        # Advanced Malware Detection (NEW)
        advanced_detection = results.get('advanced_detection')
        if advanced_detection:
            html += self._generate_advanced_detection_section(advanced_detection)

        # PII/Data Classification (NEW)
        pii_classification = results.get('pii_classification')
        if pii_classification:
            html += self._generate_pii_classification_section(pii_classification)

        # Threat Attribution (NEW)
        threat_attribution = results.get('threat_attribution')
        if threat_attribution:
            html += self._generate_threat_attribution_section(threat_attribution)

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
        """Classify the threat type with evidence-based conservative language"""
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        vt_malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']

        # Count total VT detections across all malicious domains
        total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)

        # Conservative classification - require strong evidence for "malicious" label
        if vt_malicious and total_detections >= 10:
            # Multiple vendors across multiple domains = high confidence
            return 'Likely Malicious'
        elif vt_malicious and total_detections >= 5:
            # Several vendors detected issues
            return 'Suspicious Activity Detected'
        elif vt_malicious:
            # Low detection count - could be false positives
            return 'Potentially Suspicious'
        elif campaign:
            return campaign.get('name', 'Possible Malware Campaign')
        elif settings.get('search_hijacking'):
            return 'Possible Browser Hijacker'
        elif len(results.get('malicious_patterns', [])) > 15:
            # Require more patterns for high-confidence classification
            return 'Suspicious Behavior Detected'
        else:
            return 'Analysis Complete - Review Findings'
    
    def _calculate_confidence(self, results):
        """Calculate analysis confidence - conservative approach"""
        confidence = 60  # Start lower to acknowledge uncertainty

        vt_results = results.get('virustotal_results', [])
        vt_malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']

        # Only increase confidence significantly with strong VT evidence
        if vt_malicious:
            total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)
            if total_detections >= 10:
                confidence += 20  # High confidence with multiple vendors
            elif total_detections >= 5:
                confidence += 12  # Moderate confidence
            else:
                confidence += 5   # Low confidence - could be false positives

        if results.get('campaign_attribution'):
            confidence += 15  # Attribution increases confidence but not certainty

        if results.get('settings_overrides', {}).get('has_overrides'):
            confidence += 8

        # Cap at 85% - never claim 95%+ confidence without manual verification
        return min(confidence, 85)
    
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
        
        # BLUF (Bottom Line Up Front) - Conservative language
        if vt_malicious:
            total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)
            if total_detections >= 10:
                bluf = f"{len(vt_malicious)} domain(s) flagged by multiple security vendors ({total_detections} total detections). Suspicious activity detected. Further investigation recommended."
            elif total_detections >= 5:
                bluf = f"{len(vt_malicious)} domain(s) flagged by security vendors ({total_detections} total detections). Potentially suspicious behavior detected. Manual review recommended."
            else:
                bluf = f"{len(vt_malicious)} domain(s) flagged by limited security vendors ({total_detections} total detections). May indicate suspicious activity or false positives. Manual verification recommended."
        elif campaign:
            bluf = f"Extension behavior patterns similar to {campaign['name']} campaign. Further analysis recommended to confirm attribution."
        elif settings.get('search_hijacking'):
            bluf = "Extension modifies browser search settings. Could indicate affiliate revenue generation or user tracking. Review privacy implications."
        elif risk_level == 'CRITICAL':
            bluf = "Multiple suspicious behaviors detected. Extension exhibits characteristics associated with potentially unwanted programs. Manual security review recommended."
        elif risk_level == 'HIGH':
            bluf = "Suspicious behaviors detected. Manual security review recommended before deployment or continued use."
        else:
            bluf = "Analysis completed. Review findings below for security assessment. No immediately critical issues identified."
        
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
        
        # Show malicious first - with conservative language
        if malicious:
            total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in malicious)
            if total_detections >= 10:
                html += '<h3 style="color: #dc2626; margin-bottom: 20px; font-size: 20px; font-weight: 700;">⚠️ Domains Flagged by Multiple Security Vendors</h3>'
            elif total_detections >= 5:
                html += '<h3 style="color: #ea580c; margin-bottom: 20px; font-size: 20px; font-weight: 700;">⚠️ Domains Flagged by Security Vendors</h3>'
            else:
                html += '<h3 style="color: #f59e0b; margin-bottom: 20px; font-size: 20px; font-weight: 700;">⚠️ Domains Flagged (Low Detection Count - Verify Manually)</h3>'

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
                
                <div style="margin: 15px 0; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 6px;">
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
                
                <div style="margin: 15px 0; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 6px;">
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
                <div style="margin: 15px 0; padding: 15px; background: rgba(255,255,255,0.05); border-radius: 6px;">
                    <div style="margin-bottom: 10px; color: #f1f5f9;">
                        <strong>Security Vendors Flagging This Domain:</strong>
                    </div>
                    <div style="display: grid; gap: 8px;">
"""
                    for vendor in vendors[:10]:
                        html += f"""
                        <div style="padding: 10px 12px; background: rgba(239, 68, 68, 0.15); border-left: 3px solid #ef4444; border-radius: 4px; font-size: 13px;">
                            <strong style="color: #f87171;">{vendor['vendor']}</strong><span style="color: #94a3b8;">:</span> <span style="color: #fecaca;">{vendor['result']}</span>
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
                <div style="font-size: 14px; color: #fcd34d;">
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

    def _generate_network_capture_section(self, network_data):
        """Generate dynamic network capture analysis section with scoring engine results"""

        if not network_data or not network_data.get('available'):
            return ""

        summary = network_data.get('summary', {})
        extension_reqs = network_data.get('extension_requests', [])
        suspicious = network_data.get('suspicious_connections', [])
        beaconing = network_data.get('beaconing', [])
        post_nav = network_data.get('post_nav_exfil', [])
        ws_conns = network_data.get('websocket_connections', [])
        verdict = network_data.get('verdict', 'CLEAN')

        # Verdict color/label mapping
        verdict_styles = {
            'MALICIOUS': ('#ef4444', 'rgba(239, 68, 68, 0.15)', 'Multiple converging threat signals detected'),
            'SUSPICIOUS': ('#f97316', 'rgba(249, 115, 22, 0.15)', 'Threat signals detected - manual review recommended'),
            'LOW_RISK': ('#eab308', 'rgba(234, 179, 8, 0.15)', 'Minor signals observed - likely benign'),
            'CLEAN': ('#22c55e', 'rgba(34, 197, 94, 0.15)', 'No suspicious network behavior observed'),
        }
        v_color, v_bg, v_desc = verdict_styles.get(verdict, ('#94a3b8', 'rgba(148,163,184,0.15)', ''))

        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">&#x1F4E1;</div>
                <div class="section-title">Dynamic Network Analysis</div>
            </div>
            <p style="color: #94a3b8; margin-bottom: 20px;">
                Runtime network traffic captured via Playwright + Chrome DevTools Protocol.
                Requests are scored individually and aggregated into a verdict.
                Single hits do not trigger alerts &mdash; patterns do.
            </p>
"""

        # Verdict banner
        html += f"""
            <div style="background: {v_bg}; border: 1px solid {v_color}; border-radius: 8px; padding: 18px 20px; margin-bottom: 25px; display: flex; align-items: center; gap: 15px;">
                <span style="background: {v_color}; color: #fff; padding: 4px 14px; border-radius: 4px; font-size: 14px; font-weight: 800; letter-spacing: 1px;">{verdict}</span>
                <span style="color: #e2e8f0; font-size: 14px;">{v_desc}</span>
            </div>
"""

        # Summary stat boxes (6 columns now)
        html += f"""
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 25px;">
                <div style="background: rgba(59, 130, 246, 0.15); border: 1px solid rgba(59, 130, 246, 0.3); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #60a5fa;">{summary.get('total_requests', 0)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Total Requests</div>
                </div>
                <div style="background: rgba(34, 197, 94, 0.15); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #4ade80;">{summary.get('extension_requests', 0)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Extension-Initiated</div>
                </div>
                <div style="background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #f87171;">{summary.get('suspicious_count', 0)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Scored Suspicious</div>
                </div>
            </div>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-bottom: 25px;">
                <div style="background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #fca5a5;">{summary.get('high_score_count', 0)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">High-Score Hits</div>
                </div>
                <div style="background: rgba(168, 85, 247, 0.15); border: 1px solid rgba(168, 85, 247, 0.3); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #c084fc;">{summary.get('websocket_count', 0)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">WebSocket Conns</div>
                </div>
                <div style="background: rgba(251, 191, 36, 0.15); border: 1px solid rgba(251, 191, 36, 0.3); border-radius: 8px; padding: 15px; text-align: center;">
                    <div style="font-size: 28px; font-weight: 700; color: #fbbf24;">{len(beaconing)}</div>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Beaconing Endpoints</div>
                </div>
            </div>
"""

        # Beaconing detections
        if beaconing:
            html += """
            <h3 style="color: #fbbf24; margin-bottom: 15px; font-size: 18px; font-weight: 700;">Beaconing Detection</h3>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                Endpoints hit repeatedly by the extension. Regular intervals suggest C2 heartbeating or telemetry exfil.
            </p>
"""
            for b in beaconing:
                sev_color = '#ef4444' if b.get('severity') == 'HIGH' else '#f97316'
                html += f"""
            <div style="background: rgba(251, 191, 36, 0.08); border-left: 4px solid {sev_color}; border-radius: 6px; padding: 15px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="color: #e2e8f0; font-weight: 600; font-size: 14px; word-break: break-all;">{html_module.escape(b.get('endpoint', ''))}</span>
                    <span style="background: {sev_color}; color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; white-space: nowrap; margin-left: 10px;">{b.get('severity', 'MEDIUM')}</span>
                </div>
                <div style="color: #fbbf24; font-size: 13px;">{html_module.escape(b.get('reason', ''))}</div>
            </div>
"""

        # Post-navigation exfil
        if post_nav:
            html += """
            <h3 style="color: #fb923c; margin: 25px 0 15px 0; font-size: 18px; font-weight: 700;">Post-Navigation Exfiltration</h3>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                Suspicious requests fired within 3 seconds of a page navigation. Malicious extensions
                commonly exfiltrate data immediately after a page loads.
            </p>
"""
            for pn in post_nav:
                sev_color = '#ef4444' if pn.get('severity') == 'HIGH' else '#f97316'
                reasons_html = ''.join(
                    f'<li style="margin-bottom: 4px;">{html_module.escape(r)}</li>'
                    for r in pn.get('reasons', [])
                )
                html += f"""
            <div style="background: rgba(251, 146, 60, 0.08); border-left: 4px solid {sev_color}; border-radius: 6px; padding: 15px; margin-bottom: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span style="color: #e2e8f0; font-weight: 600; font-size: 14px; word-break: break-all;">{html_module.escape(pn.get('method', 'GET'))} {html_module.escape(pn.get('url', ''))}</span>
                    <span style="background: {sev_color}; color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700; white-space: nowrap; margin-left: 10px;">Score: {pn.get('score', 0)}</span>
                </div>
                <div style="color: #fb923c; font-size: 13px; margin-bottom: 4px;">Fired {pn.get('seconds_after_navigation', 0)}s after navigation</div>
                <ul style="color: #fbbf24; font-size: 13px; margin: 0; padding-left: 20px;">
                    {reasons_html}
                </ul>
            </div>
"""

        # Scored suspicious connections
        if suspicious:
            html += """
            <h3 style="color: #f87171; margin: 25px 0 15px 0; font-size: 18px; font-weight: 700;">Scored Suspicious Connections</h3>
            <p style="color: #94a3b8; font-size: 13px; margin-bottom: 12px;">
                Each request is scored based on routing indicators, payload analysis, and behavioral signals.
                Score &ge;4 = flagged, &ge;7 = high-confidence threat signal.
            </p>
"""
            for conn in suspicious:
                severity = conn.get('severity', 'MEDIUM')
                score = conn.get('score', 0)
                sev_color = '#ef4444' if severity == 'CRITICAL' else ('#f97316' if severity == 'HIGH' else '#eab308')
                reasons_html = ''.join(
                    f'<li style="margin-bottom: 4px;">{html_module.escape(r)}</li>'
                    for r in conn.get('reasons', [])
                )
                post_preview = ''
                if conn.get('post_data_preview'):
                    escaped_data = html_module.escape(conn['post_data_preview'])
                    post_preview = f"""
                    <div style="margin-top: 10px;">
                        <strong style="color: #e2e8f0;">POST Body Preview:</strong>
                        <pre style="background: rgba(0,0,0,0.3); color: #93c5fd; padding: 10px; border-radius: 4px; font-size: 12px; overflow-x: auto; margin-top: 5px; white-space: pre-wrap; word-break: break-all;">{escaped_data}</pre>
                    </div>"""

                html += f"""
            <div style="background: rgba(255,255,255,0.03); border-left: 4px solid {sev_color}; border-radius: 6px; padding: 15px; margin-bottom: 12px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span style="color: #e2e8f0; font-weight: 600; font-size: 14px; word-break: break-all;">{html_module.escape(conn.get('method', 'GET'))} {html_module.escape(conn.get('url', ''))}</span>
                    <div style="display: flex; gap: 6px; flex-shrink: 0; margin-left: 10px;">
                        <span style="background: {sev_color}; color: #fff; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700;">{severity}</span>
                        <span style="background: rgba(255,255,255,0.1); color: #e2e8f0; padding: 2px 10px; border-radius: 4px; font-size: 11px; font-weight: 700;">Score: {score}</span>
                    </div>
                </div>
                <ul style="color: #fbbf24; font-size: 13px; margin: 0; padding-left: 20px;">
                    {reasons_html}
                </ul>
                {post_preview}
            </div>
"""

        # Extension requests table
        if extension_reqs:
            external_reqs = [r for r in extension_reqs if not r.get('url', '').startswith('chrome-extension://')]
            if external_reqs:
                html += f"""
            <h3 style="color: #60a5fa; margin: 25px 0 15px 0; font-size: 18px; font-weight: 700;">Extension Network Requests ({len(external_reqs)} external)</h3>
            <div style="max-height: 400px; overflow-y: auto; border: 1px solid #475569; border-radius: 8px;">
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <thead>
                        <tr style="background: rgba(255,255,255,0.05); position: sticky; top: 0;">
                            <th style="padding: 10px 12px; text-align: left; color: #94a3b8; border-bottom: 1px solid #475569;">Method</th>
                            <th style="padding: 10px 12px; text-align: left; color: #94a3b8; border-bottom: 1px solid #475569;">URL</th>
                            <th style="padding: 10px 12px; text-align: left; color: #94a3b8; border-bottom: 1px solid #475569;">Type</th>
                        </tr>
                    </thead>
                    <tbody>
"""
                for i, req in enumerate(external_reqs[:50]):
                    bg = 'rgba(255,255,255,0.02)' if i % 2 == 0 else 'transparent'
                    method = html_module.escape(req.get('method', 'GET'))
                    url = html_module.escape(req.get('url', '')[:120])
                    rtype = html_module.escape(req.get('resource_type', ''))
                    method_color = '#f87171' if method == 'POST' else '#e2e8f0'
                    html += f"""
                        <tr style="background: {bg};">
                            <td style="padding: 8px 12px; color: {method_color}; font-weight: 600; border-bottom: 1px solid rgba(71,85,105,0.3);">{method}</td>
                            <td style="padding: 8px 12px; color: #e2e8f0; border-bottom: 1px solid rgba(71,85,105,0.3); word-break: break-all;">{url}</td>
                            <td style="padding: 8px 12px; color: #94a3b8; border-bottom: 1px solid rgba(71,85,105,0.3);">{rtype}</td>
                        </tr>
"""
                if len(external_reqs) > 50:
                    html += f"""
                        <tr><td colspan="3" style="padding: 10px 12px; color: #94a3b8; text-align: center;">... and {len(external_reqs) - 50} more requests</td></tr>
"""
                html += """
                    </tbody>
                </table>
            </div>
"""

        # WebSocket connections
        if ws_conns:
            html += f"""
            <h3 style="color: #c084fc; margin: 25px 0 15px 0; font-size: 18px; font-weight: 700;">WebSocket Connections ({len(ws_conns)})</h3>
"""
            for ws in ws_conns:
                ws_url = html_module.escape(ws.get('url', ''))
                frames_sent = len(ws.get('frames_sent', []))
                frames_recv = len(ws.get('frames_received', []))
                html += f"""
            <div style="background: rgba(168, 85, 247, 0.1); border-left: 4px solid #a855f7; border-radius: 6px; padding: 15px; margin-bottom: 10px;">
                <div style="color: #e2e8f0; font-weight: 600; word-break: break-all; margin-bottom: 8px;">{ws_url}</div>
                <div style="color: #94a3b8; font-size: 13px;">Frames sent: {frames_sent} | Frames received: {frames_recv}</div>
            </div>
"""

        # Duration note
        duration = summary.get('duration_seconds', 0)
        hp_pages = summary.get('host_permission_pages', 0)
        hp_note = f" | Host permission pages: {hp_pages}" if hp_pages else ""
        html += f"""
            <p style="color: #64748b; font-size: 12px; margin-top: 20px; text-align: right;">
                Capture duration: {duration}s | Trigger pages: {summary.get('trigger_pages_loaded', 0)}{hp_note}
            </p>
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
        
        # Show only suspicious/malicious domains from domain intelligence analysis
        threats = [d for d in domain_intel if d.get('threat_level') != 'BENIGN']

        if not threats:
            html += '<div class="no-data">✅ No suspicious domain patterns detected in static analysis</div>'
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
                <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 15px; color: var(--text-primary);">📋 Dangerous Permissions</h3>
"""
        
        # Show permission details
        permissions = results.get('permissions', {})
        perm_details = permissions.get('details', {})
        
        if permissions.get('high_risk'):
            html += '<div style="display: grid; gap: 12px;">'
            
            for perm in permissions['high_risk']:
                details = perm_details.get(perm, {})
                html += f"""
                <div style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid #dc2626; padding: 15px; border-radius: 6px;">
                    <div style="font-weight: 700; font-size: 15px; color: #fca5a5; margin-bottom: 6px;">
                        🚩 {perm}
                    </div>
                    <div style="font-size: 14px; color: #f87171; margin-bottom: 4px;">
                        {details.get('description', 'No description')}
                    </div>
                    <div style="font-size: 13px; color: #fca5a5; font-weight: 600;">
                        {details.get('risk', 'Unknown risk')}
                    </div>
                </div>
"""
            
            html += '</div>'
        else:
            html += '<div class="no-data">✅ No high-risk permissions detected</div>'

        # ========== PERMISSION COMBINATION WARNINGS ==========
        combo_warnings = permissions.get('combination_warnings', [])
        if combo_warnings:
            html += '''
                <h3 style="margin-top: 25px; color: #f1f5f9; display: flex; align-items: center; gap: 8px;">
                    <span style="font-size: 20px;">⚠️</span> Dangerous Permission Combinations Detected
                </h3>
                <p style="font-size: 13px; color: #94a3b8; margin: 8px 0 15px 0;">
                    These permission combinations indicate potential malicious capabilities:
                </p>
                <div style="display: grid; gap: 12px;">
'''
            for warning in combo_warnings:
                severity = warning.get('severity', 'MEDIUM')
                sev_colors = {
                    'CRITICAL': ('#dc2626', 'rgba(239, 68, 68, 0.15)', '#fca5a5'),
                    'HIGH': ('#ea580c', 'rgba(234, 88, 12, 0.15)', '#fdba74'),
                    'MEDIUM': ('#f59e0b', 'rgba(245, 158, 11, 0.15)', '#fcd34d')
                }
                border_color, bg_color, text_color = sev_colors.get(severity, sev_colors['MEDIUM'])
                perms_raw = ' + '.join(warning.get('permissions', []))
                # Escape HTML so values like <all_urls> render literally, not as tags
                perms_list = html_module.escape(perms_raw)

                html += f'''
                    <div style="background: {bg_color}; border-left: 4px solid {border_color}; padding: 15px; border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                            <span style="font-weight: 700; font-size: 15px; color: {text_color};">
                                🔗 {warning.get('name', 'Unknown')}
                            </span>
                            <span style="background: {border_color}; color: white; padding: 3px 10px; border-radius: 4px; font-size: 11px; font-weight: 700;">
                                {severity}
                            </span>
                        </div>
                        <div style="font-size: 12px; color: #94a3b8; margin-bottom: 6px;">
                            <strong>Permissions:</strong> <code style="background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 3px; color: {text_color};">{perms_list}</code>
                        </div>
                        <div style="font-size: 14px; color: #e2e8f0;">
                            {warning.get('description', '')}
                        </div>
                    </div>
'''
            html += '</div>'

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
                # Generate context analysis explaining HOW the function is used
                context_analysis = self._generate_context_analysis(threat)

                html += f"""
            <div class="threat-item {threat.get('severity', 'medium')}">
                <div class="threat-header">
                    <div class="threat-name">🚨 {threat.get('name', 'Unknown Threat')}</div>
                    <div class="threat-severity {threat.get('severity', 'medium')}">{threat.get('severity', 'medium')}</div>
                </div>
                <div class="threat-description">{threat.get('description', 'No description available')}</div>
"""
                # Add context analysis if available
                if context_analysis:
                    html += f"""
                <div class="context-analysis" style="margin: 10px 0; padding: 12px 15px; background: rgba(59, 130, 246, 0.1); border-left: 3px solid #3b82f6; border-radius: 4px; font-size: 13px; color: #cbd5e1; line-height: 1.5;">
                    <strong style="color: #60a5fa;">Context Analysis:</strong> {context_analysis}
                </div>
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
                
                # Add code snippet with 6-7 lines of context
                # Prefer context_with_lines (new format) over raw context
                context_code = threat.get('context_with_lines', '') or threat.get('context', '') or threat.get('evidence', '')
                if context_code and len(context_code) > 20:
                    file_name = threat.get('file', 'unknown.js')
                    line_num = threat.get('line', 0)
                    start_line = threat.get('context_start_line', max(1, line_num - 3))
                    matched_text = threat.get('matched_text', '')

                    # Add matched text indicator
                    if matched_text:
                        html += f'''
                <div style="margin: 10px 0; padding: 8px 12px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; border-radius: 4px;">
                    <span style="color: #94a3b8; font-size: 12px;">Matched pattern:</span>
                    <code style="color: #f87171; background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-left: 8px;">{matched_text[:80]}{"..." if len(matched_text) > 80 else ""}</code>
                </div>
'''
                    html += self._generate_code_snippet(context_code, file_name, line_num, start_line)
                
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
    
    def _generate_code_snippet(self, code, filename, highlight_line, start_line=None):
        """Generate beautiful code snippet like KOI report with 6-7 lines of context"""

        lines = code.strip().split('\n')

        # If start_line provided, use it; otherwise calculate from highlight_line
        if start_line is None:
            start_line = max(1, highlight_line - 3)

        html = f"""
                <div class="code-snippet-container" style="margin: 15px 0; border-radius: 8px; overflow: hidden; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
                    <div class="code-snippet-header" style="background: linear-gradient(135deg, #374151 0%, #1f2937 100%); padding: 10px 15px; display: flex; align-items: center; gap: 10px;">
                        <div class="code-snippet-header-dots" style="display: flex; gap: 6px;">
                            <div style="width: 12px; height: 12px; border-radius: 50%; background: #ef4444;"></div>
                            <div style="width: 12px; height: 12px; border-radius: 50%; background: #f59e0b;"></div>
                            <div style="width: 12px; height: 12px; border-radius: 50%; background: #22c55e;"></div>
                        </div>
                        <div class="code-snippet-filename" style="color: #9ca3af; font-size: 13px; font-family: monospace;">{filename}</div>
                    </div>
                    <div class="code-snippet-body" style="background: #0f172a; padding: 0; overflow-x: auto;">
                        <pre style="margin: 0; padding: 15px; font-family: 'Fira Code', 'Monaco', 'Consolas', monospace; font-size: 13px; line-height: 1.6;">"""

        # Add each line with line numbers
        for i, line in enumerate(lines, start=start_line):
            # Skip lines that look like they already have >>> markers (pre-formatted)
            if line.strip().startswith('>>>') or line.strip().startswith('   '):
                # Extract the actual content after the marker
                parts = line.split('|', 1)
                if len(parts) == 2:
                    line_content = parts[1]
                    line_num_match = line.split('|')[0].strip().replace('>>>', '').strip()
                    try:
                        actual_line_num = int(line_num_match)
                        is_highlight = '>>>' in line
                    except:
                        actual_line_num = i
                        is_highlight = (i == highlight_line)
                else:
                    line_content = line
                    actual_line_num = i
                    is_highlight = (i == highlight_line)
            else:
                line_content = line
                actual_line_num = i
                is_highlight = (i == highlight_line)

            # Escape HTML
            line_escaped = line_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')

            # Simple syntax highlighting
            line_highlighted = self._apply_syntax_highlighting(line_escaped)

            # Styles for highlighted vs normal lines
            if is_highlight:
                line_bg = 'background: rgba(239, 68, 68, 0.2); border-left: 3px solid #ef4444;'
                line_num_color = '#ef4444'
                marker = '<span style="color: #ef4444; font-weight: bold;">&gt;&gt;</span> '
            else:
                line_bg = 'border-left: 3px solid transparent;'
                line_num_color = '#4b5563'
                marker = '   '

            html += f'''<div style="display: flex; {line_bg} padding: 2px 10px;"><span style="color: {line_num_color}; min-width: 35px; text-align: right; padding-right: 15px; user-select: none; border-right: 1px solid #374151;">{actual_line_num}</span><span style="padding-left: 10px; color: #e2e8f0;">{marker}{line_highlighted}</span></div>'''

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

    def _generate_context_analysis(self, threat):
        """
        Generate 1-2 lines explaining HOW the suspicious function is used in context.
        This helps analysts understand the actual behavior, not just that a pattern was detected.
        """
        name = threat.get('name', '').lower()
        context = threat.get('context', '') or threat.get('evidence', '') or ''
        context_lower = context.lower()
        technique = threat.get('technique', '')

        # WebAssembly context analysis
        if 'webassembly' in name:
            if 'crypto' in context_lower or 'miner' in context_lower or 'hash' in context_lower:
                return "This script loads WebAssembly code and contains crypto/mining-related keywords, suggesting potential cryptocurrency mining behavior."
            elif 'wasm' in context_lower and ('fetch' in context_lower or 'load' in context_lower):
                return "The script fetches and instantiates a WebAssembly module from an external source. WebAssembly can execute native-speed code for legitimate purposes (image processing, games) or malicious ones (crypto mining, bypassing JS analysis)."
            else:
                return "WebAssembly is used in this script. While WASM has legitimate uses (performance-critical code), it can also be used to hide malicious logic or perform crypto mining. Review the WASM module's purpose."

        # Keylogger detection context
        if 'key' in name and ('log' in name or 'event' in name or 'stroke' in name):
            if 'password' in context_lower:
                return "A keyboard event listener is attached that appears to target password fields. This is a strong indicator of credential theft - the extension is capturing keystrokes in password inputs."
            elif 'buffer' in context_lower or 'push' in context_lower or 'array' in context_lower:
                return "Keystrokes are being collected into a buffer/array. This buffering pattern is typical of keyloggers that batch-send captured data to avoid detection."
            else:
                return "A keyboard event listener is registered. Could be legitimate (hotkeys, shortcuts) or malicious (keylogging). Check if it's scoped to specific UI elements or captures all keystrokes."

        # Screen capture context
        if 'capture' in name or 'screenshot' in name:
            if 'formdata' in context_lower or 'upload' in context_lower or 'post' in context_lower:
                return "Screenshots are being captured and uploaded to a server. This is surveillance behavior - the extension is exfiltrating visual data from the user's browsing session."
            elif 'encrypt' in context_lower or 'aes' in context_lower or 'rsa' in context_lower:
                return "Screenshots are captured and encrypted before transmission. Encryption hides the exfiltrated content from network inspection, making detection harder."
            else:
                return "Screen capture API is used. This allows the extension to take screenshots of browser tabs or the desktop, potentially capturing sensitive information displayed on screen."

        # Data exfiltration context
        if 'exfil' in name or 'post' in name or 'beacon' in name:
            if 'cookie' in context_lower or 'session' in context_lower:
                return "Data is being sent to an external server, and the code references cookies/sessions. This suggests session hijacking - the extension may be stealing authentication tokens."
            elif 'password' in context_lower or 'credential' in context_lower:
                return "Data exfiltration is occurring with credential-related keywords present. The extension appears to be stealing and transmitting user credentials."
            else:
                return "Data is being sent to an external server. Review what data is being collected and whether the destination is a legitimate service or a potential C2 server."

        # Eval/code injection context
        if 'eval' in name or 'function' in name and 'dynamic' in name:
            if 'fetch' in context_lower or 'http' in context_lower:
                return "Dynamic code execution combined with network requests. This is a remote code execution pattern - the extension fetches code from a server and executes it, allowing attackers to change behavior without updating the extension."
            elif 'atob' in context_lower or 'base64' in context_lower:
                return "Code is being decoded from Base64 and executed. This obfuscation technique hides the actual malicious payload from static analysis."
            else:
                return "Dynamic code execution (eval/new Function) allows running arbitrary code at runtime. This is dangerous as the executed code cannot be statically analyzed."

        # MutationObserver context
        if 'mutation' in name or 'observer' in name:
            if 'password' in context_lower or 'login' in context_lower or 'form' in context_lower:
                return "A MutationObserver monitors DOM changes with focus on login/password elements. This watches for dynamically loaded login forms to capture credentials as soon as they appear."
            else:
                return "A MutationObserver watches for DOM changes. This can be used to detect when sensitive forms are added to the page and immediately begin capturing their data."

        # Cookie/session theft context
        if 'cookie' in name:
            if 'getall' in context_lower or 'all' in context_lower:
                return "The extension accesses all cookies, not just those for specific sites. This allows stealing session tokens from any website, enabling account takeover across multiple services."
            else:
                return "Cookie access detected. Cookies often contain session tokens that authenticate users - stealing them allows attackers to hijack user sessions without knowing passwords."

        # Clipboard context
        if 'clipboard' in name:
            if 'password' in context_lower or 'crypto' in context_lower or 'wallet' in context_lower:
                return "Clipboard access combined with sensitive keywords (password/crypto/wallet). Users often copy sensitive data like passwords or cryptocurrency addresses - this extension may be intercepting them."
            else:
                return "Clipboard read access detected. Clipboard often contains sensitive copied data like passwords, credit card numbers, or crypto wallet addresses."

        # Default context based on technique
        if technique:
            technique_contexts = {
                'Credential theft': "This pattern is associated with stealing login credentials. Review the surrounding code to determine what data is being accessed and where it's sent.",
                'Data exfiltration': "This pattern indicates data leaving the browser to an external server. Verify the destination and what data is being transmitted.",
                'Code injection': "This allows executing arbitrary code, which can perform any action including data theft, UI modification, or loading additional malware.",
                'Screen capture/surveillance': "Visual data capture can expose any sensitive information visible on screen, including passwords, financial data, and private messages.",
                'Input monitoring': "Input monitoring can capture everything the user types, including passwords, personal messages, and financial information.",
            }
            return technique_contexts.get(technique, f"This pattern is associated with '{technique}' behavior. Review the code context to assess the actual risk.")

        return ""

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
                html += f'<p style="margin-top: 8px; font-size: 12px; color: #94a3b8;"><strong style="color: #cbd5e1;">Detected via:</strong> <code style="background: rgba(59, 130, 246, 0.2); color: #93c5fd; padding: 2px 8px; border-radius: 3px; font-size: 11px;">chrome.{classification["matched_api"]}</code></p>'
            elif classification.get('matched_patterns'):
                patterns = ', '.join(classification['matched_patterns'][:2])
                html += f'<p style="margin-top: 8px; font-size: 12px; color: #94a3b8;"><strong style="color: #cbd5e1;">Matched patterns:</strong> <code style="background: rgba(59, 130, 246, 0.2); color: #93c5fd; padding: 2px 8px; border-radius: 3px; font-size: 11px;">{patterns}</code></p>'

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
                        <strong>Analysis:</strong> Advanced behavioral analysis completed
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
                # Safely get evidence
                evidence = finding.get('evidence', {})
                file_name = evidence.get('file', 'N/A') if isinstance(evidence, dict) else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical); background: rgba(239, 68, 68, 0.1);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px; color: var(--color-critical);">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Severity:</strong> {finding.get('severity', 'Unknown')}</p>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Impact:</strong> {finding.get('impact', 'Unknown')}</p>
                    <p style="margin: 5px 0; font-size: 12px; background: #f1f5f9; padding: 8px; border-radius: 4px;"><strong>Evidence:</strong> {file_name}</p>
                    <p style="margin: 5px 0; font-size: 12px; color: var(--color-critical); font-weight: 600;">{finding.get('recommendation', 'Review required')}</p>
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
                # Safely get indicators
                evidence = finding.get('evidence', {})
                indicators = evidence.get('indicators_found', []) if isinstance(evidence, dict) else []
                indicators_str = ', '.join(indicators) if indicators else 'N/A'
                file_name = evidence.get('file', 'N/A') if isinstance(evidence, dict) else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Technique:</strong> {finding.get('technique', 'N/A')}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Indicators:</strong> {indicators_str}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>File:</strong> <code>{file_name}</code></p>
                </div>
"""

        # WebSocket C2
        ws_findings = advanced_data.get('websocket_c2', [])
        if ws_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-high);">📡 WebSocket Command & Control</h3>
"""
            for finding in ws_findings[:3]:
                # Safely get WebSocket details
                evidence = finding.get('evidence', {})
                ws_url = evidence.get('websocket_url', 'N/A') if isinstance(evidence, dict) else 'N/A'
                reasons = evidence.get('suspicion_reasons', []) if isinstance(evidence, dict) else []
                reasons_str = ', '.join(reasons) if reasons else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-high);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>WebSocket URL:</strong> <code>{ws_url}</code></p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Suspicion Reasons:</strong> {reasons_str}</p>
                </div>
"""

        # Delayed Activation
        delay_findings = advanced_data.get('delayed_activation', [])
        if delay_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-high);">⏰ Delayed Activation (Time Bomb)</h3>
"""
            for finding in delay_findings[:2]:
                # Safely get indicators
                evidence = finding.get('evidence', {})
                indicators = evidence.get('indicators_found', []) if isinstance(evidence, dict) else []
                indicators_str = ', '.join(indicators) if indicators else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-high);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Impact:</strong> {finding.get('impact', 'Unknown')}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Indicators:</strong> {indicators_str}</p>
                </div>
"""

        # Obfuscation
        obf_findings = advanced_data.get('obfuscation', [])
        if obf_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-medium);">🔒 Code Obfuscation</h3>
"""
            for finding in obf_findings[:2]:
                # Safely get obfuscation details
                evidence = finding.get('evidence', {})
                techniques = evidence.get('obfuscation_techniques', []) if isinstance(evidence, dict) else []
                techniques_str = ', '.join(techniques) if techniques else 'N/A'
                file_name = evidence.get('file', 'N/A') if isinstance(evidence, dict) else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-medium);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Techniques:</strong> {techniques_str}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>File:</strong> <code>{file_name}</code></p>
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
                html += f'<code style="display: block; margin: 3px 0; padding: 6px; background: rgba(239, 68, 68, 0.1); border-radius: 4px; font-size: 12px;">{domain}</code>'

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

    def _generate_host_permissions_section(self, host_permissions):
        """Generate host permissions analysis section"""

        risk = host_permissions.get('risk_assessment', {})
        stats = host_permissions.get('statistics', {})
        sensitive_access = host_permissions.get('sensitive_access', {})
        perm_scope = host_permissions.get('permission_scope', 'UNKNOWN')

        # Risk color
        risk_level = risk.get('overall_risk', 'LOW')
        risk_color = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#f59e0b',
            'LOW': '#84cc16'
        }.get(risk_level, '#64748b')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔐</div>
                <div class="section-title">Host Permissions & Website Access</div>
            </div>
            <div class="subsection">
"""

        # All URLs warning
        if host_permissions.get('all_urls_access'):
            html += """
                <div class="alert alert-critical">
                    <div class="alert-icon">🚨</div>
                    <div>
                        <strong>CRITICAL:</strong> This extension has <code>&lt;all_urls&gt;</code> access - can read and modify data on ALL websites you visit!
                    </div>
                </div>
"""

        # Statistics summary
        html += f"""
                <div style="background: rgba(255,255,255,0.03); border: 1px solid #475569; border-radius: 8px; padding: 20px; margin-bottom: 15px;">
                    <h3 style="color: #e2e8f0; margin: 0 0 10px 0;">Permission Scope: {perm_scope}</h3>
                    <p style="color: {risk_color}; font-weight: 700; font-size: 18px; margin: 10px 0;">Risk Level: {risk_level}</p>
                    <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 15px; margin: 15px 0;">
                        <div>
                            <p style="font-size: 12px; color: #94a3b8; margin: 0;">Host Permissions</p>
                            <p style="font-size: 24px; font-weight: 700; color: #e2e8f0; margin: 5px 0;">{stats['total_host_permissions']}</p>
                        </div>
                        <div>
                            <p style="font-size: 12px; color: #94a3b8; margin: 0;">Content Scripts</p>
                            <p style="font-size: 24px; font-weight: 700; color: #e2e8f0; margin: 5px 0;">{stats['total_content_scripts']}</p>
                        </div>
                        <div>
                            <p style="font-size: 12px; color: #94a3b8; margin: 0;">Sensitive Categories</p>
                            <p style="font-size: 24px; font-weight: 700; color: #e2e8f0; margin: 5px 0;">{stats['total_sensitive_categories']}</p>
                        </div>
                        <div>
                            <p style="font-size: 12px; color: #94a3b8; margin: 0;">Sensitive Domains</p>
                            <p style="font-size: 24px; font-weight: 700; color: #e2e8f0; margin: 5px 0;">{stats['total_sensitive_domains']}</p>
                        </div>
                    </div>
                </div>
"""

        # Risk factors
        if risk.get('risk_factors'):
            html += """
                <h3 style="margin-top: 25px; color: #e2e8f0;">Risk Factors</h3>
                <div style="background: rgba(255,255,255,0.03); border: 1px solid #475569; border-radius: 8px; padding: 15px; margin-bottom: 15px;">
"""
            for factor in risk['risk_factors']:
                html += f'<p style="margin: 8px 0; font-size: 13px; color: #fbbf24;">[!] {factor}</p>'

            html += "</div>"

        # Sensitive access breakdown
        if sensitive_access:
            html += """
                <h3 style="margin-top: 25px; color: #e2e8f0;">Sensitive Website Access</h3>
                <p style="font-size: 13px; color: #94a3b8; margin: 10px 0;">Extension requests permission to access the following sensitive categories:</p>
"""

            for category, domains in sensitive_access.items():
                category_name = category.replace('_', ' ').title()
                html += f"""
                <div style="background: rgba(255,255,255,0.03); border: 1px solid #475569; border-radius: 8px; padding: 15px; margin: 15px 0;">
                    <h4 style="color: {risk_color}; margin: 0 0 10px 0;">{category_name} ({len(domains)} domains)</h4>
                    <div style="max-height: 150px; overflow-y: auto;">
"""
                for domain in domains[:10]:
                    html += f'<code style="display: block; margin: 3px 0; padding: 6px; background: rgba(59, 130, 246, 0.1); color: #93c5fd; border-radius: 4px; font-size: 12px;">{domain}</code>'

                if len(domains) > 10:
                    html += f'<p style="margin: 10px 0; font-size: 12px; color: #94a3b8;">... and {len(domains) - 10} more</p>'

                html += """
                    </div>
                </div>
"""

        # Sample permissions
        host_perms_list = host_permissions.get('host_permissions', [])
        total_host_perms = len(host_perms_list)
        display_count = min(total_host_perms, 10)

        html += f"""
                <h3 style="margin-top: 25px; color: #e2e8f0;">Sample Host Permissions</h3>
                <p style="font-size: 13px; color: #94a3b8; margin: 10px 0;">Showing {display_count} of {total_host_perms} host permission(s) requested by this extension:</p>
                <div style="background: rgba(255,255,255,0.03); border: 1px solid #475569; border-radius: 8px; padding: 15px;">
"""

        for i, perm in enumerate(host_perms_list[:10], 1):
            perm_risk = perm.get('risk_level', 'UNKNOWN')
            perm_color = {
                'CRITICAL': '#dc2626',
                'HIGH': '#ea580c',
                'MEDIUM': '#f59e0b',
                'LOW': '#84cc16'
            }.get(perm_risk, '#64748b')

            html += f"""
                <div style="border-left: 3px solid {perm_color}; padding: 10px; margin: 10px 0; background: rgba(255,255,255,0.03); border-radius: 0 6px 6px 0;">
                    <p style="margin: 0; font-family: 'Courier New', monospace; font-size: 13px; font-weight: 700; color: #e2e8f0;">{perm['pattern']}</p>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #94a3b8;">{perm['description']}</p>
                    <p style="margin: 5px 0 0 0; font-size: 11px;"><span style="color: {perm_color}; font-weight: 700;">Risk: {perm_risk}</span> <span style="color: #64748b;">| Category: {perm['category']}</span></p>
                </div>
"""

        html += """
                </div>
            </div>
        </div>
"""

        return html

    def _render_osint_findings(self, attribution, campaign_data):
        """Render OSINT findings as beautiful structured HTML"""

        ext_info = attribution.get('extension_info', {})
        confidence = attribution.get('confidence', 'NONE')

        # Determine status colors
        if confidence == 'CONFIRMED':
            status_bg = '#fef2f2'
            status_border = '#dc2626'
            status_text = '#991b1b'
            status_label = 'CONFIRMED MALICIOUS'
        elif confidence == 'HIGH':
            status_bg = '#fef2f2'
            status_border = '#dc2626'
            status_text = '#991b1b'
            status_label = 'HIGH CONFIDENCE'
        else:
            status_bg = '#fffbeb'
            status_border = '#f59e0b'
            status_text = '#92400e'
            status_label = 'SUSPECTED'

        html = f"""
                <div style="background: linear-gradient(135deg, #1e293b 0%, #334155 100%); border-radius: 12px; padding: 24px; margin: 15px 0; color: #fff;">

                    <!-- Header with status badge -->
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px;">
                        <h4 style="margin: 0; font-size: 18px; font-weight: 600; color: #fff;">
                            <span style="color: #f87171;">⚠</span> Threat Intelligence Report
                        </h4>
                        <span style="background: {status_bg}; color: {status_text}; padding: 6px 14px; border-radius: 20px; font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; border: 1px solid {status_border};">
                            {status_label}
                        </span>
                    </div>

                    <!-- Extension Info Card -->
                    <div style="background: rgba(255,255,255,0.08); border-radius: 8px; padding: 16px; margin-bottom: 16px;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Extension Identified</div>
                        <div style="font-size: 15px; font-weight: 500; color: #f1f5f9;">{attribution.get('extension_name', 'Unknown')}</div>
                        <div style="font-size: 12px; color: #64748b; margin-top: 4px; font-family: 'Monaco', 'Consolas', monospace;">{attribution.get('extension_id', 'Unknown ID')}</div>
                    </div>
"""

        # Campaign Attribution section
        if campaign_data:
            html += f"""
                    <!-- Campaign Attribution -->
                    <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 12px; margin-bottom: 16px;">
                        <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 14px; border-left: 3px solid #f87171;">
                            <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Campaign</div>
                            <div style="font-size: 14px; font-weight: 600; color: #fca5a5;">{campaign_data.get('campaign_name', attribution.get('campaign_name', 'Unknown'))}</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 14px; border-left: 3px solid #fbbf24;">
                            <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Threat Actor</div>
                            <div style="font-size: 14px; font-weight: 600; color: #fcd34d;">{campaign_data.get('threat_actor', attribution.get('threat_actor', 'Unknown'))}</div>
                        </div>
                        <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 14px; border-left: 3px solid #60a5fa;">
                            <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 6px;">Active Period</div>
                            <div style="font-size: 14px; font-weight: 600; color: #93c5fd;">{campaign_data.get('active_period', 'Unknown')}</div>
                        </div>
                    </div>
"""

            # Impact Stats
            impact = campaign_data.get('impact', {})
            if impact:
                # Handle string values for impact metrics (e.g., "Unknown")
                total_users = impact.get('total_users', 0)
                total_users_str = total_users if isinstance(total_users, str) else f"{total_users:,}"
                campaign_users = impact.get('campaign_users', 0)
                campaign_users_str = campaign_users if isinstance(campaign_users, str) else f"{campaign_users:,}"
                extensions_count = impact.get('extensions_count', 0)

                html += f"""
                    <!-- Impact Statistics -->
                    <div style="background: rgba(239, 68, 68, 0.1); border-radius: 8px; padding: 16px; margin-bottom: 16px; border: 1px solid rgba(239, 68, 68, 0.2);">
                        <div style="font-size: 11px; color: #fca5a5; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 12px; font-weight: 600;">Impact Assessment</div>
                        <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; text-align: center;">
                            <div>
                                <div style="font-size: 22px; font-weight: 700; color: #f87171;">{total_users_str}</div>
                                <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Total Users Affected</div>
                            </div>
                            <div>
                                <div style="font-size: 22px; font-weight: 700; color: #fbbf24;">{campaign_users_str}</div>
                                <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">This Campaign</div>
                            </div>
                            <div>
                                <div style="font-size: 22px; font-weight: 700; color: #60a5fa;">{extensions_count}</div>
                                <div style="font-size: 10px; color: #94a3b8; margin-top: 2px;">Known Extensions</div>
                            </div>
                        </div>
                    </div>
"""

            # Targets
            targets = campaign_data.get('targets', [])
            if targets:
                targets_html = ' '.join([f'<span style="background: rgba(96, 165, 250, 0.2); color: #93c5fd; padding: 4px 10px; border-radius: 4px; font-size: 11px; margin: 2px;">{t}</span>' for t in targets])
                html += f"""
                    <!-- Targets -->
                    <div style="margin-bottom: 16px;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Targeted Platforms</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">{targets_html}</div>
                    </div>
"""

            # Data Exfiltrated
            data_exfil = campaign_data.get('data_exfiltrated', [])
            if data_exfil:
                html += """
                    <!-- Data Exfiltrated -->
                    <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 14px; margin-bottom: 16px;">
                        <div style="font-size: 11px; color: #fca5a5; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 600;">Data Exfiltrated</div>
                        <ul style="margin: 0; padding-left: 18px; color: #e2e8f0; font-size: 13px; line-height: 1.8;">
"""
                for data in data_exfil[:6]:  # Limit to 6 items
                    html += f'                            <li>{data}</li>\n'
                html += """                        </ul>
                    </div>
"""

            # C2 Infrastructure
            c2_infra = campaign_data.get('c2_infrastructure', [])
            if c2_infra:
                html += """
                    <!-- C2 Infrastructure -->
                    <div style="background: rgba(239, 68, 68, 0.08); border-radius: 8px; padding: 14px; margin-bottom: 16px; border: 1px solid rgba(239, 68, 68, 0.15);">
                        <div style="font-size: 11px; color: #f87171; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 600;">C2 Infrastructure (IOCs)</div>
                        <div style="font-family: 'Monaco', 'Consolas', monospace; font-size: 12px; color: #fca5a5;">
"""
                for c2 in c2_infra:
                    html += f'                            <div style="padding: 4px 0; border-bottom: 1px solid rgba(255,255,255,0.05);">• {c2}</div>\n'
                html += """                        </div>
                    </div>
"""

            # TTPs
            ttps = campaign_data.get('ttps', {})
            if ttps:
                html += """
                    <!-- TTPs -->
                    <div style="background: rgba(255,255,255,0.05); border-radius: 8px; padding: 14px;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 600;">TTPs (MITRE ATT&CK)</div>
                        <div style="display: grid; gap: 8px; font-size: 12px;">
"""
                ttp_labels = {
                    'initial_access': ('Initial Access', '#60a5fa'),
                    'persistence': ('Persistence', '#a78bfa'),
                    'collection': ('Collection', '#f472b6'),
                    'exfiltration': ('Exfiltration', '#fb923c'),
                    'c2': ('C2', '#f87171')
                }
                for key, (label, color) in ttp_labels.items():
                    if ttps.get(key):
                        html += f"""
                            <div style="display: flex; gap: 10px; align-items: baseline;">
                                <span style="color: {color}; font-weight: 600; min-width: 100px;">{label}:</span>
                                <span style="color: #cbd5e1;">{ttps[key]}</span>
                            </div>
"""
                html += """                        </div>
                    </div>
"""

        else:
            # Web search based findings (no campaign_data)
            keywords = attribution.get('keywords_found', [])
            if keywords:
                keywords_html = ' '.join([f'<span style="background: rgba(251, 191, 36, 0.2); color: #fcd34d; padding: 4px 10px; border-radius: 4px; font-size: 11px; margin: 2px;">{k}</span>' for k in keywords[:5]])
                html += f"""
                    <!-- Keywords Found -->
                    <div style="margin-bottom: 16px;">
                        <div style="font-size: 11px; color: #94a3b8; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px;">Keywords Detected</div>
                        <div style="display: flex; flex-wrap: wrap; gap: 6px;">{keywords_html}</div>
                    </div>
"""

        html += """
                </div>
"""
        return html

    def _generate_threat_attribution_section(self, attribution):
        """Generate threat attribution section with OSINT analysis"""

        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔍</div>
                <div class="section-title">Threat Campaign Attribution (OSINT)</div>
            </div>
            <div class="subsection">
"""

        # Check if attribution found
        attribution_found = attribution.get('attribution_found', False)
        confidence = attribution.get('confidence', 'NONE')

        # Attribution confidence
        if confidence == 'CONFIRMED':
            conf_color = '#dc2626'
            conf_msg = 'CONFIRMED - Extension found in known malicious database'
        elif confidence == 'HIGH':
            conf_color = '#dc2626'
            conf_msg = 'HIGH - Extension identified in threat campaign via OSINT'
        elif confidence == 'MEDIUM':
            conf_color = '#f59e0b'
            conf_msg = 'MEDIUM - Malicious indicators found in web search results'
        elif confidence == 'LOW':
            conf_color = '#64748b'
            conf_msg = 'LOW - Mentions found but no clear malicious indicators'
        else:
            conf_color = '#64748b'
            conf_msg = 'No confirmed attribution to known campaigns'

        html += f"""
                <div class="finding-card" style="border-left: 4px solid {conf_color};">
                    <h3 style="color: {conf_color}; margin: 0 0 10px 0;">Attribution Confidence: {confidence}</h3>
                    <p style="font-size: 14px; margin: 0;">{conf_msg}</p>
                </div>
"""

        # Show OSINT analysis if attribution found
        if attribution_found and attribution.get('osint_summary'):
            campaign_name = attribution.get('campaign_name')
            threat_actor = attribution.get('threat_actor')
            campaign_desc = attribution.get('campaign_description', '')
            campaign_data = attribution.get('campaign_data', {})
            source_articles = attribution.get('source_articles', [])
            keywords_found = attribution.get('keywords_found', [])

            # Smart campaign name - if no specific campaign, derive from source
            if not campaign_name or campaign_name in ['None', 'Unknown Campaign', None]:
                if source_articles:
                    # Get first source name
                    first_source = source_articles[0].get('source', '') or source_articles[0].get('url', '')
                    if first_source:
                        # Extract domain name if it's a URL
                        if 'http' in first_source:
                            from urllib.parse import urlparse
                            domain = urlparse(first_source).netloc.replace('www.', '')
                            campaign_name = f"Identified in {domain}'s Security Disclosure"
                        else:
                            campaign_name = f"Identified in {first_source}'s Security Disclosure"
                    else:
                        campaign_name = "Identified via OSINT Research"
                elif keywords_found:
                    campaign_name = f"Flagged for: {', '.join(keywords_found[:3])}"
                else:
                    campaign_name = "Identified via Web Search Analysis"

            # Smart threat actor - don't show if unknown
            threat_actor_html = ""
            if threat_actor and threat_actor not in ['None', 'Unknown', None, 'Various / Unknown']:
                threat_actor_html = f'<p style="margin: 5px 0; font-size: 14px;"><strong>Threat Actor:</strong> {threat_actor}</p>'

            # Smart description - provide context if none
            if not campaign_desc:
                if keywords_found:
                    campaign_desc = f"This extension was flagged during security research. Keywords detected: {', '.join(keywords_found[:5])}"
                else:
                    campaign_desc = "This extension was identified as potentially malicious through automated OSINT research."

            html += f"""
                <div class="alert alert-critical" style="margin: 20px 0;">
                    <div class="alert-icon">🚨</div>
                    <div>
                        <strong style="font-size: 16px;">THREAT INTELLIGENCE ALERT</strong><br>
                        <p style="margin: 10px 0 5px 0; font-size: 14px;"><strong>Finding:</strong> {campaign_name}</p>
                        {threat_actor_html}
                        <p style="margin: 10px 0 0 0; font-size: 13px; color: #94a3b8;">{campaign_desc}</p>
                    </div>
                </div>

                <h3 style="margin-top: 25px;">OSINT Research Findings</h3>
"""
            # Generate beautiful structured HTML instead of raw markdown
            html += self._render_osint_findings(attribution, campaign_data)

            # Source articles
            source_articles = attribution.get('source_articles', [])
            if source_articles:
                html += """
                <h3 style="margin-top: 25px;">Threat Intelligence Sources</h3>
                <p style="font-size: 13px; color: #64748b; margin: 10px 0;">Research verified by the following security sources:</p>
"""
                for article in source_articles:
                    html += f"""
                <div style="padding: 12px; margin: 10px 0; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0;">
                    <strong style="font-size: 14px;">
                        <a href="{article['url']}" target="_blank" style="color: #2563eb; text-decoration: none;">
                            {article['title']}
                        </a>
                    </strong>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #64748b;">Source: {article['source']}</p>
                </div>
"""
        else:
            # No attribution found
            html += """
                <div class="finding-card" style="margin: 20px 0;">
                    <p style="font-size: 13px; margin: 0;">
                        ✓ No confirmed attribution to known threat campaigns based on OSINT research.<br><br>
                        This does not mean the extension is safe - it may be a new campaign, unpublished threat, or benign software.
                        Continue with technical analysis to determine actual risk.
                    </p>
                </div>
"""

        # VirusTotal comments link
        if attribution.get('virustotal_comments'):
            html += f"""
                <div style="margin-top: 20px; padding: 15px; background: #f1f5f9; border-radius: 8px; border: 1px solid #cbd5e1;">
                    <strong style="font-size: 14px;">VirusTotal Community Intelligence:</strong><br>
                    <p style="margin: 8px 0; font-size: 12px; color: #64748b;">Check community analysis and comments from security researchers</p>
                    <a href="{attribution['virustotal_comments']}" target="_blank" style="font-size: 13px; color: #2563eb; text-decoration: none;">
                        View VirusTotal Comments →
                    </a>
                </div>
"""

        html += """
            </div>
        </div>
"""

        return html

    def _generate_recommendations_section(self, results, threat_class):
        """Generate evidence-based recommendations scaled to actual findings"""

        risk_level = results.get('risk_level')
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        vt_malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']

        # Check for credential theft evidence
        pii_classification = results.get('pii_classification', {})
        pii_categories = [c['category'] for c in pii_classification.get('classifications', [])]
        has_credential_theft = 'CREDENTIALS' in pii_categories or 'COOKIES_SESSIONS' in pii_categories

        # Check detection strength
        total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)

        rec_class = 'critical' if risk_level in ['CRITICAL', 'HIGH'] or (vt_malicious and total_detections >= 10) else ''

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🎯</div>
                <div class="section-title">Security Recommendations</div>
            </div>
            <div class="recommendations {rec_class}">
                <h3>{'⚠️' if rec_class == 'critical' else '✅'} Recommended Actions</h3>
                <div class="rec-list">
"""

        if vt_malicious and total_detections >= 10:
            # High confidence - multiple vendors
            recs = [
                f"<strong>Priority 1:</strong> {len(vt_malicious)} domain(s) flagged by {total_detections} security vendors",
                f"Consider blocking extension ID {results['extension_id']} pending further investigation",
                "Review extension across deployed systems",
                "Monitor network logs for suspicious activity",
                "Check browser history for accessed domains"
            ]
            if has_credential_theft:
                recs.append("<strong>If credential access confirmed:</strong> Consider password resets for affected users")
            recs.append("Consider reporting to Chrome Web Store if malicious behavior confirmed")

        elif vt_malicious and total_detections >= 3:
            # Moderate confidence
            recs = [
                f"<strong>Priority 2:</strong> {len(vt_malicious)} domain(s) flagged by {total_detections} security vendors",
                "Manual security review recommended",
                "Consider temporary suspension pending investigation",
                "Review extension behavior and network activity",
                "Evaluate business need vs security risk"
            ]
            if has_credential_theft:
                recs.append("<strong>If credential access confirmed:</strong> Evaluate need for password resets")

        elif vt_malicious:
            # Low confidence - possible false positives
            recs = [
                f"<strong>Priority 3:</strong> {len(vt_malicious)} domain(s) flagged by {total_detections} vendor(s) (low detection count)",
                "Manual verification recommended - could be false positives",
                "Review flagged domains for legitimacy (e.g., Firebase, CDNs)",
                "Monitor for additional suspicious behaviors",
                "Re-assess if additional indicators emerge"
            ]
        elif campaign:
            recs = [
                f"<strong>Investigate:</strong> Extension behavior similar to {campaign.get('name', 'known malware')} patterns",
                "Manual verification recommended to confirm attribution",
                f"Consider blocking extension ID {results['extension_id']} pending review",
                "Review systems where extension is deployed",
                "Document findings for security team",
                "Consider reporting if malicious behavior confirmed"
            ]
        elif settings.get('has_overrides'):
            recs = [
                "<strong>Review:</strong> Extension modifies browser settings",
                "Evaluate if modifications are justified by extension functionality",
                "Review privacy and user consent implications",
                "Consider user awareness training on browser modifications",
                "Monitor for additional suspicious behaviors"
            ]
        elif risk_level == 'CRITICAL':
            recs = [
                "Detailed security review recommended before deployment",
                "Test in isolated environment first",
                "Monitor network traffic during testing",
                "Evaluate all permissions for necessity",
                "Consider alternative solutions if available"
            ]
        elif risk_level == 'HIGH':
            recs = [
                "Manual code review recommended",
                "Limit deployment to test environments initially",
                "Monitor for unexpected behavior",
                "Re-assess periodically",
                "Consider alternatives if concerns persist"
            ]
        else:
            recs = [
                "No immediately critical issues identified",
                "Standard security practices apply",
                "Implement version pinning for stability",
                "Periodic re-assessment recommended (quarterly)",
                "Monitor for significant updates"
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