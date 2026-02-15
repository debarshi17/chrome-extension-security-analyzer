"""
Professional Threat Analysis Report Generator - FIXED VERSION
Shows exact POST destinations, data sources, and VirusTotal cross-references
Modern design inspired by Mandiant, CrowdStrike, Unit 42
"""

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import json
import html as html_module  # For escaping permission strings that contain angle brackets like <all_urls>

class ProfessionalReportGenerator:
    """Generates professional threat analysis reports"""
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
        self._file_display_map = {}

    def _build_file_display_map(self, results):
        """Build map: full path -> display name. Duplicate basenames become filename(2), filename(3), etc."""
        paths = []
        for p in results.get('malicious_patterns', []):
            f = p.get('file')
            if f:
                paths.append(f)
        ast = results.get('ast_results', {})
        for item in ast.get('data_exfiltration', []) + ast.get('network_calls', []):
            f = item.get('file')
            if f:
                paths.append(f)
        sensitive = results.get('pii_classification', {}) or {}
        for gm in sensitive.get('gmail_module', []):
            f = gm.get('file')
            if f:
                paths.append(f)
        adv = results.get('advanced_detection') or {}
        for finding in adv.get('findings', []):
            ev = finding.get('evidence', {}) or {}
            if isinstance(ev, dict) and ev.get('file'):
                paths.append(ev['file'])
        for cat_data in adv.values():
            if isinstance(cat_data, list):
                for finding in cat_data:
                    ev = finding.get('evidence', {}) if isinstance(finding, dict) else {}
                    if isinstance(ev, dict) and ev.get('file'):
                        paths.append(ev['file'])
        for rel_path in (results.get('obfuscation_indicators') or {}).keys():
            if rel_path:
                paths.append(rel_path)
        # Order by first occurrence; then assign display names by basename count
        seen_basename_count = {}
        display_map = {}
        for p in paths:
            if not p or p in display_map:
                continue
            base = Path(p).name or p
            count = seen_basename_count.get(base, 0) + 1
            seen_basename_count[base] = count
            display_map[p] = f"{base}({count})" if count > 1 else base
        return display_map

    def _file_display_name(self, file_path):
        """Return display name for a file path (disambiguates duplicate basenames as filename(2), etc.)."""
        if not file_path or file_path == 'N/A':
            return file_path or 'unknown'
        return self._file_display_map.get(file_path, file_path)
    
    def generate_threat_analysis_report(self, results):
        """Generate professional threat analysis report"""
        
        self._file_display_map = self._build_file_display_map(results)

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
    <title>Threat Analysis Report - {extension_name}</title>
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
                        <div class="subtitle">Threat Analysis Report • {datetime.now().strftime('%B %d, %Y at %H:%M UTC')}</div>
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
                    <div class="meta-label">{'Extension Type' if results.get('extension_type') == 'vscode' else 'Manifest Version'}</div>
                    <div class="meta-value">{'VSCode Extension' if results.get('extension_type') == 'vscode' else f"MV{results.get('manifest_version', '?')}"}</div>
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

        # Scan coverage (transparency when full scan failed on some files)
        scan_coverage = results.get('scan_coverage')
        if scan_coverage and isinstance(scan_coverage, dict):
            html += self._generate_scan_coverage_section(scan_coverage)

        # Lab / Sinkhole context (localhost-only C2 — no real internet exfil)
        if results.get('sinkhole_or_lab_c2'):
            html += self._generate_lab_sinkhole_section(results)

        # VSCode-specific sections
        if results.get('extension_type') == 'vscode':
            html += self._generate_vscode_overview_section(results)
            html += self._generate_vscode_supply_chain_section(results)
            html += self._generate_vscode_code_analysis_section(results)

        # Risk Score Breakdown (V2)
        if results.get('risk_breakdown'):
            html += self._generate_risk_breakdown_section(results)

        # Behavioral Threat Analysis (V2)
        bc_data = results.get('behavioral_correlations', {})
        if isinstance(bc_data, dict) and bc_data.get('correlations'):
            html += self._generate_behavioral_correlations_section(bc_data, results)

        # Permission Attack Paths (V2)
        attack_paths = results.get('permissions', {}).get('attack_paths', [])
        if attack_paths:
            html += self._generate_attack_paths_section(attack_paths)

        # Attack Narrative (V3)
        attack_narrative = results.get('attack_narrative', {})
        if attack_narrative.get('attack_chain'):
            html += self._generate_attack_narrative_section(attack_narrative)

        # Sensitive Targets (V3)
        sensitive_targets = results.get('sensitive_targets', {})
        if isinstance(sensitive_targets, dict) and (sensitive_targets.get('targets') or sensitive_targets.get('gmail_module')):
            html += self._generate_sensitive_targets_section(sensitive_targets)

        # Campaign Fingerprint (V3)
        campaign_fp = results.get('campaign_fingerprint', {})
        if campaign_fp.get('matched_campaigns'):
            html += self._generate_campaign_fingerprint_section(campaign_fp)

        # IOC Section
        html += self._generate_ioc_section(results)

        # Host Permissions Analysis (Chrome/Edge only)
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

        # Supply Chain Version Diff (V2)
        version_diff = results.get('version_diff', {})
        if version_diff.get('has_baseline') and version_diff.get('changes'):
            html += self._generate_version_diff_section(version_diff)

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
            <div class="footer-logo">Extension Security Analyzer</div>
            <div>Professional Threat Analysis • Powered by VirusTotal & Static Analysis</div>
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
        # Use V2 threat classification if available
        tc = results.get('threat_classification', {})
        tc_class = tc.get('classification', '')
        tc_primary = tc.get('primary_archetype', '')

        if tc_class == 'MALICIOUS_INDICATORS':
            primary_display = tc_primary.replace('_', ' ').title() if tc_primary != 'UNKNOWN' else 'Multiple Threats'
            return f'Malicious Indicators ({primary_display})'
        elif tc_class == 'HIGH_RISK_SUSPICIOUS':
            primary_display = tc_primary.replace('_', ' ').title() if tc_primary != 'UNKNOWN' else 'Suspicious'
            return f'High Risk ({primary_display})'
        elif tc_class == 'ELEVATED_RISK':
            return 'Elevated Risk - Investigation Needed'

        # Fall back to legacy classification
        campaign = results.get('campaign_attribution')
        settings = results.get('settings_overrides', {})
        vt_results = results.get('virustotal_results', [])
        vt_malicious = [r for r in vt_results if r.get('threat_level') == 'MALICIOUS']

        total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)

        if vt_malicious and total_detections >= 10:
            return 'Likely Malicious'
        elif vt_malicious and total_detections >= 5:
            return 'Suspicious Activity Detected'
        elif vt_malicious:
            return 'Potentially Suspicious'
        elif campaign:
            return campaign.get('name', 'Matches Known Campaign Pattern')
        elif settings.get('search_hijacking'):
            return 'Possible Browser Hijacker'
        elif len(results.get('malicious_patterns', [])) > 15:
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
                confidence += 20
            elif total_detections >= 5:
                confidence += 12
            else:
                confidence += 5

        if results.get('campaign_attribution'):
            confidence += 15

        if results.get('settings_overrides', {}).get('has_overrides'):
            confidence += 8

        # V2: Behavioral correlations increase confidence
        bc = results.get('behavioral_correlations', {})
        bc_summary = bc.get('summary', {}) if isinstance(bc, dict) else {}
        if bc_summary.get('critical', 0) >= 2:
            confidence += 15  # Multiple critical chains = strong signal
        elif bc_summary.get('critical', 0) >= 1:
            confidence += 10
        elif bc_summary.get('high', 0) >= 2:
            confidence += 5

        # Cap at 90% with behavioral evidence, 85% without
        max_conf = 90 if bc_summary.get('critical', 0) > 0 else 85
        return min(confidence, max_conf)
    
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
        attribution = results.get('threat_attribution') or {}
        attr_conf = attribution.get('confidence', 'NONE')
        attr_found = attribution.get('attribution_found', False)
        has_ti_sources = bool(attribution.get('source_articles'))
        
        summary_class = 'critical' if risk_level in ['CRITICAL', 'HIGH'] or vt_malicious else ''
        
        # Use V2 threat classification if available
        tc = results.get('threat_classification', {})
        tc_class = tc.get('classification', '')
        tc_summary = tc.get('summary', '')
        tc_primary = tc.get('primary_archetype', '')

        # BLUF (Bottom Line Up Front) - Use V2 classification and OSINT when available
        if attr_found and attr_conf == 'CONFIRMED':
            # External threat intelligence has already confirmed this extension as malicious
            bluf = "External threat intelligence has confirmed this extension as malicious. Immediate removal and incident response are strongly recommended."
        elif tc_class == 'MALICIOUS_INDICATORS':
            bluf = f"MALICIOUS INDICATORS: {tc_summary} Immediate removal recommended."
        elif tc_class == 'HIGH_RISK_SUSPICIOUS':
            bluf = f"HIGH RISK: {tc_summary} Manual security review and monitoring recommended."
        elif vt_malicious:
            total_detections = sum(r.get('stats', {}).get('malicious', 0) for r in vt_malicious)
            if total_detections >= 10:
                bluf = f"{len(vt_malicious)} domain(s) flagged by multiple security vendors ({total_detections} total detections). Suspicious activity detected. Further investigation recommended."
            elif total_detections >= 5:
                bluf = f"{len(vt_malicious)} domain(s) flagged by security vendors ({total_detections} total detections). Potentially suspicious behavior detected. Manual review recommended."
            else:
                bluf = f"{len(vt_malicious)} domain(s) flagged by limited security vendors ({total_detections} total detections). May indicate suspicious activity or false positives. Manual verification recommended."
        elif campaign:
            bluf = f"Extension behavior patterns similar to {campaign['name']} campaign. Further analysis recommended to confirm attribution."
        elif tc_class == 'ELEVATED_RISK':
            bluf = f"ELEVATED RISK: {tc_summary}"
        elif settings.get('search_hijacking'):
            bluf = "Extension modifies browser search settings. Could indicate affiliate revenue generation or user tracking. Review privacy implications."
        elif risk_level == 'CRITICAL':
            bluf = "Multiple suspicious behaviors detected. Extension exhibits characteristics associated with potentially unwanted programs. Manual security review recommended."
        elif risk_level == 'HIGH':
            if attr_found and attr_conf in ('CONFIRMED', 'HIGH', 'MEDIUM'):
                bluf = "This extension is flagged by external security research as potentially malicious. Treat as hostile until proven otherwise and restrict usage."
            else:
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

        # Threat intelligence / OSINT findings
        if attr_found:
            if attr_conf == 'CONFIRMED':
                findings.append(('🧠', "Confirmed malicious in external threat intelligence sources (see Threat Intelligence section)."))
            elif has_ti_sources or attr_conf in ('HIGH', 'MEDIUM', 'LOW'):
                campaign_name = attribution.get('campaign_name') or "external security research"
                findings.append(('🧠', f"Identified as suspicious/malicious in {campaign_name} based on OSINT threat intelligence."))

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
        
        # Behavioral correlations (V2)
        bc = results.get('behavioral_correlations', {})
        bc_correlations = bc.get('correlations', []) if isinstance(bc, dict) else []
        bc_crit = [c for c in bc_correlations if c.get('severity') == 'critical']
        bc_high = [c for c in bc_correlations if c.get('severity') == 'high']
        if bc_crit:
            findings.append(('🔗', f"{len(bc_crit)} critical attack chain(s) detected: " +
                           ', '.join(c['name'] for c in bc_crit[:3])))
        elif bc_high:
            findings.append(('🔗', f"{len(bc_high)} high-risk behavioral pattern(s) detected"))

        # Attack paths (V2)
        attack_paths = results.get('permissions', {}).get('attack_paths', [])
        crit_paths = [ap for ap in attack_paths if ap.get('severity') == 'CRITICAL']
        if crit_paths:
            findings.append(('⚡', f"{len(crit_paths)} critical attack path(s): " +
                           ', '.join(ap['name'] for ap in crit_paths[:3])))

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
    
    def _generate_scan_coverage_section(self, scan_coverage):
        """Scan coverage: total JS files, fully scanned count, files with parse/scan errors (fallback used)."""
        total = scan_coverage.get('total_js_files') or 0
        if total == 0:
            return ''
        full = scan_coverage.get('files_fully_scanned', 0)
        errors = scan_coverage.get('files_with_scan_errors', 0)
        pct = round(100 * full / total) if total else 0
        color = '#22c55e' if errors == 0 else '#eab308' if pct >= 70 else '#f97316'
        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">📋</div>
                <div class="section-title">Scan Coverage</div>
            </div>
            <div style="display: flex; align-items: center; gap: 16px; flex-wrap: wrap;">
                <div style="font-size: 28px; font-weight: 700; color: {color};">{pct}%</div>
                <div style="color: var(--text-secondary); font-size: 14px;">
                    {full} of {total} JS files fully scanned.
                    {f'{errors} file(s) used fallback pattern-only scan (parse/slice errors).' if errors else 'All files parsed successfully.'}
                </div>
            </div>
        </div>
"""
        return html

    def _generate_lab_sinkhole_section(self, results):
        """Sinkhole C2: destinations are localhost only — used to validate rule engine, not real C2."""
        context = results.get('lab_malware_context', 'All C2/exfil destinations are sinkhole domains (localhost). Used only to validate the rule engine.')
        tc = results.get('threat_classification', {})
        env_summary = tc.get('environment_summary', context)
        html = f"""
        <div class="section" style="border: 2px solid #3b82f6;">
            <div class="section-header">
                <div class="section-icon">🧪</div>
                <div class="section-title">Sinkhole C2 — Rule Engine Validation</div>
            </div>
            <div style="padding: 16px; background: rgba(59, 130, 246, 0.1); border-radius: 8px;">
                <p style="margin: 0 0 12px 0; font-size: 14px; color: var(--text-primary);">
                    {html_module.escape(env_summary)}
                </p>
                <p style="margin: 0; font-size: 13px; color: var(--text-secondary);">
                    The extension uses <strong>sinkhole domains</strong> (e.g. 127.0.0.1) as C2/exfil targets — the same patterns as real malware, but no data leaves the host. 
                    This is used to <strong>check that the detection rules work correctly</strong>; these are not real C2 domains.
                </p>
            </div>
        </div>
"""
        return html

    def _generate_risk_breakdown_section(self, results):
        """Generate V2 risk score breakdown with component bars"""
        breakdown = results.get('risk_breakdown', {})
        risk_score = results.get('risk_score', 0)
        risk_level = results.get('risk_level', 'UNKNOWN')
        tc = results.get('threat_classification', {})

        components = [
            ('Permissions', breakdown.get('permissions', 0), 2.5, '#f97316'),
            ('Code Analysis', breakdown.get('code_analysis', 0), 2.5, '#eab308'),
            ('Behavioral Correlations', breakdown.get('behavioral_correlations', 0), 3.0, '#ef4444'),
            ('Infrastructure', breakdown.get('infrastructure', 0), 2.0, '#8b5cf6'),
        ]

        positive = breakdown.get('positive_signals', 0)

        # Classification badge
        classification = tc.get('classification', '')
        primary = tc.get('primary_archetype', '')
        class_color = {
            'MALICIOUS_INDICATORS': '#ef4444',
            'HIGH_RISK_SUSPICIOUS': '#f97316',
            'ELEVATED_RISK': '#eab308',
            'SUSPICIOUS_HIGH_RISK': '#f97316',
            'MODERATE_RISK': '#eab308',
            'LOW_RISK': '#22c55e',
        }.get(classification, '#64748b')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">📊</div>
                <div class="section-title">Risk Score Breakdown</div>
            </div>

            <div style="display: flex; gap: 30px; align-items: flex-start; flex-wrap: wrap;">
                <div style="flex: 0 0 200px; text-align: center;">
                    <div style="font-size: 56px; font-weight: 800; color: {self._get_risk_color(risk_level)};">{risk_score:.1f}</div>
                    <div style="font-size: 14px; color: var(--text-secondary); margin-top: 4px;">out of 10.0</div>
                    <div style="margin-top: 12px; padding: 6px 16px; border-radius: 20px; display: inline-block;
                                background: {self._get_risk_color(risk_level)}; color: white;
                                font-weight: 700; font-size: 13px; letter-spacing: 1px;">
                        {risk_level} RISK
                    </div>
"""
        if classification and classification not in ('LOW_RISK', 'MODERATE_RISK'):
            html += f"""
                    <div style="margin-top: 10px; padding: 6px 12px; border-radius: 16px; display: inline-block;
                                border: 1px solid {class_color}; color: {class_color};
                                font-size: 11px; font-weight: 600; letter-spacing: 0.5px;">
                        {classification.replace('_', ' ')}
                    </div>
"""
        if primary and primary != 'UNKNOWN':
            html += f"""
                    <div style="margin-top: 6px; font-size: 12px; color: var(--text-secondary);">
                        Primary: {primary.replace('_', ' ')}
                    </div>
"""
        html += """
                </div>
                <div style="flex: 1; min-width: 300px;">
"""
        for name, value, max_val, color in components:
            pct = (value / max_val * 100) if max_val > 0 else 0
            html += f"""
                    <div style="margin-bottom: 16px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                            <span style="font-size: 13px; font-weight: 600; color: var(--text-primary);">{name}</span>
                            <span style="font-size: 13px; color: var(--text-secondary);">{value:.1f} / {max_val:.1f}</span>
                        </div>
                        <div style="height: 10px; background: rgba(255,255,255,0.08); border-radius: 5px; overflow: hidden;">
                            <div style="height: 100%; width: {pct:.0f}%; background: {color}; border-radius: 5px;
                                        transition: width 0.3s;"></div>
                        </div>
                    </div>
"""

        if positive < 0:
            html += f"""
                    <div style="margin-top: 8px; padding: 8px 14px; background: rgba(34, 197, 94, 0.1);
                                border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px;
                                font-size: 12px; color: #86efac;">
                        Positive signals: {positive:.1f} (verified publisher, user count, narrow scope)
                    </div>
"""
        html += """
                </div>
            </div>
        </div>
"""
        return html

    def _generate_behavioral_correlations_section(self, bc_data, results):
        """Generate behavioral threat analysis section showing attack chains"""
        correlations = bc_data.get('correlations', [])
        summary = bc_data.get('summary', {})

        severity_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#eab308',
            'low': '#22c55e',
        }
        severity_icons = {
            'critical': '🔴',
            'high': '🟠',
            'medium': '🟡',
            'low': '🟢',
        }
        attack_type_icons = {
            'session_hijacking': '🍪',
            'credential_theft': '🔑',
            'surveillance': '👁️',
            'data_exfiltration': '📤',
            'remote_code_exec': '💉',
            'wallet_hijack': '💰',
            'search_hijack': '🔍',
            'fingerprinting': '🖐️',
            'tracking': '📡',
            'extension_manipulation': '🧩',
            'staged_payload': '📦',
            'phishing_overlay': '🎣',
            'traffic_mitm': '🔀',
            'c2_channel': '📡',
            'evasive_malware': '🥷',
            'system_escape': '🖥️',
            'oauth_theft': '🔐',
        }

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔗</div>
                <div class="section-title">Behavioral Threat Analysis</div>
            </div>

            <div style="margin-bottom: 20px; padding: 16px; background: rgba(239, 68, 68, 0.08);
                        border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 8px;">
                <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 8px;">
                    <strong>{summary.get('total_correlations', len(correlations))} compound threat pattern(s)</strong> detected by correlating findings across permissions, code patterns, and infrastructure.
                </div>
                <div style="display: flex; gap: 16px; font-size: 12px; color: var(--text-secondary);">
                    <span>🔴 Critical: <strong style="color: #ef4444;">{summary.get('critical', 0)}</strong></span>
                    <span>🟠 High: <strong style="color: #f97316;">{summary.get('high', 0)}</strong></span>
                    <span>🟡 Medium: <strong style="color: #eab308;">{summary.get('medium', 0)}</strong></span>
                </div>
            </div>

            <div style="display: grid; gap: 16px;">
"""

        # Sort: critical first, then high, then medium
        sorted_corr = sorted(correlations,
                             key=lambda c: {'critical': 0, 'high': 1, 'medium': 2}.get(
                                 c.get('severity', ''), 3))

        for corr in sorted_corr:
            sev = corr.get('severity', 'medium')
            color = severity_colors.get(sev, '#64748b')
            icon = severity_icons.get(sev, '⚪')
            attack_icon = attack_type_icons.get(corr.get('attack_type', ''), '🔗')
            name = html_module.escape(corr.get('name', 'Unknown'))
            desc = html_module.escape(corr.get('description', ''))
            evidence = html_module.escape(corr.get('evidence', ''))
            confidence = corr.get('confidence', 'medium')
            attack_type = corr.get('attack_type', '').replace('_', ' ').title()

            html += f"""
                <div style="background: var(--bg-card); border: 1px solid var(--border-color);
                            border-left: 4px solid {color}; border-radius: 8px; padding: 20px;">
                    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px;">
                        <div style="display: flex; align-items: center; gap: 10px;">
                            <span style="font-size: 20px;">{attack_icon}</span>
                            <div>
                                <div style="font-size: 16px; font-weight: 700; color: var(--text-primary);">{name}</div>
                                <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">{attack_type}</div>
                            </div>
                        </div>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
                                        background: {color}; color: white; text-transform: uppercase;">{sev}</span>
                            <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px;
                                        border: 1px solid var(--border-color); color: var(--text-secondary);">
                                {confidence} confidence
                            </span>
                        </div>
                    </div>
                    <div style="font-size: 14px; color: var(--text-primary); margin-bottom: 12px; line-height: 1.6;">{desc}</div>
                    <div style="padding: 10px 14px; background: rgba(0,0,0,0.2); border-radius: 6px;
                                font-size: 12px; font-family: 'Monaco', 'Courier New', monospace; color: #94a3b8;">
                        <strong style="color: var(--text-primary);">Evidence:</strong> {evidence}
                    </div>
"""
            # Show components if available
            components = corr.get('components', [])
            if components:
                html += """
                    <div style="margin-top: 10px; display: flex; flex-wrap: wrap; gap: 6px;">
"""
                for comp in components:
                    comp_escaped = html_module.escape(str(comp))
                    html += f"""
                        <span style="padding: 2px 8px; border-radius: 10px; font-size: 11px;
                                    background: rgba(255,255,255,0.06); border: 1px solid var(--border-color);
                                    color: var(--text-secondary);">{comp_escaped}</span>
"""
                html += "                    </div>"

            html += """
                </div>
"""

        html += """
            </div>
        </div>
"""
        return html

    def _generate_attack_paths_section(self, attack_paths):
        """Generate permission attack paths section"""
        severity_colors = {
            'CRITICAL': '#ef4444',
            'HIGH': '#f97316',
            'MEDIUM': '#eab308',
        }

        crit_count = sum(1 for ap in attack_paths if ap.get('severity') == 'CRITICAL')
        high_count = sum(1 for ap in attack_paths if ap.get('severity') == 'HIGH')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚡</div>
                <div class="section-title">Permission Attack Paths</div>
            </div>

            <div style="margin-bottom: 20px; font-size: 14px; color: var(--text-secondary); line-height: 1.6;">
                Permission combinations that enable specific attack capabilities.
                {crit_count} critical and {high_count} high-severity path(s) detected.
            </div>

            <div style="display: grid; gap: 12px;">
"""

        for ap in sorted(attack_paths,
                         key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(
                             x.get('severity', ''), 3)):
            sev = ap.get('severity', 'MEDIUM')
            color = severity_colors.get(sev, '#64748b')
            name = html_module.escape(ap.get('name', ''))
            desc = html_module.escape(ap.get('description', ''))
            perms = ap.get('permissions', [])
            score = ap.get('score', 0)

            perm_badges = ' '.join(
                f'<span style="padding: 2px 8px; border-radius: 10px; font-size: 11px; '
                f'background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3); '
                f'color: #fca5a5;">{html_module.escape(p)}</span>'
                for p in perms
            )

            html += f"""
                <div style="background: var(--bg-card); border: 1px solid var(--border-color);
                            border-left: 4px solid {color}; border-radius: 8px; padding: 16px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                        <div style="font-size: 15px; font-weight: 700; color: var(--text-primary);">{name}</div>
                        <div style="display: flex; gap: 8px; align-items: center;">
                            <span style="font-size: 12px; color: var(--text-secondary);">+{score:.1f}</span>
                            <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
                                        background: {color}; color: white;">{sev}</span>
                        </div>
                    </div>
                    <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 10px;">{desc}</div>
                    <div style="display: flex; flex-wrap: wrap; gap: 6px;">
                        {perm_badges}
                    </div>
                </div>
"""

        html += """
            </div>
        </div>
"""
        return html

    def _generate_version_diff_section(self, version_diff):
        """Generate supply chain version diff section"""
        changes = version_diff.get('changes', [])
        sc_level = version_diff.get('supply_chain_level', 'LOW')
        sc_risk = version_diff.get('supply_chain_risk', 0)
        risk_delta = version_diff.get('risk_delta', 0)
        old_v = version_diff.get('old_version', '?')
        new_v = version_diff.get('new_version', '?')
        baseline_date = version_diff.get('baseline_date', '?')

        level_colors = {
            'CRITICAL': '#ef4444',
            'HIGH': '#f97316',
            'MEDIUM': '#eab308',
            'LOW': '#22c55e',
        }
        sc_color = level_colors.get(sc_level, '#64748b')

        severity_colors = {
            'critical': '#ef4444',
            'high': '#f97316',
            'medium': '#eab308',
            'low': '#22c55e',
        }

        delta_str = f"+{risk_delta:.1f}" if risk_delta > 0 else f"{risk_delta:.1f}"
        delta_color = '#ef4444' if risk_delta > 0 else '#22c55e' if risk_delta < 0 else '#64748b'

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔄</div>
                <div class="section-title">Supply Chain Version Analysis</div>
            </div>

            <div style="display: flex; gap: 20px; margin-bottom: 20px; flex-wrap: wrap;">
                <div style="padding: 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 150px; text-align: center;">
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Version Change</div>
                    <div style="font-size: 16px; font-weight: 700; color: var(--text-primary);">v{html_module.escape(str(old_v))} → v{html_module.escape(str(new_v))}</div>
                </div>
                <div style="padding: 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 150px; text-align: center;">
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Supply Chain Risk</div>
                    <div style="font-size: 16px; font-weight: 700; color: {sc_color};">{sc_level} ({sc_risk:.1f}/5)</div>
                </div>
                <div style="padding: 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 150px; text-align: center;">
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Risk Delta</div>
                    <div style="font-size: 16px; font-weight: 700; color: {delta_color};">{delta_str}</div>
                </div>
                <div style="padding: 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 150px; text-align: center;">
                    <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 4px;">Baseline Date</div>
                    <div style="font-size: 14px; font-weight: 600; color: var(--text-primary);">{html_module.escape(str(baseline_date)[:10])}</div>
                </div>
            </div>

            <div style="display: grid; gap: 10px;">
"""
        for change in changes:
            sev = change.get('severity', 'medium')
            color = severity_colors.get(sev, '#64748b')
            desc = html_module.escape(change.get('description', ''))
            change_type = change.get('type', '').replace('_', ' ').title()

            html += f"""
                <div style="padding: 12px 16px; background: var(--bg-card); border-left: 4px solid {color};
                            border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div style="font-size: 14px; font-weight: 600; color: var(--text-primary);">{desc}</div>
                        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 4px;">{change_type}</div>
                    </div>
                    <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
                                background: {color}; color: white; text-transform: uppercase; flex-shrink: 0;">{sev}</span>
                </div>
"""

        html += """
            </div>
        </div>
"""
        return html

    # ------------------------------------------------------------------
    # V3 report sections
    # ------------------------------------------------------------------

    def _generate_attack_narrative_section(self, narrative):
        """Generate attack narrative chain visualization (V3)"""
        chain = narrative.get('attack_chain', [])
        confidence = narrative.get('confidence', 'low')
        impact = narrative.get('impact_summary', '')

        conf_colors = {'high': '#ef4444', 'medium': '#f97316', 'low': '#eab308'}
        stage_icons = {'ACCESS': '🔓', 'COLLECT': '📥', 'EXFILTRATE': '📤', 'PERSIST': '🔁'}
        risk_colors = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#22c55e'}
        conf_color = conf_colors.get(confidence, '#64748b')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⛓️</div>
                <div class="section-title">Attack Narrative</div>
                <span style="margin-left: auto; padding: 4px 12px; border-radius: 12px; font-size: 11px;
                            font-weight: 700; background: {conf_color}; color: white; text-transform: uppercase;">
                    {html_module.escape(confidence)} confidence
                </span>
            </div>
"""
        if impact:
            html += f"""
            <div style="padding: 14px 18px; margin-bottom: 20px; background: rgba(239, 68, 68, 0.08);
                        border: 1px solid rgba(239, 68, 68, 0.25); border-radius: 8px;
                        font-size: 13px; color: #fca5a5; line-height: 1.6;">
                {html_module.escape(impact)}
            </div>
"""

        # Chain visualization
        html += '            <div style="display: flex; align-items: stretch; gap: 0; flex-wrap: wrap;">\n'
        for i, stage in enumerate(chain):
            stage_name = html_module.escape(stage.get('stage', ''))
            capability = html_module.escape(stage.get('capability', ''))
            risk = stage.get('risk', 'medium')
            r_color = risk_colors.get(risk, '#64748b')
            icon = stage_icons.get(stage_name, '🔗')

            # Arrow between stages
            if i > 0:
                html += """
                <div style="display: flex; align-items: center; padding: 0 4px; color: var(--text-secondary); font-size: 22px;">→</div>
"""
            destinations = stage.get('destinations', [])
            dest_html = ''
            if destinations:
                dest_list = ', '.join(html_module.escape(d) for d in destinations[:5])
                dest_html = f'<div style="font-size: 11px; color: #fca5a5; margin-top: 4px;">→ {dest_list}</div>'

            html += f"""
                <div style="flex: 1; min-width: 180px; padding: 16px; background: var(--bg-card);
                            border-top: 3px solid {r_color}; border-radius: 8px;">
                    <div style="font-size: 20px; margin-bottom: 6px;">{icon}</div>
                    <div style="font-size: 12px; font-weight: 700; color: {r_color}; letter-spacing: 1px; margin-bottom: 6px;">
                        {stage_name}
                    </div>
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">{capability}</div>
                    {dest_html}
                </div>
"""
        html += '            </div>\n'

        html += """
        </div>
"""
        return html

    def _generate_sensitive_targets_section(self, sensitive_data):
        """Generate sensitive target detection section (V3)"""
        targets = sensitive_data.get('targets', [])
        gmail_modules = sensitive_data.get('gmail_module', [])
        multiplier = sensitive_data.get('risk_multiplier', 1.0)
        categories = sensitive_data.get('categories', [])

        category_icons = {
            'email': '📧', 'productivity': '💼',
            'finance': '💰', 'auth': '🔐',
        }
        severity_colors = {
            'critical': '#ef4444', 'high': '#f97316',
            'medium': '#eab308', 'low': '#22c55e',
        }

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🎯</div>
                <div class="section-title">Sensitive Target Detection</div>
                <span style="margin-left: auto; padding: 4px 12px; border-radius: 12px; font-size: 11px;
                            font-weight: 700; background: #ef4444; color: white;">
                    {len(targets)} target{'s' if len(targets) != 1 else ''} &middot; {multiplier:.1f}x multiplier
                </span>
            </div>
"""
        # Category summary chips
        if categories:
            html += '            <div style="display: flex; gap: 8px; margin-bottom: 16px; flex-wrap: wrap;">\n'
            for cat in categories:
                icon = category_icons.get(cat, '⚠️')
                html += f"""
                <span style="padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 600;
                            background: rgba(239, 68, 68, 0.12); border: 1px solid rgba(239, 68, 68, 0.3); color: #fca5a5;">
                    {icon} {html_module.escape(cat.upper())}
                </span>
"""
            html += '            </div>\n'

        # Target list
        if targets:
            html += '            <div style="display: grid; gap: 8px; margin-bottom: 16px;">\n'
            for t in targets:
                sev = t.get('severity', 'medium')
                s_color = severity_colors.get(sev, '#64748b')
                domain = html_module.escape(t.get('domain', ''))
                desc = html_module.escape(t.get('description', ''))
                source = html_module.escape(t.get('source', ''))
                run_at = t.get('run_at', '')

                run_at_badge = ''
                if run_at == 'document_start':
                    run_at_badge = ('<span style="margin-left: 8px; padding: 2px 8px; border-radius: 10px; '
                                    'font-size: 10px; font-weight: 700; background: #ef4444; color: white;">'
                                    'DOCUMENT_START</span>')

                html += f"""
                <div style="padding: 10px 14px; background: var(--bg-card); border-left: 3px solid {s_color};
                            border-radius: 6px; display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <span style="font-size: 13px; font-weight: 600; color: var(--text-primary);">{domain}</span>
                        {run_at_badge}
                        <div style="font-size: 12px; color: var(--text-secondary); margin-top: 2px;">{desc} &middot; via {source}</div>
                    </div>
                    <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;
                                background: {s_color}; color: white; text-transform: uppercase; flex-shrink: 0;">{sev}</span>
                </div>
"""
            html += '            </div>\n'

        # Gmail surveillance modules
        if gmail_modules:
            html += f"""
            <div style="padding: 16px; background: rgba(239, 68, 68, 0.1); border: 1px solid rgba(239, 68, 68, 0.3);
                        border-radius: 8px;">
                <div style="font-size: 14px; font-weight: 700; color: #ef4444; margin-bottom: 10px;">
                    📧 Gmail Surveillance Module Detected
                </div>
"""
            for gm in gmail_modules:
                file_name = html_module.escape(self._file_display_name(gm.get('file', '')))
                indicators = gm.get('indicators', [])
                count = gm.get('indicator_count', 0)
                html += f"""
                <div style="margin-bottom: 10px;">
                    <div style="font-size: 13px; font-weight: 600; color: var(--text-primary);">
                        {file_name} &mdash; {count} surveillance indicators
                    </div>
                    <div style="display: flex; gap: 6px; flex-wrap: wrap; margin-top: 6px;">
"""
                for ind in indicators:
                    html += f"""
                        <span style="padding: 3px 10px; border-radius: 12px; font-size: 11px;
                                    background: rgba(239, 68, 68, 0.15); color: #fca5a5; border: 1px solid rgba(239, 68, 68, 0.25);">
                            {html_module.escape(ind)}
                        </span>
"""
                html += """
                    </div>
                </div>
"""
            html += '            </div>\n'

        html += """
        </div>
"""
        return html

    def _generate_campaign_fingerprint_section(self, campaign_fp):
        """Generate campaign fingerprint / known campaign match section (V3)"""
        matched = campaign_fp.get('matched_campaigns', [])
        domains = campaign_fp.get('domains', [])
        code_hashes = campaign_fp.get('code_hashes', [])
        infra_fp = campaign_fp.get('infra_fingerprint', '')
        cap_fp = campaign_fp.get('capability_fingerprint', '')

        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🧬</div>
                <div class="section-title">Campaign Fingerprint</div>
            </div>
"""
        # Matched campaigns
        for match in matched:
            name = html_module.escape(match.get('name', ''))
            conf = match.get('confidence', 0)
            desc = html_module.escape(match.get('description', ''))
            ref = match.get('reference', '')

            conf_pct = int(conf * 100)
            conf_color = '#ef4444' if conf >= 0.8 else '#f97316' if conf >= 0.6 else '#eab308'

            ref_html = ''
            if ref:
                ref_html = f'<a href="{html_module.escape(ref)}" style="color: #93c5fd; font-size: 12px; text-decoration: none;" target="_blank">Reference →</a>'

            html += f"""
            <div style="padding: 18px; background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.3);
                        border-radius: 8px; margin-bottom: 14px;">
                <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 8px;">
                    <div style="font-size: 16px; font-weight: 700; color: #fca5a5;">⚠️ {name}</div>
                    <div style="text-align: right;">
                        <div style="font-size: 24px; font-weight: 800; color: {conf_color};">{conf_pct}%</div>
                        <div style="font-size: 11px; color: var(--text-secondary);">match confidence</div>
                    </div>
                </div>
                <div style="font-size: 13px; color: var(--text-secondary); line-height: 1.6; margin-bottom: 8px;">{desc}</div>
                {ref_html}
            </div>
"""

        # Fingerprint details
        html += """
            <div style="display: flex; gap: 16px; flex-wrap: wrap; margin-top: 8px;">
"""
        if infra_fp:
            html += f"""
                <div style="padding: 12px 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 200px;">
                    <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">Infrastructure Fingerprint</div>
                    <div style="font-family: monospace; font-size: 13px; color: #93c5fd;">{html_module.escape(infra_fp)}</div>
                </div>
"""
        if cap_fp:
            html += f"""
                <div style="padding: 12px 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 200px;">
                    <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">Capability Fingerprint</div>
                    <div style="font-family: monospace; font-size: 13px; color: #c4b5fd;">{html_module.escape(cap_fp)}</div>
                </div>
"""
        if code_hashes:
            html += f"""
                <div style="padding: 12px 16px; background: var(--bg-card); border-radius: 8px; flex: 1; min-width: 200px;">
                    <div style="font-size: 11px; color: var(--text-secondary); margin-bottom: 4px;">Code Hashes</div>
                    <div style="font-size: 13px; color: var(--text-primary);">{len(code_hashes)} file(s) fingerprinted</div>
                </div>
"""
        html += '            </div>\n'

        # Domains
        if domains:
            html += """
            <div style="margin-top: 14px;">
                <div style="font-size: 12px; font-weight: 600; color: var(--text-secondary); margin-bottom: 8px;">External Domains in Fingerprint</div>
                <div style="display: flex; gap: 6px; flex-wrap: wrap;">
"""
            for d in domains[:20]:
                html += f"""
                    <span style="padding: 4px 10px; border-radius: 12px; font-size: 11px; font-family: monospace;
                                background: rgba(147, 197, 253, 0.1); border: 1px solid rgba(147, 197, 253, 0.25); color: #93c5fd;">
                        {html_module.escape(d)}
                    </span>
"""
            html += """
                </div>
            </div>
"""

        html += """
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
                    <div class="ioc-item">{results.get('extension_id', results.get('identifier', 'unknown'))}</div>
                </div>
            </div>
"""
        
        # File Hash IOCs (SHA-256) — VT file-hash lookup results
        file_hashes = results.get('file_hashes', [])
        vt_file_results = {r.get('hash', ''): r for r in results.get('virustotal_file_results', [])}
        if file_hashes:
            html += """
            <div class="ioc-category">
                <div class="ioc-category-title">🔐 File Hash IOCs (SHA-256)</div>
                <div class="ioc-list">
"""
            for fh in file_hashes:
                sha = fh.get('sha256', '')
                fname = html_module.escape(fh.get('filename', ''))
                vt = vt_file_results.get(sha)

                if vt and vt.get('threat_level') == 'MALICIOUS':
                    det = vt.get('stats', {}).get('malicious', 0)
                    vt_url = html_module.escape(vt.get('vt_url', ''))
                    html += f"""
                    <div class="ioc-item" style="border-left: 3px solid #dc2626; padding-left: 10px;">
                        <strong style="color:#dc2626;">⚠️ {fname}</strong>
                        <span style="background:#dc2626;color:#fff;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px;">
                            MALICIOUS — {det} vendor(s)
                        </span>
                        <br><code style="font-size:11px;word-break:break-all;">{sha}</code>
                        {'<br><a href="' + vt_url + '" target="_blank" style="color:#60a5fa;font-size:12px;">View on VirusTotal ↗</a>' if vt_url else ''}
                    </div>
"""
                elif vt and vt.get('threat_level') == 'SUSPICIOUS':
                    det_s = vt.get('stats', {}).get('suspicious', 0)
                    vt_url = html_module.escape(vt.get('vt_url', ''))
                    html += f"""
                    <div class="ioc-item" style="border-left: 3px solid #f59e0b; padding-left: 10px;">
                        <strong style="color:#f59e0b;">⚠ {fname}</strong>
                        <span style="background:#f59e0b;color:#000;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px;">
                            SUSPICIOUS — {det_s} flag(s)
                        </span>
                        <br><code style="font-size:11px;word-break:break-all;">{sha}</code>
                        {'<br><a href="' + vt_url + '" target="_blank" style="color:#60a5fa;font-size:12px;">View on VirusTotal ↗</a>' if vt_url else ''}
                    </div>
"""
                else:
                    html += f"""
                    <div class="ioc-item">
                        <strong>{fname}</strong>
                        <span style="background:#374151;color:#9ca3af;padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px;">
                            {'CLEAN' if (vt and vt.get('known')) else 'NOT IN VT'}
                        </span>
                        <br><code style="font-size:11px;word-break:break-all;">{sha}</code>
                    </div>
"""
            html += """
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

        # ── Top 5 Domains (unified, sorted by malicious + community score) ──
        # Build a unified domain map: domain → {malicious, community_neg, threat_level, vt_url, sources}
        domain_map = {}  # domain_str → info dict

        def _ensure(d, source_tag):
            d = d.strip().lower()
            if not d or d.startswith('<'):
                return
            if d not in domain_map:
                domain_map[d] = {'malicious': 0, 'community_neg': 0, 'threat_level': 'UNKNOWN', 'vt_url': '', 'sources': set()}
            domain_map[d]['sources'].add(source_tag)

        # VT domain results (richest data)
        for vt in results.get('virustotal_results', []):
            d = (vt.get('domain') or '').strip().lower()
            if not d:
                continue
            _ensure(d, 'VT')
            stats = vt.get('stats', {})
            votes = vt.get('votes', {})
            domain_map[d]['malicious'] = stats.get('malicious', 0)
            domain_map[d]['community_neg'] = votes.get('malicious', 0)
            domain_map[d]['threat_level'] = vt.get('threat_level', 'UNKNOWN')
            domain_map[d]['vt_url'] = vt.get('url', '')

        # AST exfil destinations
        ast_results = results.get('ast_results', {})
        for exfil in ast_results.get('data_exfiltration', []):
            dest = exfil.get('destination', '')
            if dest and not dest.startswith('<'):
                # Strip scheme to get host
                if '://' in dest:
                    try:
                        from urllib.parse import urlparse
                        dest = urlparse(dest).netloc
                    except Exception:
                        dest = dest.split('://')[1].split('/')[0].split(':')[0]
                _ensure(dest, 'Exfil')

        # Code / manifest URLs
        for item in results.get('urls_in_code', []):
            h = item.get('host')
            if h:
                _ensure(h, 'Code')
        for item in results.get('manifest_urls', []):
            h = item.get('host')
            if h:
                _ensure(h, 'Manifest')

        # Sort: primary = malicious vendor count (desc), secondary = community negative votes (desc)
        sorted_domains = sorted(
            domain_map.items(),
            key=lambda kv: (kv[1]['malicious'], kv[1]['community_neg']),
            reverse=True
        )
        top5 = sorted_domains[:5]

        if top5:
            html += """
            <div class="ioc-category">
                <div class="ioc-category-title">🌐 Top Domains (sorted by threat score)</div>
                <div class="ioc-list">
"""
            for domain, info in top5:
                escaped = html_module.escape(domain)
                mal = info['malicious']
                comm = info['community_neg']
                tl = info['threat_level']
                vt_url = html_module.escape(info.get('vt_url', ''))
                sources = ', '.join(sorted(info['sources']))

                # Badge color
                if tl == 'MALICIOUS':
                    badge_bg, badge_fg = '#dc2626', '#fff'
                    border = '#dc2626'
                elif tl == 'SUSPICIOUS':
                    badge_bg, badge_fg = '#f59e0b', '#000'
                    border = '#f59e0b'
                else:
                    badge_bg, badge_fg = '#374151', '#9ca3af'
                    border = '#4b5563'

                html += f"""
                    <div class="ioc-item" style="border-left: 3px solid {border}; padding-left: 10px; margin-bottom: 8px;">
                        <strong style="color:{badge_fg if tl == 'MALICIOUS' else '#e5e7eb'};">{escaped}</strong>
                        <span style="background:{badge_bg};color:{badge_fg};padding:2px 8px;border-radius:4px;font-size:11px;margin-left:8px;">
                            {tl}
                        </span>
                        <br>
                        <span style="font-size:12px;color:#9ca3af;">
                            🛡️ {mal} malicious vendor(s) &nbsp;|&nbsp; 👥 {comm} negative community vote(s)
                            &nbsp;|&nbsp; Source: {html_module.escape(sources)}
                        </span>
                        {'<br><a href="' + vt_url + '" target="_blank" style="color:#60a5fa;font-size:12px;">View on VirusTotal ↗</a>' if vt_url else ''}
                    </div>
"""
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
                Endpoints hit repeatedly by the extension. Regular intervals suggest periodic communication or telemetry collection.
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

        is_vscode = results.get('extension_type') == 'vscode'
        ext_id = results.get('identifier', results.get('extension_id', 'unknown'))
        permissions_total = results.get('permissions', {}).get('total', 0)

        if is_vscode:
            third_label = 'Publisher'
            third_value = results.get('publisher', 'Unknown')
        else:
            third_label = 'Manifest Version'
            third_value = results.get('manifest_version', 'Unknown')

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚙️</div>
                <div class="section-title">Technical Details</div>
            </div>
            <div class="detail-grid">
                <div class="detail-card">
                    <div class="detail-label">{'Identifier' if is_vscode else 'Extension ID'}</div>
                    <div class="detail-value" style="font-family: monospace; font-size: 13px;">{ext_id}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Version</div>
                    <div class="detail-value">{results.get('version', 'Unknown')}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">{third_label}</div>
                    <div class="detail-value">{third_value}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">{'API Usage' if is_vscode else 'Permissions'}</div>
                    <div class="detail-value">{permissions_total}</div>
                </div>
            </div>
            
            <div style="margin-top: 30px;">
                <h3 style="font-size: 18px; font-weight: 700; margin-bottom: 15px; color: var(--text-primary);">📋 Dangerous Permissions</h3>
"""
        
        # Show permission details
        permissions = results.get('permissions', {})
        perm_details = permissions.get('details', {})
        is_vscode = results.get('extension_type') == 'vscode'

        if permissions.get('high_risk'):
            html += '<div style="display: grid; gap: 12px;">'

            for perm in permissions['high_risk']:
                # VSCode returns dicts, Chrome returns strings
                if isinstance(perm, dict):
                    perm_name = perm.get('permission', 'Unknown')
                    perm_desc = perm.get('description', 'No description')
                    perm_risk = f"High-risk API usage ({perm.get('finding_count', 'N/A')} finding(s))" if perm.get('finding_count') else 'High-risk API'
                else:
                    perm_name = perm
                    details = perm_details.get(perm, {})
                    perm_desc = details.get('description', 'No description')
                    perm_risk = details.get('risk', 'Unknown risk')

                html += f"""
                <div style="background: rgba(239, 68, 68, 0.1); border-left: 4px solid #dc2626; padding: 15px; border-radius: 6px;">
                    <div style="font-weight: 700; font-size: 15px; color: #fca5a5; margin-bottom: 6px;">
                        🚩 {html_module.escape(str(perm_name))}
                    </div>
                    <div style="font-size: 14px; color: #f87171; margin-bottom: 4px;">
                        {html_module.escape(str(perm_desc))}
                    </div>
                    <div style="font-size: 13px; color: #fca5a5; font-weight: 600;">
                        {html_module.escape(str(perm_risk))}
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
        - Code evidence snippets for all findings (VSCode + Chrome)
        """

        patterns = results.get('malicious_patterns', [])
        vt_results = results.get('virustotal_results', [])
        is_vscode = results.get('extension_type') == 'vscode'

        # Create VT lookup map for cross-referencing
        vt_map = {}
        for vt in vt_results:
            if vt.get('known'):
                vt_map[vt.get('domain')] = vt

        # Deduplicate patterns:
        # - Chrome extensions: by destination URL (network-centric)
        # - VSCode extensions: by name+file+line (code-centric)
        seen_keys = set()
        unique_patterns = []

        for pattern in patterns:
            if is_vscode:
                key = f"{pattern.get('name', '')}|{pattern.get('file', '')}|{pattern.get('line', 0)}"
            else:
                key = pattern.get('destination', f"{pattern.get('name', '')}|{pattern.get('file', '')}|{pattern.get('line', 0)}")
            if key not in seen_keys:
                seen_keys.add(key)
                unique_patterns.append(pattern)

        critical_patterns = [p for p in unique_patterns if p.get('severity') == 'critical'][:10]
        high_patterns = [p for p in unique_patterns if p.get('severity') == 'high'][:10]
        medium_patterns = [p for p in unique_patterns if p.get('severity') == 'medium'][:5]

        html = """
        <div class="section">
            <div class="section-header">
                <div class="section-icon">⚠️</div>
                <div class="section-title">Threat Analysis</div>
            </div>
"""

        all_shown = critical_patterns + high_patterns + medium_patterns
        if not all_shown:
            html += '<div class="no-data">✅ No malicious code patterns detected</div>'
        else:
            for threat in all_shown:
                # Generate context analysis explaining HOW the function is used
                context_analysis = self._generate_context_analysis(threat)

                sev = threat.get('severity', 'medium')
                sev_icon = {'critical': '🔴', 'high': '🚨', 'medium': '⚠️', 'low': 'ℹ️'}.get(sev, '⚠️')
                sev_css = 'high' if sev in ('critical', 'high') else sev

                dup_count = threat.get('duplicate_count', 1)
                dup_badge = f' <span style="background:#334155;color:#94a3b8;padding:2px 6px;border-radius:10px;font-size:11px;margin-left:6px;">{dup_count}x</span>' if dup_count > 1 else ''
                html += f"""
            <div class="threat-item {sev_css}">
                <div class="threat-header">
                    <div class="threat-name">{sev_icon} {html_module.escape(threat.get('name', 'Unknown Threat'))}{dup_badge}</div>
                    <div class="threat-severity {sev_css}">{sev}</div>
                </div>
                <div class="threat-description">{html_module.escape(threat.get('description', 'No description available'))}</div>
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
                
                # Show technique/category and file location
                technique_label = threat.get('technique') or threat.get('category', 'Unknown')
                html += f"""
                <div style="font-size: 13px; color: #64748b; margin: 8px 0;">
                    <strong>Technique:</strong> {technique_label}
                </div>
"""
                
                # Add code snippet with context
                # Prefer context_with_lines (Chrome multi-line) over raw context/evidence
                context_code = threat.get('context_with_lines', '') or threat.get('context', '') or threat.get('evidence', '')
                if context_code and len(context_code) > 10:
                    file_name = self._file_display_name(threat.get('file', 'unknown.js'))
                    line_num = threat.get('line', 0)
                    start_line = threat.get('context_start_line', max(1, line_num))
                    matched_text = threat.get('matched_text', '')

                    # Add matched text indicator
                    if matched_text:
                        html += f'''
                <div style="margin: 10px 0; padding: 8px 12px; background: rgba(239, 68, 68, 0.1); border-left: 3px solid #ef4444; border-radius: 4px;">
                    <span style="color: #94a3b8; font-size: 12px;">Matched pattern:</span>
                    <code style="color: #f87171; background: rgba(0,0,0,0.2); padding: 2px 6px; border-radius: 3px; font-size: 12px; margin-left: 8px;">{html_module.escape(matched_text[:80])}{"..." if len(matched_text) > 80 else ""}</code>
                </div>
'''
                    # For single-line evidence (VSCode findings), render as inline code block
                    if '\n' not in context_code and not threat.get('context_with_lines'):
                        escaped_evidence = html_module.escape(context_code.strip())
                        html += f'''
                <div style="margin: 10px 0; padding: 12px 15px; background: #0f172a; border-radius: 8px; border: 1px solid #374151; overflow-x: auto;">
                    <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 8px;">
                        <span style="color: #6b7280; font-size: 11px; font-family: monospace;">{html_module.escape(file_name)}:{line_num}</span>
                    </div>
                    <pre style="margin: 0; font-family: 'Fira Code', 'Monaco', 'Consolas', monospace; font-size: 13px; line-height: 1.6;"><span style="color: #ef4444; min-width: 35px; display: inline-block; text-align: right; padding-right: 15px; user-select: none; border-right: 1px solid #374151; margin-right: 12px;">{line_num}</span><span style="color: #e2e8f0;">{self._apply_syntax_highlighting(escaped_evidence)}</span></pre>
                </div>
'''
                    else:
                        html += self._generate_code_snippet(context_code, file_name, line_num, start_line)
                
                html += f"""
                <div class="threat-location">📍 {self._file_display_name(threat.get('file', 'Unknown file'))} : Line {threat.get('line', 0)}</div>
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
                return "Data is being sent to an external server, and the code references cookies/sessions. This pattern is consistent with session token collection - verify whether the destination is a legitimate service."
            elif 'password' in context_lower or 'credential' in context_lower:
                return "Data is being sent to an external server with credential-related keywords present. Review what data is collected and whether the destination endpoint is a legitimate service."
            else:
                return "Data is being sent to an external server. Review what data is being collected and whether the destination is a legitimate service or an untrusted endpoint."

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

        # Fetch with credentials: 'include' (cookie/session replay) - e.g. inject script network-helper.js
        if 'credentials include' in name or 'cookie replay' in name:
            file_path = (threat.get('file') or '').lower()
            if 'network-helper' in file_path or 'inject' in file_path or 'content' in file_path:
                return "Inject or content script uses fetch with credentials: 'include' to replay network requests with the victim's cookies. This can hijack sessions or exfiltrate data as the user without their knowledge."
            return "Fetch is called with credentials: 'include', so requests are sent with the user's cookies. In content/inject scripts this replays the victim's requests and can be used for session hijacking or data theft."

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
                'Code injection': "This allows executing arbitrary code, which can perform any action including data theft, UI modification, or loading additional payloads.",
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
                <h3 style="margin-top: 20px; color: var(--color-critical);">⛔ CSP Manipulation Attack Detected</h3>
                <p style="margin: 10px 0; font-size: 13px;">Removes Content-Security-Policy headers to enable remote code injection. This is a <strong>high-risk technique</strong> associated with malicious extensions.</p>
"""
            for finding in csp_findings[:3]:
                # Safely get evidence
                evidence = finding.get('evidence', {})
                file_name = self._file_display_name(evidence.get('file', 'N/A')) if isinstance(evidence, dict) else 'N/A'

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
                file_name = self._file_display_name(evidence.get('file', 'N/A')) if isinstance(evidence, dict) else 'N/A'

                html += f"""
                <div class="finding-card" style="border-left: 4px solid var(--color-critical);">
                    <h4 style="margin: 0 0 8px 0; font-size: 14px;">{finding.get('type', 'Unknown')}</h4>
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Technique:</strong> {finding.get('technique', 'N/A')}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>Indicators:</strong> {indicators_str}</p>
                    <p style="margin: 5px 0; font-size: 12px;"><strong>File:</strong> <code>{file_name}</code></p>
                </div>
"""

        # WebSocket suspicious connections
        ws_findings = advanced_data.get('websocket_c2', [])
        if ws_findings:
            html += """
                <h3 style="margin-top: 20px; color: var(--color-high);">📡 Suspicious WebSocket Connections</h3>
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
                file_name = self._file_display_name(evidence.get('file', 'N/A')) if isinstance(evidence, dict) else 'N/A'

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
                <div class="section-title">Prior Analysis History</div>
            </div>
            <div class="subsection">
                <div class="alert alert-{'critical' if extension_ioc.get('risk_score', 0) >= 7 else 'high' if extension_ioc.get('risk_score', 0) >= 4 else 'medium'}">
                    <div class="alert-icon">📋</div>
                    <div>
                        <strong>NOTE:</strong> This extension was previously analyzed by this tool.<br>
                        <strong>First Analyzed:</strong> {extension_ioc.get('first_analyzed', 'Unknown')}<br>
                        <strong>Previous Risk Score:</strong> {extension_ioc.get('risk_score', 0):.1f}/10<br>
                        <span style="font-size: 11px; color: var(--text-secondary);">This is a local analysis record, not an external threat intelligence source.</span>
                    </div>
                </div>

                <h3 style="margin-top: 20px;">Previously Flagged Domains</h3>
                <div class="finding-card">
                    <p style="margin: 5px 0; font-size: 13px;"><strong>Flagged Domains:</strong> {len(extension_ioc.get('malicious_domains', []))}</p>
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
                            <span style="color: #f87171;">⚠</span> Threat Analysis Report
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
                        <div style="font-size: 11px; color: #f87171; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 10px; font-weight: 600;">Remote Infrastructure (IOCs)</div>
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
                from urllib.parse import urlparse
                for article in source_articles:
                    url = article.get('url', '#')
                    title = article.get('title', url)
                    # Some entries (e.g. cache-based ones) may not include an explicit 'source'
                    source_label = article.get('source')
                    if not source_label:
                        try:
                            domain = urlparse(url).netloc.replace('www.', '')
                            source_label = domain or 'Unknown'
                        except Exception:
                            source_label = 'Unknown'
                    html += f"""
                <div style="padding: 12px; margin: 10px 0; background: #f8fafc; border-radius: 6px; border: 1px solid #e2e8f0;">
                    <strong style="font-size: 14px;">
                        <a href="{url}" target="_blank" style="color: #2563eb; text-decoration: none;">
                            {title}
                        </a>
                    </strong>
                    <p style="margin: 5px 0 0 0; font-size: 12px; color: #64748b;">Source: {source_label}</p>
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
                f"Consider blocking extension ID {results.get('extension_id', results.get('identifier', 'unknown'))} pending further investigation",
                "Review extension across deployed systems",
                "Monitor network logs for suspicious activity",
                "Check browser history for accessed domains"
            ]
            if has_credential_theft:
                recs.append("<strong>If credential access verified:</strong> Consider password resets for affected users")
            recs.append("Consider reporting to extension marketplace if suspicious behavior is verified")

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
                recs.append("<strong>If credential access verified:</strong> Evaluate need for password resets")

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
                f"<strong>Investigate:</strong> Extension behavior matches {campaign.get('name', 'known suspicious')} campaign patterns",
                "Manual verification recommended to confirm attribution",
                f"Consider blocking extension ID {results.get('extension_id', results.get('identifier', 'unknown'))} pending review",
                "Review systems where extension is deployed",
                "Document findings for security team",
                "Consider reporting if suspicious behavior is verified"
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
    
    # ══════════════════════════════════════════════════════════════════════
    # VSCode Extension Report Sections
    # ══════════════════════════════════════════════════════════════════════

    def _generate_vscode_overview_section(self, results):
        """Generate VSCode extension overview with marketplace metadata"""
        metadata = results.get('store_metadata', {})
        meta_risk = results.get('metadata_risk', {})

        publisher = results.get('publisher', 'Unknown')
        verified = metadata.get('publisher_verified', False)
        installs = metadata.get('install_count', 0)
        rating = metadata.get('rating_value', 0)
        rating_count = metadata.get('rating_count', 0)
        description = results.get('description', '')

        activation_events = meta_risk.get('activation_events', [])
        contributes = meta_risk.get('contributes', [])

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">📦</div>
                <div class="section-title">VSCode Extension Overview</div>
            </div>
            <div class="detail-grid">
                <div class="detail-card">
                    <div class="detail-label">Publisher</div>
                    <div class="detail-value">{html_module.escape(publisher)} {'✅' if verified else '⚠️ Unverified'}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Installs</div>
                    <div class="detail-value">{installs:,}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Rating</div>
                    <div class="detail-value">{'⭐ ' + str(rating) + ' (' + str(rating_count) + ')' if rating else 'N/A'}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Risk Score</div>
                    <div class="detail-value" style="color: {self._get_risk_color(results.get('risk_level', 'UNKNOWN'))};">
                        {results.get('risk_score', 0):.1f}/10
                    </div>
                </div>
            </div>
"""

        if description:
            html += f"""
            <div style="margin-top: 15px; padding: 12px 16px; background: var(--bg-card); border-radius: 8px; color: var(--text-secondary); font-size: 14px;">
                {html_module.escape(description[:300])}
            </div>
"""

        # Metadata findings
        findings = meta_risk.get('findings', [])
        if findings:
            html += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 16px; color: var(--text-primary); margin-bottom: 12px;">Metadata Risk Signals</h3>
                <div style="display: grid; gap: 8px;">
"""
            for finding in findings:
                sev = finding.get('severity', 'low')
                sev_color = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#22c55e'}.get(sev, '#94a3b8')
                html += f"""
                    <div style="display: flex; align-items: center; gap: 10px; padding: 10px 14px; background: var(--bg-card); border-left: 3px solid {sev_color}; border-radius: 6px;">
                        <span style="background: {sev_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; text-transform: uppercase;">{sev}</span>
                        <span style="color: var(--text-primary); font-size: 13px;">{html_module.escape(finding.get('detail', ''))}</span>
                    </div>
"""
            html += "</div></div>"

        # Activation events
        if activation_events:
            html += f"""
            <div style="margin-top: 15px; padding: 12px 16px; background: var(--bg-card); border-radius: 8px;">
                <div style="font-size: 12px; color: var(--text-secondary); margin-bottom: 6px;">Activation Events</div>
                <div style="font-family: monospace; font-size: 13px; color: var(--text-primary);">
                    {', '.join(html_module.escape(e) for e in activation_events[:10])}
                    {'...' if len(activation_events) > 10 else ''}
                </div>
            </div>
"""

        html += "</div>"
        return html

    def _generate_vscode_supply_chain_section(self, results):
        """Generate supply chain analysis section for VSCode extensions"""
        supply = results.get('supply_chain', {})
        findings = supply.get('findings', [])

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔗</div>
                <div class="section-title">Supply Chain Analysis</div>
            </div>
            <div class="detail-grid">
                <div class="detail-card">
                    <div class="detail-label">Dependencies</div>
                    <div class="detail-value">{supply.get('dependency_count', 0)}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Dev Dependencies</div>
                    <div class="detail-value">{supply.get('dev_dependency_count', 0)}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Bundled node_modules</div>
                    <div class="detail-value">{'Yes' if supply.get('has_node_modules') else 'No'}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Supply Chain Risk</div>
                    <div class="detail-value" style="color: {'#ef4444' if supply.get('risk_score', 0) >= 5 else '#eab308' if supply.get('risk_score', 0) >= 2 else '#22c55e'};">
                        {supply.get('risk_score', 0)}/10
                    </div>
                </div>
            </div>
"""

        if findings:
            # Filter out info-level for main display
            significant = [f for f in findings if f.get('severity') != 'info']
            if significant:
                html += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 16px; color: var(--text-primary); margin-bottom: 12px;">Supply Chain Findings</h3>
                <div style="display: grid; gap: 8px;">
"""
                for finding in significant:
                    sev = finding.get('severity', 'low')
                    sev_color = {'critical': '#ef4444', 'high': '#f97316', 'medium': '#eab308', 'low': '#22c55e'}.get(sev, '#94a3b8')
                    html += f"""
                    <div style="background: var(--bg-card); border-left: 3px solid {sev_color}; padding: 12px 16px; border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-weight: 600; color: var(--text-primary); font-size: 14px;">{html_module.escape(finding.get('type', '').replace('_', ' ').title())}</span>
                            <span style="background: {sev_color}; color: white; padding: 2px 8px; border-radius: 3px; font-size: 10px; font-weight: 700; text-transform: uppercase;">{sev}</span>
                        </div>
                        <div style="color: var(--text-secondary); font-size: 13px;">{html_module.escape(finding.get('detail', ''))}</div>
                    </div>
"""
                html += "</div></div>"

            # Show info-level findings in compact form
            info_findings = [f for f in findings if f.get('severity') == 'info']
            if info_findings:
                html += '<div style="margin-top: 12px;">'
                for finding in info_findings:
                    html += f'<div style="padding: 8px 14px; color: var(--text-secondary); font-size: 13px;">ℹ️ {html_module.escape(finding.get("detail", ""))}</div>'
                html += '</div>'
        else:
            html += '<div class="no-data" style="margin-top: 15px;">✅ No supply chain issues detected</div>'

        html += "</div>"
        return html

    def _generate_vscode_code_analysis_section(self, results):
        """Generate code analysis section for VSCode extensions"""
        code = results.get('code_analysis', {})
        findings_by_cat = code.get('findings_by_category', {})
        findings_by_sev = code.get('findings_by_severity', {})
        module_usage = results.get('module_usage', {})
        breakdown = results.get('risk_breakdown', {})

        html = f"""
        <div class="section">
            <div class="section-header">
                <div class="section-icon">🔬</div>
                <div class="section-title">Deep Code Analysis</div>
            </div>
            <div class="detail-grid">
                <div class="detail-card">
                    <div class="detail-label">Files Scanned</div>
                    <div class="detail-value">{code.get('files_scanned', 0)}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Critical Findings</div>
                    <div class="detail-value" style="color: #ef4444;">{findings_by_sev.get('critical', 0)}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">High Findings</div>
                    <div class="detail-value" style="color: #f97316;">{findings_by_sev.get('high', 0)}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-label">Code Risk</div>
                    <div class="detail-value">{breakdown.get('code_analysis', 0)}/4</div>
                </div>
            </div>
"""

        # Sensitive module usage
        if module_usage:
            html += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 16px; color: var(--text-primary); margin-bottom: 12px;">Sensitive Module Usage</h3>
                <div style="display: grid; gap: 8px;">
"""
            category_icons = {
                'file_access': '📁',
                'network': '🌐',
                'process_execution': '⚡',
                'os_info': '💻',
                'crypto': '🔐',
                'vm': '🖥️',
            }
            category_risk = {
                'process_execution': '#ef4444',
                'network': '#f97316',
                'file_access': '#eab308',
                'vm': '#ef4444',
                'os_info': '#22c55e',
                'crypto': '#3b82f6',
            }
            for category, usages in module_usage.items():
                modules = sorted(set(u['module'] for u in usages))
                files = sorted(set(u['file'] for u in usages))
                icon = category_icons.get(category, '📦')
                color = category_risk.get(category, '#94a3b8')
                html += f"""
                    <div style="background: var(--bg-card); border-left: 3px solid {color}; padding: 12px 16px; border-radius: 6px;">
                        <div style="font-weight: 600; color: var(--text-primary); font-size: 14px; margin-bottom: 4px;">
                            {icon} {category.replace('_', ' ').title()}
                        </div>
                        <div style="font-family: monospace; font-size: 12px; color: {color}; margin-bottom: 4px;">
                            {', '.join(html_module.escape(m) for m in modules)}
                        </div>
                        <div style="font-size: 11px; color: var(--text-secondary);">
                            Used in: {', '.join(html_module.escape(f) for f in files[:5])}{'...' if len(files) > 5 else ''}
                        </div>
                    </div>
"""
            html += "</div></div>"

        # Finding categories breakdown
        priority_categories = [
            ('behavioral_correlation', 'Behavioral Correlation', '#ef4444'),
            ('command_injection', 'Command Injection', '#ef4444'),
            ('credential_theft', 'Credential Theft', '#ef4444'),
            ('code_execution', 'Unsafe Code Execution', '#f97316'),
            ('terminal_hijack', 'Terminal Hijacking', '#f97316'),
            ('keylogging', 'Keystroke Monitoring', '#f97316'),
            ('network_exfil', 'Network Exfiltration', '#f97316'),
            ('obfuscation', 'Code Obfuscation', '#eab308'),
            ('weak_crypto', 'Weak Cryptography', '#eab308'),
            ('prototype_pollution', 'Prototype Pollution', '#eab308'),
            ('webview_risk', 'Webview Security', '#eab308'),
            ('settings_manipulation', 'Settings Manipulation', '#eab308'),
            ('extension_hijack', 'Extension Hijacking', '#eab308'),
            ('data_access', 'Data Access', '#3b82f6'),
            ('reconnaissance', 'Reconnaissance', '#3b82f6'),
        ]

        active_categories = [(cat, label, color) for cat, label, color in priority_categories if cat in findings_by_cat]

        if active_categories:
            html += """
            <div style="margin-top: 20px;">
                <h3 style="font-size: 16px; color: var(--text-primary); margin-bottom: 12px;">Finding Categories</h3>
                <div style="display: grid; gap: 8px;">
"""
            for cat, label, color in active_categories:
                cat_findings = findings_by_cat[cat]
                count = len(cat_findings)
                # Show first finding as example
                example = cat_findings[0]
                html += f"""
                    <div style="background: var(--bg-card); border-left: 3px solid {color}; padding: 12px 16px; border-radius: 6px;">
                        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                            <span style="font-weight: 600; color: var(--text-primary); font-size: 14px;">{label}</span>
                            <span style="background: {color}; color: white; padding: 2px 10px; border-radius: 12px; font-size: 11px; font-weight: 700;">{count}</span>
                        </div>
                        <div style="font-size: 13px; color: var(--text-secondary); margin-bottom: 4px;">
                            {html_module.escape(example.get('description', ''))}
                        </div>
                        <div style="font-family: monospace; font-size: 11px; color: var(--text-secondary);">
                            {html_module.escape(self._file_display_name(example.get('file', '')))}:{example.get('line', 0)}
                        </div>
                    </div>
"""
            html += "</div></div>"

        html += "</div>"
        return html

    def save_professional_report(self, results, output_dir='reports'):
        """Save professional report"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)

        html = self.generate_threat_analysis_report(results)

        if results.get('extension_type') == 'vscode':
            import re as _re
            identifier = results.get('identifier', 'unknown')
            safe_name = _re.sub(r'[^\w\-.]', '_', identifier)
            html_path = output_dir / f"vscode_{safe_name}_threat_analysis_report.html"
        else:
            extension_id = results.get('extension_id', 'unknown')
            html_path = output_dir / f"{extension_id}_threat_analysis_report.html"

        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)

        print(f"[+] Professional threat intel report saved: {html_path}")
        return html_path