"""
Executive Security Report Generator
Creates concise, actionable reports for CISOs and security analysts
Enhanced with campaign attribution and settings override detection
"""

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

class ExecutiveReportGenerator:
    """Generates executive-focused PDF reports from analysis results"""
    
    def __init__(self):
        self.report_dir = Path("reports")
        self.report_dir.mkdir(exist_ok=True)
    
    def generate_executive_report(self, results):
        """Generate executive-focused HTML report"""
        
        extension_name = results.get('name', 'Unknown Extension')
        extension_id = results.get('extension_id', 'unknown')
        risk_score = results.get('risk_score', 0)
        risk_level = results.get('risk_level', 'UNKNOWN')
        campaign = results.get('campaign_attribution')
        
        # Risk color coding
        risk_colors = {
            'CRITICAL': '#dc2626',
            'HIGH': '#ea580c',
            'MEDIUM': '#f59e0b',
            'LOW': '#84cc16',
            'MINIMAL': '#22c55e'
        }
        risk_color = risk_colors.get(risk_level, '#6b7280')
        
        # Extract key findings
        permissions = results.get('permissions', {})
        patterns = results.get('malicious_patterns', [])
        external = results.get('external_scripts', [])
        obfuscation = results.get('obfuscation_indicators', {})
        settings_overrides = results.get('settings_overrides', {})
        
        # Get unique domains
        domains = self._extract_domains(external)
        
        # Build concise HTML
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Assessment - {extension_name}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #1f2937;
            background: #f9fafb;
            padding: 20px;
        }}
        
        .container {{
            max-width: 850px;
            margin: 0 auto;
            background: white;
            box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
        }}
        
        .header {{
            background: linear-gradient(135deg, #1e293b 0%, #334155 100%);
            color: white;
            padding: 30px 40px;
        }}
        
        .header h1 {{
            font-size: 24px;
            margin-bottom: 8px;
            font-weight: 600;
        }}
        
        .header .subtitle {{
            opacity: 0.9;
            font-size: 14px;
        }}
        
        .campaign-alert {{
            background: #7f1d1d;
            color: white;
            padding: 20px 40px;
            border-left: 6px solid #991b1b;
        }}
        
        .campaign-alert h2 {{
            font-size: 18px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .campaign-alert p {{
            margin-bottom: 8px;
            font-size: 14px;
        }}
        
        .campaign-alert .reference {{
            margin-top: 10px;
            padding-top: 10px;
            border-top: 1px solid rgba(255,255,255,0.2);
            font-size: 12px;
        }}
        
        .campaign-alert .reference a {{
            color: #fca5a5;
            text-decoration: none;
        }}
        
        .verdict {{
            background: {risk_color};
            color: white;
            padding: 25px 40px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        
        .verdict-left {{
            flex: 1;
        }}
        
        .verdict-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 5px;
        }}
        
        .verdict-subtitle {{
            font-size: 14px;
            opacity: 0.95;
        }}
        
        .risk-badge {{
            background: rgba(255, 255, 255, 0.2);
            padding: 15px 30px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .risk-score {{
            font-size: 42px;
            font-weight: bold;
            line-height: 1;
        }}
        
        .risk-label {{
            font-size: 13px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
            opacity: 0.95;
        }}
        
        .content {{
            padding: 40px;
        }}
        
        .summary {{
            background: #fef3c7;
            border-left: 4px solid #f59e0b;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 4px;
        }}
        
        .summary.critical {{
            background: #fee2e2;
            border-left-color: #dc2626;
        }}
        
        .summary.critical h2 {{
            color: #991b1b;
        }}
        
        .summary.critical li {{
            color: #7f1d1d;
        }}
        
        .summary h2 {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #92400e;
        }}
        
        .summary ul {{
            margin-left: 20px;
        }}
        
        .summary li {{
            margin-bottom: 8px;
            color: #78350f;
        }}
        
        .section {{
            margin-bottom: 35px;
        }}
        
        .section-title {{
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #1e293b;
            display: flex;
            align-items: center;
        }}
        
        .section-title::before {{
            content: '';
            display: inline-block;
            width: 4px;
            height: 20px;
            background: #3b82f6;
            margin-right: 10px;
        }}
        
        .info-box {{
            background: #f8fafc;
            border: 1px solid #e2e8f0;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 15px;
        }}
        
        .info-row {{
            display: flex;
            padding: 8px 0;
            border-bottom: 1px solid #e2e8f0;
        }}
        
        .info-row:last-child {{
            border-bottom: none;
        }}
        
        .info-label {{
            font-weight: 600;
            min-width: 180px;
            color: #475569;
        }}
        
        .info-value {{
            color: #1e293b;
            font-family: monospace;
            font-size: 13px;
            word-break: break-all;
        }}
        
        .hijacking-alert {{
            background: #fef2f2;
            border: 2px solid #dc2626;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        
        .hijacking-alert h3 {{
            color: #991b1b;
            font-size: 16px;
            margin-bottom: 12px;
            font-weight: 600;
        }}
        
        .hijacking-alert .detail {{
            margin-bottom: 8px;
            padding: 10px;
            background: white;
            border-radius: 4px;
            font-size: 14px;
        }}
        
        .hijacking-alert .detail strong {{
            color: #7f1d1d;
        }}
        
        .threat-list {{
            list-style: none;
        }}
        
        .threat-item {{
            background: white;
            border: 1px solid #e5e7eb;
            padding: 15px;
            margin-bottom: 10px;
            border-radius: 6px;
            border-left: 4px solid #ef4444;
        }}
        
        .threat-item.medium {{
            border-left-color: #f59e0b;
        }}
        
        .threat-item.low {{
            border-left-color: #6b7280;
        }}
        
        .threat-name {{
            font-weight: 600;
            color: #1f2937;
            margin-bottom: 5px;
        }}
        
        .threat-desc {{
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 8px;
        }}
        
        .threat-location {{
            font-size: 13px;
            color: #9ca3af;
            font-family: monospace;
        }}
        
        .domain-list {{
            background: #fef2f2;
            border: 1px solid #fecaca;
            padding: 20px;
            border-radius: 6px;
        }}
        
        .domain-item {{
            padding: 10px;
            background: white;
            margin-bottom: 8px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 14px;
            border-left: 3px solid #dc2626;
        }}
        
        .recommendations {{
            background: #ecfdf5;
            border-left: 4px solid #10b981;
            padding: 20px;
            border-radius: 4px;
        }}
        
        .recommendations.critical {{
            background: #fee2e2;
            border-left-color: #dc2626;
        }}
        
        .recommendations.critical h3 {{
            color: #991b1b;
        }}
        
        .recommendations.critical li {{
            color: #7f1d1d;
        }}
        
        .recommendations h3 {{
            font-size: 16px;
            font-weight: 600;
            margin-bottom: 12px;
            color: #065f46;
        }}
        
        .recommendations ul {{
            margin-left: 20px;
        }}
        
        .recommendations li {{
            margin-bottom: 8px;
            color: #047857;
        }}
        
        .footer {{
            background: #f8fafc;
            padding: 20px 40px;
            text-align: center;
            color: #64748b;
            font-size: 12px;
            border-top: 1px solid #e2e8f0;
        }}
        
        .no-findings {{
            text-align: center;
            padding: 30px;
            color: #10b981;
            font-weight: 500;
        }}
        
        @media print {{
            body {{ padding: 0; }}
            .container {{ box-shadow: none; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <h1>🛡️ Chrome Extension Security Assessment</h1>
            <div class="subtitle">
                Analysis Date: {datetime.now().strftime('%B %d, %Y')} | Extension: {extension_name}
            </div>
        </div>
"""
        
        # Campaign Alert (if detected)
        if campaign:
            html += f"""
        <!-- Campaign Alert -->
        <div class="campaign-alert">
            <h2>🚨 MALICIOUS CAMPAIGN DETECTED: {campaign['name']}</h2>
            <p><strong>Confidence:</strong> {campaign['confidence']} | <strong>Severity:</strong> {campaign['severity']}</p>
            <p><strong>Description:</strong> {campaign.get('description', 'N/A')}</p>
            <p><strong>Indicators:</strong></p>
            <ul style="margin-left: 20px; margin-top: 5px;">
"""
            for indicator in campaign.get('indicators', []):
                html += f"<li>{indicator}</li>"
            
            html += "</ul>"
            
            if campaign.get('reference'):
                html += f"""
            <div class="reference">
                <strong>Reference:</strong> <a href="{campaign['reference']}" target="_blank">{campaign['reference']}</a>
            </div>
"""
            html += "</div>"
        
        # Verdict Banner
        verdict_text = '⛔ BLOCK IMMEDIATELY - Known malicious campaign' if campaign else \
                      '⛔ Block immediately - High security risk detected' if risk_level in ['CRITICAL', 'HIGH'] else \
                      '⚠️ Review required before deployment' if risk_level == 'MEDIUM' else \
                      '✓ Low risk detected - Monitor for updates'
        
        html += f"""
        <!-- Verdict Banner -->
        <div class="verdict">
            <div class="verdict-left">
                <div class="verdict-title">Security Verdict: {risk_level} RISK</div>
                <div class="verdict-subtitle">{verdict_text}</div>
            </div>
            <div class="risk-badge">
                <div class="risk-score">{risk_score:.1f}</div>
                <div class="risk-label">Risk Score</div>
            </div>
        </div>
        
        <!-- Content -->
        <div class="content">
"""
        
        # Executive Summary
        html += self._generate_executive_summary(results, risk_level, domains, campaign, settings_overrides)
        
        # Settings Overrides (CRITICAL SECTION)
        if settings_overrides.get('has_overrides'):
            html += self._generate_settings_override_section(settings_overrides)
        
        # Extension Details
        html += f"""
            <!-- Extension Information -->
            <div class="section">
                <h2 class="section-title">Extension Details</h2>
                <div class="info-box">
                    <div class="info-row">
                        <div class="info-label">Extension ID:</div>
                        <div class="info-value">{extension_id}</div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Name:</div>
                        <div class="info-value">{extension_name}</div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Version:</div>
                        <div class="info-value">{results.get('version', 'Unknown')}</div>
                    </div>
                    <div class="info-row">
                        <div class="info-label">Manifest Version:</div>
                        <div class="info-value">{results.get('manifest_version', 'Unknown')}</div>
                    </div>
                </div>
            </div>
"""
        
        # Key Threats Found
        html += self._generate_key_threats(patterns, permissions)
        
        # Suspicious Domains
        html += self._generate_domain_section(domains)
        
        # Dangerous Permissions
        if permissions.get('high_risk'):
            html += self._generate_permissions_section(permissions)
        
        # Recommendations
        html += self._generate_recommendations(risk_level, permissions, patterns, domains, campaign, settings_overrides)
        
        html += """
        </div>
        
        <!-- Footer -->
        <div class="footer">
            <p><strong>Chrome Extension Security Analyzer (Enhanced)</strong> | Automated Analysis Report</p>
            <p style="margin-top: 5px;">Campaign detection based on DarkSpectre/ZoomStealer research by KOI Security</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html
    
    def _generate_executive_summary(self, results, risk_level, domains, campaign, settings_overrides):
        """Generate executive summary box"""
        
        permissions = results.get('permissions', {})
        patterns = results.get('malicious_patterns', [])
        
        summary_points = []
        
        # Campaign membership (HIGHEST PRIORITY)
        if campaign:
            summary_points.append(f"<strong>Part of {campaign['name']} malicious campaign</strong> - {campaign.get('description', '')}")
        
        # Settings overrides (CRITICAL)
        if settings_overrides.get('search_hijacking'):
            search = settings_overrides['search_hijacking']
            if search.get('has_affiliate_params'):
                summary_points.append(f"<strong>Search engine hijacking with affiliate fraud</strong> detected")
            else:
                summary_points.append(f"<strong>Search engine hijacking</strong> detected")
        
        if settings_overrides.get('homepage_hijacking'):
            summary_points.append(f"<strong>Homepage override</strong> detected")
        
        # High-risk permissions
        if permissions.get('high_risk'):
            top_perms = ', '.join(permissions['high_risk'][:3])
            summary_points.append(f"<strong>{len(permissions['high_risk'])} dangerous permissions</strong> ({top_perms})")
        
        # Critical patterns
        high_patterns = [p for p in patterns if p['severity'] == 'high']
        if high_patterns:
            summary_points.append(f"<strong>{len(high_patterns)} critical security issues</strong> (data exfiltration, dynamic code execution)")
        
        # External connections
        if len(domains) > 0:
            summary_points.append(f"<strong>Connects to {len(domains)} external domain(s)</strong> - potential data leakage")
        
        if not summary_points:
            return '<div class="no-findings">✅ No significant security threats detected</div>'
        
        summary_class = 'critical' if campaign or risk_level in ['CRITICAL', 'HIGH'] else ''
        
        html = f"""
            <div class="summary {summary_class}">
                <h2>⚠️ Executive Summary</h2>
                <ul>
"""
        for point in summary_points:
            html += f"<li>{point}</li>"
        
        html += """
                </ul>
            </div>
"""
        return html
    
    def _generate_settings_override_section(self, settings_overrides):
        """Generate settings override section (CRITICAL)"""
        
        html = """
            <div class="section">
                <h2 class="section-title">⚠️ Browser Settings Hijacking</h2>
                <div class="hijacking-alert">
"""
        
        if settings_overrides.get('search_hijacking'):
            search = settings_overrides['search_hijacking']
            html += f"""
                    <h3>🚨 Search Engine Hijacking</h3>
                    <div class="detail">
                        <strong>Redirects to:</strong> {search['search_url']}
                    </div>
"""
            if search.get('has_affiliate_params'):
                html += f"""
                    <div class="detail">
                        <strong>Affiliate Parameters:</strong> {', '.join(search['affiliate_params'])}
                        <br><em>This extension generates revenue by redirecting your searches.</em>
                    </div>
"""
        
        if settings_overrides.get('homepage_hijacking'):
            homepage = settings_overrides['homepage_hijacking']
            html += f"""
                    <h3>🚨 Homepage Override</h3>
                    <div class="detail">
                        <strong>Sets homepage to:</strong> {homepage['url']}
                    </div>
"""
        
        if settings_overrides.get('startup_hijacking'):
            startup = settings_overrides['startup_hijacking']
            html += f"""
                    <h3>🚨 Startup Pages Override</h3>
                    <div class="detail">
                        <strong>Opens {len(startup['urls'])} page(s) on startup</strong>
                    </div>
"""
        
        if settings_overrides.get('newtab_hijacking'):
            newtab = settings_overrides['newtab_hijacking']
            html += f"""
                    <h3>⚠️ New Tab Override</h3>
                    <div class="detail">
                        <strong>Overrides new tab page:</strong> {newtab['url']}
                    </div>
"""
        
        html += """
                </div>
            </div>
"""
        return html
    
    def _generate_key_threats(self, patterns, permissions):
        """Generate key threats section - Top 8 only"""
        
        html = """
            <div class="section">
                <h2 class="section-title">Key Security Threats</h2>
"""
        
        # Show top critical patterns only
        high_patterns = [p for p in patterns if p['severity'] == 'high'][:5]
        medium_patterns = [p for p in patterns if p['severity'] == 'medium'][:3]
        
        all_threats = high_patterns + medium_patterns
        
        if not all_threats:
            html += '<div class="no-findings">✅ No malicious code patterns detected</div>'
        else:
            html += '<ul class="threat-list">'
            for threat in all_threats:
                html += f"""
                <li class="threat-item {threat['severity']}">
                    <div class="threat-name">🚨 {threat['name']}</div>
                    <div class="threat-desc">{threat['description']}</div>
                    <div class="threat-location">📍 {threat['file']} (Line {threat['line']})</div>
                </li>
"""
            
            # Show count of remaining threats
            remaining_high = len([p for p in patterns if p['severity'] == 'high']) - 5
            remaining_medium = len([p for p in patterns if p['severity'] == 'medium']) - 3
            
            if remaining_high > 0 or remaining_medium > 0:
                html += f'<p style="margin-top: 15px; color: #6b7280; text-align: center;">'
                if remaining_high > 0:
                    html += f'+ {remaining_high} more high severity threats  '
                if remaining_medium > 0:
                    html += f'+ {remaining_medium} more medium severity threats'
                html += '</p>'
            
            html += '</ul>'
        
        html += '</div>'
        return html
    
    def _generate_domain_section(self, domains):
        """Generate suspicious domains section"""
        
        html = """
            <div class="section">
                <h2 class="section-title">Suspicious Network Connections</h2>
"""
        
        if not domains:
            html += '<div class="no-findings">✅ No external connections detected</div>'
        else:
            html += f"""
                <div class="domain-list">
                    <p style="margin-bottom: 15px; color: #991b1b; font-weight: 500;">
                        ⚠️ This extension connects to {len(domains)} external domain(s):
                    </p>
"""
            for domain in sorted(domains)[:15]:  # Top 15 domains
                html += f'<div class="domain-item">🌐 {domain}</div>'
            
            if len(domains) > 15:
                html += f'<p style="margin-top: 10px; color: #991b1b; font-weight: 500;">... and {len(domains) - 15} more domains</p>'
            
            html += '</div>'
        
        html += '</div>'
        return html
    
    def _generate_permissions_section(self, permissions):
        """Generate dangerous permissions section"""
        
        html = """
            <div class="section">
                <h2 class="section-title">Dangerous Permissions</h2>
"""
        
        if not permissions.get('high_risk'):
            html += '<div class="no-findings">✅ No high-risk permissions detected</div>'
        else:
            html += '<div class="info-box">'
            for perm in permissions['high_risk']:
                html += f"""
                <div class="info-row">
                    <div class="info-label">🚩 {perm}</div>
                    <div class="info-value">{self._get_permission_description(perm)}</div>
                </div>
"""
            html += '</div>'
        
        html += '</div>'
        return html
    
    def _get_permission_description(self, permission):
        """Get human-readable description of permission"""
        descriptions = {
            'debugger': 'Can debug and inspect other extensions',
            '<all_urls>': 'Access to ALL websites',
            'webRequest': 'Can intercept network requests',
            'webRequestBlocking': 'Can block/modify network traffic',
            'proxy': 'Can change proxy settings',
            'cookies': 'Can access cookies from all sites',
            'history': 'Can read browsing history',
            'management': 'Can manage other extensions',
            'nativeMessaging': 'Can communicate with native apps',
            'desktopCapture': 'Can capture screen content',
            'tabCapture': 'Can capture tab content',
            'clipboardRead': 'Can read clipboard data',
        }
        return descriptions.get(permission, 'Elevated permission')
    
    def _generate_recommendations(self, risk_level, permissions, patterns, domains, campaign, settings_overrides):
        """Generate action recommendations"""
        
        rec_class = 'critical' if campaign or risk_level in ['CRITICAL', 'HIGH'] else ''
        
        html = f"""
            <div class="section">
                <h2 class="section-title">Recommended Actions</h2>
                <div class="recommendations {rec_class}">
                    <h3>🎯 Security Team Actions:</h3>
                    <ul>
"""
        
        if campaign:
            html += f"""
                        <li><strong>CRITICAL: Known malicious campaign detected ({campaign['name']})</strong></li>
                        <li>IMMEDIATE ACTION: Block this extension across ALL devices</li>
                        <li>Remove from approved extension lists immediately</li>
                        <li>Notify all users who have this extension installed</li>
                        <li>Investigate if sensitive data (searches, credentials) may have been compromised</li>
                        <li>Report to Chrome Web Store if still publicly available</li>
                        <li>Consider forensic analysis of affected systems</li>
"""
        elif settings_overrides.get('has_overrides'):
            html += """
                        <li><strong>IMMEDIATE ACTION: Browser hijacking detected</strong></li>
                        <li>Block this extension across all enterprise devices</li>
                        <li>Remove from approved extension whitelist</li>
                        <li>Notify users about the hijacking behavior</li>
                        <li>Review browser settings on affected machines</li>
                        <li>Investigate if any affiliate fraud revenue was generated</li>
"""
        elif risk_level in ['CRITICAL', 'HIGH']:
            html += """
                        <li><strong>IMMEDIATE ACTION:</strong> Block this extension across all enterprise devices</li>
                        <li>Remove from approved extension whitelist immediately</li>
                        <li>Notify all users who have installed this extension</li>
                        <li>Investigate if any sensitive data may have been compromised</li>
                        <li>Report to Chrome Web Store if still publicly available</li>
"""
        elif risk_level == 'MEDIUM':
            html += """
                        <li>Conduct detailed manual security review before deployment</li>
                        <li>Limit deployment to non-critical systems for testing</li>
                        <li>Monitor network traffic from devices with this extension</li>
                        <li>Review all external domains for legitimacy</li>
                        <li>Consider safer alternatives if available</li>
"""
        else:
            html += """
                        <li>Extension appears safe for deployment with monitoring</li>
                        <li>Add to approved extension list with version pinning</li>
                        <li>Set up periodic re-assessment for version updates</li>
                        <li>Monitor for any behavioral changes in future versions</li>
"""
        
        html += """
                    </ul>
                </div>
            </div>
"""
        return html
    
    def _extract_domains(self, external_scripts):
        """Extract unique domains from external scripts"""
        
        domains = set()
        for item in external_scripts:
            try:
                url = item.get('url', '')
                parsed = urlparse(url)
                domain = parsed.netloc
                if domain:
                    domains.add(domain)
            except:
                pass
        
        return domains
    
    def save_executive_report(self, results, output_dir='reports'):
        """Save executive report"""
        output_dir = Path(output_dir)
        output_dir.mkdir(exist_ok=True)
        
        html = self.generate_executive_report(results)
        
        extension_id = results.get('extension_id', 'unknown')
        html_path = output_dir / f"{extension_id}_executive_report.html"
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html)
        
        print(f"[+] Executive report saved: {html_path}")
        return html_path