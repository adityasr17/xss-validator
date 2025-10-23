"""
Reporting and output utilities
"""

import json
import csv
import html
from datetime import datetime
from typing import List, Dict, Any
import os


class ReportGenerator:
    """Generate various report formats for XSS scan results"""
    
    def __init__(self, scan_results: Dict[str, Any]):
        self.scan_results = scan_results
        self.vulnerabilities = scan_results.get('vulnerabilities', [])
        self.scan_info = scan_results.get('scan_info', {})
    
    def generate_json_report(self, output_file: str) -> None:
        """Generate JSON report"""
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(self.scan_results, f, indent=2, ensure_ascii=False)
    
    def generate_csv_report(self, output_file: str) -> None:
        """Generate CSV report"""
        if not self.vulnerabilities:
            return
        
        fieldnames = [
            'type', 'url', 'parameter', 'payload', 'method', 
            'evidence', 'severity', 'timestamp'
        ]
        
        with open(output_file, 'w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            for vuln in self.vulnerabilities:
                row = {
                    'type': vuln.get('type', ''),
                    'url': vuln.get('url', ''),
                    'parameter': vuln.get('parameter', ''),
                    'payload': vuln.get('payload', ''),
                    'method': vuln.get('method', ''),
                    'evidence': vuln.get('evidence', ''),
                    'severity': self._get_severity(vuln.get('type', '')),
                    'timestamp': datetime.now().isoformat()
                }
                writer.writerow(row)
    
    def generate_html_report(self, output_file: str) -> None:
        """Generate HTML report"""
        html_content = self._create_html_template()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
    
    def generate_xml_report(self, output_file: str) -> None:
        """Generate XML report"""
        xml_content = self._create_xml_template()
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(xml_content)
    
    def _get_severity(self, vuln_type: str) -> str:
        """Determine vulnerability severity based on type"""
        severity_map = {
            'Reflected XSS': 'Medium',
            'Stored XSS': 'High',
            'DOM-based XSS': 'Medium'
        }
        return severity_map.get(vuln_type, 'Medium')
    
    def _create_html_template(self) -> str:
        """Create HTML report template"""
        vuln_rows = ""
        for vuln in self.vulnerabilities:
            severity = self._get_severity(vuln.get('type', ''))
            severity_class = severity.lower()
            
            vuln_rows += f"""
            <tr class="{severity_class}">
                <td>{html.escape(vuln.get('type', ''))}</td>
                <td><a href="{html.escape(vuln.get('url', ''))}" target="_blank">{html.escape(vuln.get('url', ''))}</a></td>
                <td>{html.escape(str(vuln.get('parameter', '')))}</td>
                <td><code>{html.escape(vuln.get('payload', ''))}</code></td>
                <td>{html.escape(vuln.get('method', ''))}</td>
                <td>{html.escape(vuln.get('evidence', ''))}</td>
                <td><span class="severity {severity_class}">{severity}</span></td>
            </tr>
            """
        
        html_template = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>XSS Vulnerability Scan Report</title>
            <style>
                body {{
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                    margin: 0;
                    padding: 20px;
                    background-color: #f5f5f5;
                }}
                .container {{
                    max-width: 1200px;
                    margin: 0 auto;
                    background-color: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }}
                .header {{
                    border-bottom: 3px solid #007acc;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }}
                .title {{
                    color: #007acc;
                    font-size: 2.5em;
                    margin: 0;
                }}
                .subtitle {{
                    color: #666;
                    font-size: 1.2em;
                    margin: 10px 0 0 0;
                }}
                .summary {{
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }}
                .summary-card {{
                    background: linear-gradient(135deg, #007acc, #005a9e);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }}
                .summary-card h3 {{
                    margin: 0 0 10px 0;
                    font-size: 1.1em;
                }}
                .summary-card .value {{
                    font-size: 2em;
                    font-weight: bold;
                }}
                .vulnerabilities {{
                    margin-top: 30px;
                }}
                .section-title {{
                    color: #333;
                    font-size: 1.8em;
                    margin-bottom: 20px;
                    border-bottom: 2px solid #007acc;
                    padding-bottom: 10px;
                }}
                table {{
                    width: 100%;
                    border-collapse: collapse;
                    margin-top: 20px;
                }}
                th, td {{
                    padding: 12px;
                    text-align: left;
                    border-bottom: 1px solid #ddd;
                }}
                th {{
                    background-color: #007acc;
                    color: white;
                    font-weight: bold;
                }}
                tr:hover {{
                    background-color: #f5f5f5;
                }}
                .high {{
                    background-color: #ffe6e6;
                }}
                .medium {{
                    background-color: #fff4e6;
                }}
                .low {{
                    background-color: #e6ffe6;
                }}
                .severity {{
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-weight: bold;
                    text-transform: uppercase;
                    font-size: 0.8em;
                }}
                .severity.high {{
                    background-color: #dc3545;
                    color: white;
                }}
                .severity.medium {{
                    background-color: #fd7e14;
                    color: white;
                }}
                .severity.low {{
                    background-color: #28a745;
                    color: white;
                }}
                code {{
                    background-color: #f8f9fa;
                    padding: 2px 4px;
                    border-radius: 3px;
                    font-family: 'Courier New', monospace;
                    font-size: 0.9em;
                }}
                .no-vulnerabilities {{
                    text-align: center;
                    padding: 40px;
                    color: #28a745;
                    font-size: 1.2em;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1 class="title">XSS Vulnerability Scan Report</h1>
                    <p class="subtitle">Security Assessment Results</p>
                </div>
                
                <div class="summary">
                    <div class="summary-card">
                        <h3>Target URL</h3>
                        <div class="value">{html.escape(self.scan_info.get('target', 'N/A'))}</div>
                    </div>
                    <div class="summary-card">
                        <h3>URLs Tested</h3>
                        <div class="value">{self.scan_info.get('urls_tested', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Subdomains Found</h3>
                        <div class="value">{self.scan_info.get('subdomains_found', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Vulnerabilities Found</h3>
                        <div class="value">{self.scan_info.get('vulnerabilities_found', 0)}</div>
                    </div>
                    <div class="summary-card">
                        <h3>Scan Duration</h3>
                        <div class="value">{self.scan_info.get('duration_seconds', 0):.1f}s</div>
                    </div>
                    <div class="summary-card">
                        <h3>Scan Date</h3>
                        <div class="value">{self.scan_info.get('start_time', 'N/A')[:10]}</div>
                    </div>
                </div>
                
                <div class="vulnerabilities">
                    <h2 class="section-title">Discovered Vulnerabilities</h2>
                    
                    {f'''
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>URL</th>
                                <th>Parameter</th>
                                <th>Payload</th>
                                <th>Method</th>
                                <th>Evidence</th>
                                <th>Severity</th>
                            </tr>
                        </thead>
                        <tbody>
                            {vuln_rows}
                        </tbody>
                    </table>
                    ''' if self.vulnerabilities else '<div class="no-vulnerabilities">🎉 No XSS vulnerabilities were found!</div>'}
                </div>
            </div>
        </body>
        </html>
        """
        
        return html_template
    
    def _create_xml_template(self) -> str:
        """Create XML report template"""
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<xss_scan_report>\n'
        xml_content += '  <scan_info>\n'
        
        for key, value in self.scan_info.items():
            xml_content += f'    <{key}>{html.escape(str(value))}</{key}>\n'
        
        xml_content += '  </scan_info>\n'
        xml_content += '  <vulnerabilities>\n'
        
        for vuln in self.vulnerabilities:
            xml_content += '    <vulnerability>\n'
            xml_content += f'      <type>{html.escape(vuln.get("type", ""))}</type>\n'
            xml_content += f'      <url>{html.escape(vuln.get("url", ""))}</url>\n'
            xml_content += f'      <parameter>{html.escape(str(vuln.get("parameter", "")))}</parameter>\n'
            xml_content += f'      <payload>{html.escape(vuln.get("payload", ""))}</payload>\n'
            xml_content += f'      <method>{html.escape(vuln.get("method", ""))}</method>\n'
            xml_content += f'      <evidence>{html.escape(vuln.get("evidence", ""))}</evidence>\n'
            xml_content += f'      <severity>{self._get_severity(vuln.get("type", ""))}</severity>\n'
            xml_content += '    </vulnerability>\n'
        
        xml_content += '  </vulnerabilities>\n'
        xml_content += '</xss_scan_report>\n'
        
        return xml_content
    
    def print_summary(self) -> None:
        """Print scan summary to console"""
        print("\n" + "="*60)
        print("                XSS SCAN SUMMARY")
        print("="*60)
        print(f"Target URL: {self.scan_info.get('target', 'N/A')}")
        print(f"Scan Duration: {self.scan_info.get('duration_seconds', 0):.2f} seconds")
        print(f"URLs Tested: {self.scan_info.get('urls_tested', 0)}")
        print(f"Subdomains Found: {self.scan_info.get('subdomains_found', 0)}")
        print(f"Vulnerabilities Found: {self.scan_info.get('vulnerabilities_found', 0)}")
        
        if self.vulnerabilities:
            print("\nVULNERABILITIES FOUND:")
            print("-" * 40)
            
            vuln_types = {}
            for vuln in self.vulnerabilities:
                vuln_type = vuln.get('type', 'Unknown')
                vuln_types[vuln_type] = vuln_types.get(vuln_type, 0) + 1
            
            for vuln_type, count in vuln_types.items():
                severity = self._get_severity(vuln_type)
                print(f"  {vuln_type}: {count} ({severity} severity)")
            
            print("\nDETAILED FINDINGS:")
            print("-" * 40)
            for i, vuln in enumerate(self.vulnerabilities, 1):
                print(f"\n{i}. {vuln.get('type', 'Unknown XSS')}")
                print(f"   URL: {vuln.get('url', 'N/A')}")
                print(f"   Parameter: {vuln.get('parameter', 'N/A')}")
                print(f"   Method: {vuln.get('method', 'N/A')}")
                print(f"   Payload: {vuln.get('payload', 'N/A')[:100]}...")
        else:
            print("\n✅ No XSS vulnerabilities were found!")
        
        print("="*60)


class VulnerabilityAnalyzer:
    """Analyze and categorize vulnerabilities"""
    
    @staticmethod
    def analyze_impact(vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Analyze the impact of discovered vulnerabilities"""
        analysis = {
            'total_count': len(vulnerabilities),
            'by_type': {},
            'by_severity': {'High': 0, 'Medium': 0, 'Low': 0},
            'affected_domains': set(),
            'common_parameters': {},
            'risk_score': 0
        }
        
        for vuln in vulnerabilities:
            # Count by type
            vuln_type = vuln.get('type', 'Unknown')
            analysis['by_type'][vuln_type] = analysis['by_type'].get(vuln_type, 0) + 1
            
            # Count by severity
            severity = ReportGenerator._get_severity(None, vuln_type)
            analysis['by_severity'][severity] += 1
            
            # Extract domain
            url = vuln.get('url', '')
            if url:
                domain = url.split('/')[2] if '://' in url else url.split('/')[0]
                analysis['affected_domains'].add(domain)
            
            # Count common parameters
            param = vuln.get('parameter', '')
            if param and param != 'N/A':
                param_str = str(param)
                analysis['common_parameters'][param_str] = analysis['common_parameters'].get(param_str, 0) + 1
        
        # Calculate risk score (0-100)
        risk_score = 0
        risk_score += analysis['by_severity']['High'] * 30
        risk_score += analysis['by_severity']['Medium'] * 20
        risk_score += analysis['by_severity']['Low'] * 10
        risk_score += len(analysis['affected_domains']) * 5
        
        analysis['risk_score'] = min(risk_score, 100)
        analysis['affected_domains'] = list(analysis['affected_domains'])
        
        return analysis
