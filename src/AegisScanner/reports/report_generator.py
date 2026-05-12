"""
Report Generator - Detection Report Generation

Generates comprehensive reports in multiple formats (HTML, JSON, Markdown)
for bootkit detection findings.

Copyright (c) 2026, Aegis-Boot Research Project
SPDX-License-Identifier: BSD-2-Clause-Patent
"""

import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path


class ReportGenerator:
    """Generator for bootkit detection reports."""
    
    # Correlation confidence adjustments
    ADDRESS_CORRELATION_BOOST = 1.2
    PCR_EVENTLOG_CORRELATION_CONFIDENCE = 0.95

    def __init__(self, findings: List[Dict], baseline: Optional[Dict] = None):
        """
        Initialize report generator.

        Args:
            findings: List of detection findings
            baseline: Baseline configuration used
        """
        self.findings = findings
        self.baseline = baseline
        self.timestamp = datetime.now()
        self.correlated_findings = []

    def correlate_findings(self) -> List[Dict]:
        """
        Correlate findings by address/offset and link related anomalies.
        
        Groups findings that:
        1. Share the same memory address/offset
        2. PCR mismatches linked with event log anomalies
        3. Hook detections linked with memory allocations
        
        Returns:
            List of correlated threat entries
        """
        self.correlated_findings = []
        
        # Group and collect findings
        address_groups = self._group_findings_by_address()
        pcr_findings, eventlog_findings = self._collect_detector_findings()
        
        # Create address-based correlations
        for address, findings_list in address_groups.items():
            if len(findings_list) > 1:
                correlation = self._create_address_correlation(address, findings_list)
                self.correlated_findings.append(correlation)
        
        # Create PCR/eventlog correlations
        for pcr_finding in pcr_findings:
            pcr_idx = self._get_pcr_index(pcr_finding)
            if pcr_idx is not None:
                related_eventlog = [
                    e for e in eventlog_findings
                    if self._get_pcr_index(e) == pcr_idx
                ]
                if related_eventlog:
                    correlation = self._create_pcr_eventlog_correlation(
                        pcr_finding, related_eventlog, pcr_idx
                    )
                    self.correlated_findings.append(correlation)
        
        return self.correlated_findings
    
    def _group_findings_by_address(self) -> Dict[str, List[Dict]]:
        """Group findings by memory address/offset."""
        address_groups = defaultdict(list)
        
        for finding in self.findings:
            details = finding.get('details', {})
            address = details.get('address') or details.get('offset')
            
            if address:
                address_groups[address].append(finding)
        
        return address_groups
    
    def _collect_detector_findings(self) -> tuple:
        """
        Collect PCR and eventlog findings for correlation.
        
        Returns:
            Tuple of (pcr_findings, eventlog_findings)
        """
        pcr_findings = []
        eventlog_findings = []
        
        for finding in self.findings:
            detector = finding.get('detector', '')
            if detector == 'pcr_replay':
                pcr_findings.append(finding)
            elif detector == 'eventlog':
                eventlog_findings.append(finding)
        
        return pcr_findings, eventlog_findings
    
    def _get_pcr_index(self, finding: Dict) -> Optional[int]:
        """Extract PCR index from finding details."""
        return finding.get('details', {}).get('pcr_index')
    
    def _get_max_severity(self, findings: List[Dict]) -> str:
        """Get maximum severity from list of findings."""
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0}
        max_sev = 'info'
        max_val = 0
        
        for finding in findings:
            sev = finding.get('severity', 'info')
            val = severity_order.get(sev, 0)
            if val > max_val:
                max_val = val
                max_sev = sev
        
        return max_sev
    
    def _create_address_correlation(self, address: str, findings_list: List[Dict]) -> Dict:
        """
        Create correlation entry for address-grouped findings.
        
        Args:
            address: Memory address/offset where findings were detected
            findings_list: List of findings at this address
            
        Returns:
            Correlation dictionary entry
        """
        max_severity = self._get_max_severity(findings_list)
        avg_confidence = sum(f.get('confidence', 1.0) for f in findings_list) / len(findings_list)
        
        return {
            'type': 'address_correlation',
            'severity': max_severity,
            'confidence': min(avg_confidence * self.ADDRESS_CORRELATION_BOOST, 1.0),
            'title': f'Multiple threats detected at {address}',
            'description': (
                f'Found {len(findings_list)} related findings at address {address}. '
                f'This correlation increases confidence of malicious activity.'
            ),
            'related_findings': [f.get('title') for f in findings_list],
            'detectors': list(set(f.get('detector') for f in findings_list))
        }
    
    def _create_pcr_eventlog_correlation(
        self, 
        pcr_finding: Dict, 
        related_eventlog: List[Dict], 
        pcr_idx: int
    ) -> Dict:
        """
        Create correlation entry for PCR/eventlog findings.
        
        Args:
            pcr_finding: PCR replay finding
            related_eventlog: List of related event log findings
            pcr_idx: PCR index being correlated
            
        Returns:
            Correlation dictionary entry
        """
        return {
            'type': 'pcr_eventlog_correlation',
            'severity': 'critical',
            'confidence': self.PCR_EVENTLOG_CORRELATION_CONFIDENCE,
            'title': f'PCR {pcr_idx} mismatch correlated with event log anomaly',
            'description': (
                f'PCR {pcr_idx} replay mismatch is correlated with event log '
                f'anomalies. This strongly indicates bootkit tampering with '
                f'measured boot process.'
            ),
            'related_findings': [
                pcr_finding.get('title'),
                *[e.get('title') for e in related_eventlog]
            ],
            'detectors': ['pcr_replay', 'eventlog'],
            'recommendation': (
                'CRITICAL: Measured boot integrity compromised. '
                'Investigate boot chain for malicious modifications.'
            )
        }
        
        return max_sev
    
    def generate_sarif(self, output_path: str):
        """
        Generate SARIF 2.1.0 report for GitHub Security integration.
        
        Args:
            output_path: Path to save SARIF report
        """
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "Aegis-Boot Scanner",
                            "version": "1.0.0",
                            "informationUri": "https://github.com/aegis-boot/scanner",
                            "rules": self._generate_sarif_rules()
                        }
                    },
                    "results": self._generate_sarif_results(),
                    "columnKind": "utf16CodeUnits"
                }
            ]
        }
        
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(sarif_report, f, indent=2)
    
    def _generate_sarif_rules(self) -> List[Dict]:
        """Generate SARIF rule definitions."""
        rules = []
        rule_ids = set()
        
        for finding in self.findings:
            detector = finding.get('detector', 'unknown')
            severity = finding.get('severity', 'warning')
            
            rule_id = f"{detector}-{severity}"
            if rule_id not in rule_ids:
                rule_ids.add(rule_id)
                rules.append({
                    "id": rule_id,
                    "name": f"{detector.title()}Detection",
                    "shortDescription": {
                        "text": finding.get('title', 'Detection finding')
                    },
                    "fullDescription": {
                        "text": finding.get('description', '')
                    },
                    "defaultConfiguration": {
                        "level": self._severity_to_sarif_level(severity)
                    },
                    "properties": {
                        "tags": [detector, "security", "bootkit"],
                        "precision": "high" if finding.get('confidence', 1.0) > 0.8 else "medium"
                    }
                })
        
        return rules
    
    def _generate_sarif_results(self) -> List[Dict]:
        """Generate SARIF results from findings."""
        results = []
        
        for finding in self.findings:
            detector = finding.get('detector', 'unknown')
            severity = finding.get('severity', 'warning')
            rule_id = f"{detector}-{severity}"
            
            result = {
                "ruleId": rule_id,
                "level": self._severity_to_sarif_level(severity),
                "message": {
                    "text": finding.get('description', '')
                },
                "properties": {
                    "confidence": finding.get('confidence', 1.0),
                    "detector": detector
                }
            }
            
            # Add location if available
            details = finding.get('details', {})
            if 'path' in details:
                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": details['path']
                        },
                        "region": {
                            "startLine": details.get('line', 1),
                            "startColumn": details.get('column', 1)
                        }
                    }
                }]
            
            # Add recommendation as fix
            if 'recommendation' in finding:
                result["fixes"] = [{
                    "description": {
                        "text": finding['recommendation']
                    }
                }]
            
            results.append(result)
        
        return results
    
    def _severity_to_sarif_level(self, severity: str) -> str:
        """Convert severity to SARIF level."""
        mapping = {
            'critical': 'error',
            'high': 'error',
            'medium': 'warning',
            'low': 'note',
            'info': 'note'
        }
        return mapping.get(severity, 'warning')
        self.timestamp = datetime.now()

    def generate_html(self, output_path: str):
        """
        Generate HTML report.

        Args:
            output_path: Path to save HTML report
        """
        html = self._generate_html_content()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)

    def generate_json(self, output_path: str):
        """
        Generate JSON report.

        Args:
            output_path: Path to save JSON report
        """
        report = {
            'timestamp': self.timestamp.isoformat(),
            'summary': self._generate_summary(),
            'findings': self.findings,
            'baseline_used': self.baseline is not None
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)

    def generate_markdown(self, output_path: str):
        """
        Generate Markdown report.

        Args:
            output_path: Path to save Markdown report
        """
        md = self._generate_markdown_content()
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(md)

    def _generate_summary(self) -> Dict:
        """Generate summary statistics."""
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        detector_counts = {}

        for finding in self.findings:
            severity = finding.get('severity', 'low').lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

            detector = finding.get('detector', 'unknown')
            detector_counts[detector] = detector_counts.get(detector, 0) + 1

        return {
            'total_findings': len(self.findings),
            'severity_breakdown': severity_counts,
            'detector_breakdown': detector_counts,
            'bootkit_detected': severity_counts['critical'] > 0 or severity_counts['high'] > 0
        }

    def _generate_html_content(self) -> str:
        """Generate HTML report content."""
        summary = self._generate_summary()

        # Determine overall status
        if summary['bootkit_detected']:
            status_class = 'danger'
            status_text = 'BOOTKIT DETECTED'
        else:
            status_class = 'success'
            status_text = 'NO THREATS DETECTED'

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Aegis-Boot Scanner Report</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: #f5f5f5;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #2c3e50;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            color: #2c3e50;
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        .header .timestamp {{
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        .status {{
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 30px;
            text-align: center;
            font-size: 1.5em;
            font-weight: bold;
        }}
        .status.danger {{
            background: #e74c3c;
            color: white;
        }}
        .status.success {{
            background: #27ae60;
            color: white;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: #ecf0f1;
            padding: 20px;
            border-radius: 5px;
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .summary-card .label {{
            color: #7f8c8d;
            font-size: 0.9em;
            text-transform: uppercase;
        }}
        .findings {{
            margin-top: 30px;
        }}
        .finding {{
            background: #fff;
            border-left: 4px solid #3498db;
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 5px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .finding.critical {{
            border-left-color: #e74c3c;
        }}
        .finding.high {{
            border-left-color: #e67e22;
        }}
        .finding.medium {{
            border-left-color: #f39c12;
        }}
        .finding.low {{
            border-left-color: #3498db;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }}
        .finding-title {{
            font-size: 1.3em;
            font-weight: bold;
            color: #2c3e50;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{
            background: #e74c3c;
            color: white;
        }}
        .severity-badge.high {{
            background: #e67e22;
            color: white;
        }}
        .severity-badge.medium {{
            background: #f39c12;
            color: white;
        }}
        .severity-badge.low {{
            background: #3498db;
            color: white;
        }}
        .finding-description {{
            color: #555;
            margin-bottom: 15px;
        }}
        .finding-details {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 15px;
        }}
        .finding-details pre {{
            margin: 0;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
            white-space: pre-wrap;
            word-wrap: break-word;
        }}
        .recommendation {{
            background: #d4edda;
            border-left: 3px solid #28a745;
            padding: 15px;
            border-radius: 5px;
        }}
        .recommendation strong {{
            color: #155724;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ecf0f1;
            text-align: center;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Aegis-Boot Scanner Report</h1>
            <div class="timestamp">Generated: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}</div>
        </div>

        <div class="status {status_class}">
            {status_text}
        </div>

        <div class="summary">
            <div class="summary-card">
                <div class="number">{summary['total_findings']}</div>
                <div class="label">Total Findings</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['severity_breakdown']['critical']}</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['severity_breakdown']['high']}</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['severity_breakdown']['medium']}</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card">
                <div class="number">{summary['severity_breakdown']['low']}</div>
                <div class="label">Low</div>
            </div>
        </div>

        <div class="findings">
            <h2>Detailed Findings</h2>
"""

        # Add each finding
        for i, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'low').lower()
            title = finding.get('title', 'Unknown Issue')
            description = finding.get('description', 'No description available')
            details = finding.get('details', {})
            recommendation = finding.get('recommendation', 'No recommendation available')

            html += f"""
            <div class="finding {severity}">
                <div class="finding-header">
                    <div class="finding-title">{i}. {title}</div>
                    <span class="severity-badge {severity}">{severity}</span>
                </div>
                <div class="finding-description">{description}</div>
"""

            # Add details if present
            if details:
                html += """
                <div class="finding-details">
                    <strong>Details:</strong>
                    <pre>"""
                html += json.dumps(details, indent=2)
                html += """</pre>
                </div>
"""

            # Add recommendation
            html += f"""
                <div class="recommendation">
                    <strong>Recommendation:</strong> {recommendation}
                </div>
            </div>
"""

        html += """
        </div>

        <div class="footer">
            <p>Aegis-Boot Scanner v1.0 | Academic Research Project</p>
            <p>Copyright © 2026 Aegis-Boot Research Project</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _generate_markdown_content(self) -> str:
        """Generate Markdown report content."""
        summary = self._generate_summary()

        # Determine overall status
        if summary['bootkit_detected']:
            status = '🚨 **BOOTKIT DETECTED**'
        else:
            status = '✅ **NO THREATS DETECTED**'

        md = f"""# Aegis-Boot Scanner Report

**Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}

---

## Status

{status}

---

## Summary

| Metric | Count |
|--------|-------|
| Total Findings | {summary['total_findings']} |
| Critical | {summary['severity_breakdown']['critical']} |
| High | {summary['severity_breakdown']['high']} |
| Medium | {summary['severity_breakdown']['medium']} |
| Low | {summary['severity_breakdown']['low']} |

---

## Detailed Findings

"""

        # Add each finding
        for i, finding in enumerate(self.findings, 1):
            severity = finding.get('severity', 'low').upper()
            title = finding.get('title', 'Unknown Issue')
            description = finding.get('description', 'No description available')
            details = finding.get('details', {})
            recommendation = finding.get('recommendation', 'No recommendation available')
            detector = finding.get('detector', 'unknown')

            # Severity emoji
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🔵'
            }.get(severity, '⚪')

            md += f"""### {i}. {title}

**Severity:** {severity_emoji} {severity}  
**Detector:** {detector}

**Description:**  
{description}

"""

            # Add details if present
            if details:
                md += "**Details:**\n```json\n"
                md += json.dumps(details, indent=2)
                md += "\n```\n\n"

            # Add recommendation
            md += f"""**Recommendation:**  
{recommendation}

---

"""

        md += f"""
## Report Information

- **Scanner Version:** 1.0
- **Baseline Used:** {'Yes' if self.baseline else 'No'}
- **Total Detectors:** {len(summary['detector_breakdown'])}

---

*Aegis-Boot Scanner - Academic Research Project*  
*Copyright © 2026 Aegis-Boot Research Project*
"""

        return md
