"""
Scope Report Generator Module for ThornCipher

This module provides functionality to generate various types of reports
based on scope data, including HTML, PDF, JSON, and CSV formats.
"""

import json
import csv
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import io

# Set up logging
logger = logging.getLogger(__name__)


class ScopeReportGenerator:
    """Generates various types of reports from scope data."""
    
    def __init__(self):
        """Initialize the report generator."""
        self.report_templates = {}
        self.custom_formatters = {}
        logger.info("ScopeReportGenerator initialized")
    
    def generate_scope_summary_report(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a comprehensive summary report of scope data.
        
        Args:
            scope_data: Dictionary containing scope information
            
        Returns:
            Dictionary containing the summary report
        """
        try:
            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "scope_summary",
                    "version": "1.0"
                },
                "scope_overview": {
                    "scope_id": scope_data.get("id", "unknown"),
                    "name": scope_data.get("name", "Unnamed Scope"),
                    "description": scope_data.get("description", "No description"),
                    "created_at": scope_data.get("created_at"),
                    "updated_at": scope_data.get("updated_at"),
                    "status": scope_data.get("status", "active")
                },
                "target_statistics": self._generate_target_statistics(scope_data),
                "compliance_summary": self._generate_compliance_summary(scope_data),
                "risk_assessment": self._generate_risk_assessment(scope_data)
            }
            
            logger.info(f"Generated scope summary report for scope: {scope_data.get('name', 'unknown')}")
            return report
            
        except Exception as e:
            logger.error(f"Error generating scope summary report: {str(e)}")
            raise
    
    def generate_target_list_report(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a detailed target list report.
        
        Args:
            scope_data: Dictionary containing scope information
            
        Returns:
            Dictionary containing the target list report
        """
        try:
            targets = scope_data.get("targets", {})
            
            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "target_list",
                    "version": "1.0"
                },
                "scope_info": {
                    "scope_id": scope_data.get("id"),
                    "name": scope_data.get("name"),
                    "description": scope_data.get("description")
                },
                "targets": {
                    "domains": targets.get("domains", []),
                    "ips": targets.get("ips", []),
                    "urls": targets.get("urls", []),
                    "networks": targets.get("networks", [])
                },
                "exclusions": scope_data.get("exclusions", {}),
                "total_targets": self._count_total_targets(targets)
            }
            
            logger.info(f"Generated target list report with {report['total_targets']} targets")
            return report
            
        except Exception as e:
            logger.error(f"Error generating target list report: {str(e)}")
            raise
    
    def generate_compliance_report(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generate a compliance-focused report.
        
        Args:
            scope_data: Dictionary containing scope information
            
        Returns:
            Dictionary containing the compliance report
        """
        try:
            report = {
                "report_metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "report_type": "compliance",
                    "version": "1.0"
                },
                "scope_info": {
                    "scope_id": scope_data.get("id"),
                    "name": scope_data.get("name")
                },
                "compliance_checks": {
                    "authorization_verified": scope_data.get("authorized", False),
                    "legal_constraints": scope_data.get("legal_constraints", []),
                    "regulatory_requirements": scope_data.get("regulatory_requirements", []),
                    "business_hours_restrictions": scope_data.get("business_hours_only", False),
                    "rate_limiting_required": scope_data.get("rate_limiting", {}).get("enabled", False)
                },
                "risk_factors": {
                    "high_risk_targets": self._identify_high_risk_targets(scope_data),
                    "potential_collateral_damage": self._assess_collateral_risk(scope_data),
                    "regulatory_implications": self._assess_regulatory_risk(scope_data)
                },
                "recommendations": self._generate_compliance_recommendations(scope_data)
            }
            
            logger.info("Generated compliance report")
            return report
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {str(e)}")
            raise
    
    def export_to_json(self, report_data: Dict[str, Any], output_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Export report data to JSON format.
        
        Args:
            report_data: Report data to export
            output_path: Optional file path to save the JSON report
            
        Returns:
            JSON string or saved file confirmation
        """
        try:
            json_output = json.dumps(report_data, indent=2, default=str)
            
            if output_path:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(json_output)
                logger.info(f"JSON report exported to: {output_path}")
                return {"status": "exported", "path": output_path}
            
            return json_output
            
        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            raise
    
    def export_to_csv(self, report_data: Dict[str, Any], output_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Export report data to CSV format.
        
        Args:
            report_data: Report data to export
            output_path: Optional file path to save the CSV report
            
        Returns:
            CSV string or saved file confirmation
        """
        try:
            # Create CSV data based on report type
            if report_data.get("report_metadata", {}).get("report_type") == "target_list":
                csv_data = self._convert_target_list_to_csv(report_data)
            else:
                csv_data = self._convert_generic_report_to_csv(report_data)
            
            if output_path:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w', newline='', encoding='utf-8') as f:
                    f.write(csv_data)
                logger.info(f"CSV report exported to: {output_path}")
                return {"status": "exported", "path": output_path}
            
            return csv_data
            
        except Exception as e:
            logger.error(f"Error exporting to CSV: {str(e)}")
            raise
    
    def export_to_html(self, report_data: Dict[str, Any], output_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
        """
        Export report data to HTML format.
        
        Args:
            report_data: Report data to export
            output_path: Optional file path to save the HTML report
            
        Returns:
            HTML string or saved file confirmation
        """
        try:
            html_content = self._generate_html_report(report_data)
            
            if output_path:
                Path(output_path).parent.mkdir(parents=True, exist_ok=True)
                with open(output_path, 'w', encoding='utf-8') as f:
                    f.write(html_content)
                logger.info(f"HTML report exported to: {output_path}")
                return {"status": "exported", "path": output_path}
            
            return html_content
            
        except Exception as e:
            logger.error(f"Error exporting to HTML: {str(e)}")
            raise
    
    def generate_report(self, scope_data: List[Dict[str, Any]], format: str = "json") -> Union[str, None]:
        """Generates a report based on scope data."""
        if format == "json":
            return self._generate_json_report(scope_data)
        elif format == "csv":
            return self._generate_csv_report(scope_data)
        elif format == "html":
            return self._generate_html_scope_report(scope_data)
        else:
            logger.error(f"Unsupported format: {format}")
            return None

    def _generate_json_report(self, scope_data: List[Dict[str, Any]]) -> str:
        """Generates a JSON report."""
        return json.dumps(scope_data, indent=2)

    def _generate_csv_report(self, scope_data: List[Dict[str, Any]]) -> str:
        """Generates a CSV report."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["target", "type"])
        for item in scope_data:
            writer.writerow([item["target"], item["type"]])
        return output.getvalue()

    def _generate_html_scope_report(self, scope_data: List[Dict[str, Any]]) -> str:
        """Generates an HTML report for scope data."""
        html_data = "<html><body><table><tr><th>Target</th><th>Type</th></tr>"
        for item in scope_data:
            html_data += f"<tr><td>{item['target']}</td><td>{item['type']}</td></tr>"
        html_data += "</table></body></html>"
        return html_data
    
    def _generate_target_statistics(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate statistics about targets in the scope."""
        targets = scope_data.get("targets", {})
        
        return {
            "total_domains": len(targets.get("domains", [])),
            "total_ips": len(targets.get("ips", [])),
            "total_urls": len(targets.get("urls", [])),
            "total_networks": len(targets.get("networks", [])),
            "total_targets": self._count_total_targets(targets),
            "exclusion_count": len(scope_data.get("exclusions", {}).get("domains", [])) +
                              len(scope_data.get("exclusions", {}).get("ips", []))
        }
    
    def _generate_compliance_summary(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate compliance summary."""
        return {
            "authorized": scope_data.get("authorized", False),
            "has_legal_constraints": len(scope_data.get("legal_constraints", [])) > 0,
            "business_hours_only": scope_data.get("business_hours_only", False),
            "rate_limiting_enabled": scope_data.get("rate_limiting", {}).get("enabled", False),
            "compliance_score": self._calculate_compliance_score(scope_data)
        }
    
    def _generate_risk_assessment(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate risk assessment summary."""
        targets = scope_data.get("targets", {})
        
        return {
            "risk_level": self._assess_risk_level(scope_data),
            "high_risk_domains": self._identify_high_risk_domains(targets.get("domains", [])),
            "external_targets": self._count_external_targets(targets),
            "regulatory_risk": len(scope_data.get("regulatory_requirements", [])) > 0
        }
    
    def _count_total_targets(self, targets: Dict[str, List]) -> int:
        """Count total number of targets across all categories."""
        return sum(len(target_list) for target_list in targets.values())
    
    def _identify_high_risk_targets(self, scope_data: Dict[str, Any]) -> List[str]:
        """Identify potentially high-risk targets."""
        high_risk = []
        targets = scope_data.get("targets", {})
        
        # Check for government domains
        for domain in targets.get("domains", []):
            if any(gov_tld in domain.lower() for gov_tld in ['.gov', '.mil', '.edu']):
                high_risk.append(domain)
        
        return high_risk
    
    def _assess_collateral_risk(self, scope_data: Dict[str, Any]) -> str:
        """Assess potential for collateral damage."""
        targets = scope_data.get("targets", {})
        
        # Simple heuristic based on target types
        if targets.get("networks") or targets.get("ips"):
            return "medium"
        elif len(targets.get("domains", [])) > 10:
            return "medium"
        else:
            return "low"
    
    def _assess_regulatory_risk(self, scope_data: Dict[str, Any]) -> str:
        """Assess regulatory implications."""
        if scope_data.get("regulatory_requirements"):
            return "high"
        elif self._identify_high_risk_targets(scope_data):
            return "medium"
        else:
            return "low"
    
    def _generate_compliance_recommendations(self, scope_data: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        if not scope_data.get("authorized"):
            recommendations.append("Ensure proper authorization is obtained before testing")
        
        if not scope_data.get("business_hours_only") and self._identify_high_risk_targets(scope_data):
            recommendations.append("Consider restricting testing to business hours for high-risk targets")
        
        if not scope_data.get("rate_limiting", {}).get("enabled"):
            recommendations.append("Enable rate limiting to minimize impact on target systems")
        
        return recommendations
    
    def _calculate_compliance_score(self, scope_data: Dict[str, Any]) -> float:
        """Calculate a compliance score (0-100)."""
        score = 0
        
        if scope_data.get("authorized"):
            score += 30
        if scope_data.get("legal_constraints"):
            score += 20
        if scope_data.get("business_hours_only"):
            score += 15
        if scope_data.get("rate_limiting", {}).get("enabled"):
            score += 15
        if not self._identify_high_risk_targets(scope_data):
            score += 20
        
        return min(score, 100)
    
    def _assess_risk_level(self, scope_data: Dict[str, Any]) -> str:
        """Assess overall risk level of the scope."""
        high_risk_targets = self._identify_high_risk_targets(scope_data)
        
        if high_risk_targets:
            return "high"
        elif len(scope_data.get("targets", {}).get("domains", [])) > 20:
            return "medium"
        else:
            return "low"
    
    def _identify_high_risk_domains(self, domains: List[str]) -> List[str]:
        """Identify high-risk domains."""
        high_risk = []
        risk_indicators = ['.gov', '.mil', '.edu', 'bank', 'financial', 'healthcare']
        
        for domain in domains:
            if any(indicator in domain.lower() for indicator in risk_indicators):
                high_risk.append(domain)
        
        return high_risk
    
    def _count_external_targets(self, targets: Dict[str, List]) -> int:
        """Count targets that appear to be external/public."""
        # Simple heuristic - assume all targets are external unless they're private IPs
        external_count = 0
        
        for ip in targets.get("ips", []):
            if not any(ip.startswith(private) for private in ['10.', '192.168.', '172.']):
                external_count += 1
        
        # All domains and URLs are assumed external
        external_count += len(targets.get("domains", []))
        external_count += len(targets.get("urls", []))
        
        return external_count
    
    def _convert_target_list_to_csv(self, report_data: Dict[str, Any]) -> str:
        """Convert target list report to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write headers
        writer.writerow(['Type', 'Target', 'Status'])
        
        # Write targets
        targets = report_data.get("targets", {})
        for target_type, target_list in targets.items():
            for target in target_list:
                writer.writerow([target_type, target, 'active'])
        
        return output.getvalue()
    
    def _convert_generic_report_to_csv(self, report_data: Dict[str, Any]) -> str:
        """Convert generic report to CSV format."""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write metadata
        writer.writerow(['Report Metadata'])
        metadata = report_data.get("report_metadata", {})
        for key, value in metadata.items():
            writer.writerow([key, value])
        
        writer.writerow([])  # Empty row for separation
        
        # Write main content (simplified)
        writer.writerow(['Key', 'Value'])
        for key, value in report_data.items():
            if key != "report_metadata":
                writer.writerow([key, str(value)])
        
        return output.getvalue()
    
    def _generate_html_report(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML report."""
        report_type = report_data.get("report_metadata", {}).get("report_type", "unknown")
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ThornCipher Scope Report - {report_type.title()}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background-color: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
        h1, h2, h3 {{ color: #333; }}
        .metadata {{ background: #f8f9fa; padding: 15px; border-radius: 5px; margin-bottom: 20px; }}
        .section {{ margin-bottom: 30px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f2f2f2; font-weight: bold; }}
        .risk-high {{ color: #d32f2f; font-weight: bold; }}
        .risk-medium {{ color: #f57c00; font-weight: bold; }}
        .risk-low {{ color: #388e3c; font-weight: bold; }}
        .status-active {{ color: #4caf50; }}
        .status-inactive {{ color: #f44336; }}
        ul {{ padding-left: 20px; }}
        .summary-card {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="summary-card">
            <h1>🛡️ ThornCipher Scope Report</h1>
            <p><strong>Report Type:</strong> {report_type.title()}</p>
            <p><strong>Generated:</strong> {report_data.get("report_metadata", {}).get("generated_at", "Unknown")}</p>
        </div>
        
        {self._generate_html_content_by_type(report_data)}
        
        <div class="section">
            <p style="text-align: center; color: #666; font-size: 12px; margin-top: 40px;">
                Generated by ThornCipher Security Testing Platform
            </p>
        </div>
    </div>
</body>
</html>
        """
        
        return html
    
    def _generate_html_content_by_type(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML content based on report type."""
        report_type = report_data.get("report_metadata", {}).get("report_type", "unknown")
        
        if report_type == "scope_summary":
            return self._generate_scope_summary_html(report_data)
        elif report_type == "target_list":
            return self._generate_target_list_html(report_data)
        elif report_type == "compliance":
            return self._generate_compliance_html(report_data)
        else:
            return self._generate_generic_html(report_data)
    
    def _generate_scope_summary_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML for scope summary report."""
        overview = report_data.get("scope_overview", {})
        stats = report_data.get("target_statistics", {})
        compliance = report_data.get("compliance_summary", {})
        risk = report_data.get("risk_assessment", {})
        
        return f"""
        <div class="section">
            <h2>📋 Scope Overview</h2>
            <table>
                <tr><th>Scope Name</th><td>{overview.get('name', 'N/A')}</td></tr>
                <tr><th>Description</th><td>{overview.get('description', 'N/A')}</td></tr>
                <tr><th>Status</th><td class="status-{overview.get('status', 'unknown')}">{overview.get('status', 'Unknown').title()}</td></tr>
                <tr><th>Created</th><td>{overview.get('created_at', 'N/A')}</td></tr>
                <tr><th>Updated</th><td>{overview.get('updated_at', 'N/A')}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>📊 Target Statistics</h2>
            <table>
                <tr><th>Domains</th><td>{stats.get('total_domains', 0)}</td></tr>
                <tr><th>IP Addresses</th><td>{stats.get('total_ips', 0)}</td></tr>
                <tr><th>URLs</th><td>{stats.get('total_urls', 0)}</td></tr>
                <tr><th>Networks</th><td>{stats.get('total_networks', 0)}</td></tr>
                <tr><th>Total Targets</th><td><strong>{stats.get('total_targets', 0)}</strong></td></tr>
                <tr><th>Exclusions</th><td>{stats.get('exclusion_count', 0)}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>✅ Compliance Summary</h2>
            <table>
                <tr><th>Authorized</th><td class="status-{'active' if compliance.get('authorized') else 'inactive'}">{'Yes' if compliance.get('authorized') else 'No'}</td></tr>
                <tr><th>Legal Constraints</th><td>{'Yes' if compliance.get('has_legal_constraints') else 'No'}</td></tr>
                <tr><th>Business Hours Only</th><td>{'Yes' if compliance.get('business_hours_only') else 'No'}</td></tr>
                <tr><th>Rate Limiting</th><td>{'Enabled' if compliance.get('rate_limiting_enabled') else 'Disabled'}</td></tr>
                <tr><th>Compliance Score</th><td><strong>{compliance.get('compliance_score', 0)}%</strong></td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Risk Assessment</h2>
            <table>
                <tr><th>Risk Level</th><td class="risk-{risk.get('risk_level', 'unknown')}">{risk.get('risk_level', 'Unknown').title()}</td></tr>
                <tr><th>High-Risk Domains</th><td>{len(risk.get('high_risk_domains', []))}</td></tr>
                <tr><th>External Targets</th><td>{risk.get('external_targets', 0)}</td></tr>
                <tr><th>Regulatory Risk</th><td>{'Yes' if risk.get('regulatory_risk') else 'No'}</td></tr>
            </table>
        </div>
        """
    
    def _generate_target_list_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML for target list report."""
        targets = report_data.get("targets", {})
        
        html = '<div class="section"><h2>🎯 Target List</h2>'
        
        for target_type, target_list in targets.items():
            if target_list:
                html += f'<h3>{target_type.title()}</h3><ul>'
                for target in target_list:
                    html += f'<li>{target}</li>'
                html += '</ul>'
        
        html += '</div>'
        return html
    
    def _generate_compliance_html(self, report_data: Dict[str, Any]) -> str:
        """Generate HTML for compliance report."""
        checks = report_data.get("compliance_checks", {})
        risk_factors = report_data.get("risk_factors", {})
        recommendations = report_data.get("recommendations", [])
        
        return f"""
        <div class="section">
            <h2>✅ Compliance Checks</h2>
            <table>
                <tr><th>Authorization Verified</th><td class="status-{'active' if checks.get('authorization_verified') else 'inactive'}">{'Yes' if checks.get('authorization_verified') else 'No'}</td></tr>
                <tr><th>Business Hours Restriction</th><td>{'Yes' if checks.get('business_hours_restrictions') else 'No'}</td></tr>
                <tr><th>Rate Limiting Required</th><td>{'Yes' if checks.get('rate_limiting_required') else 'No'}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>⚠️ Risk Factors</h2>
            <table>
                <tr><th>High-Risk Targets</th><td>{len(risk_factors.get('high_risk_targets', []))}</td></tr>
                <tr><th>Collateral Damage Risk</th><td class="risk-{risk_factors.get('potential_collateral_damage', 'unknown')}">{risk_factors.get('potential_collateral_damage', 'Unknown').title()}</td></tr>
                <tr><th>Regulatory Implications</th><td class="risk-{risk_factors.get('regulatory_implications', 'unknown')}">{risk_factors.get('regulatory_implications', 'Unknown').title()}</td></tr>
            </table>
        </div>
        
        <div class="section">
            <h2>💡 Recommendations</h2>
            <ul>
                {"".join(f"<li>{rec}</li>" for rec in recommendations)}
            </ul>
        </div>
        """
    
    def _generate_generic_html(self, report_data: Dict[str, Any]) -> str:
        """Generate generic HTML for unknown report types."""
        return f"""
        <div class="section">
            <h2>📄 Report Data</h2>
            <pre style="background: #f8f9fa; padding: 15px; border-radius: 5px; overflow-x: auto;">
{json.dumps(report_data, indent=2, default=str)}
            </pre>
        </div>
        """


# Convenience functions for quick report generation
def generate_scope_summary(scope_data: Dict[str, Any]) -> Dict[str, Any]:
    """Quick function to generate a scope summary report."""
    generator = ScopeReportGenerator()
    return generator.generate_scope_summary_report(scope_data)


def generate_target_list(scope_data: Dict[str, Any]) -> Dict[str, Any]:
    """Quick function to generate a target list report."""
    generator = ScopeReportGenerator()
    return generator.generate_target_list_report(scope_data)


def generate_compliance_report(scope_data: Dict[str, Any]) -> Dict[str, Any]:
    """Quick function to generate a compliance report."""
    generator = ScopeReportGenerator()
    return generator.generate_compliance_report(scope_data)


def export_report(report_data: Dict[str, Any], format_type: str = "json", output_path: Optional[str] = None) -> Union[str, Dict[str, Any]]:
    """
    Quick function to export a report in the specified format.
    
    Args:
        report_data: Report data to export
        format_type: Export format ('json', 'csv', 'html')
        output_path: Optional file path to save the report
        
    Returns:
        Exported report string or file confirmation
    """
    generator = ScopeReportGenerator()
    
    if format_type.lower() == "json":
        return generator.export_to_json(report_data, output_path)
    elif format_type.lower() == "csv":
        return generator.export_to_csv(report_data, output_path)
    elif format_type.lower() == "html":
        return generator.export_to_html(report_data, output_path)
    else:
        raise ValueError(f"Unsupported format type: {format_type}")

