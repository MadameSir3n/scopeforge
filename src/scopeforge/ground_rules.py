from typing import Dict, List, Any, Optional
from datetime import datetime
import json
from pathlib import Path

class GroundRules:
    """Manages testing ground rules and compliance guidelines."""
    
    def __init__(self):
        self.default_rules = {
            'general': {
                'respect_robots_txt': True,
                'respect_rate_limits': True,
                'no_destructive_testing': True,
                'no_social_engineering': True,
                'no_physical_access': True,
                'report_findings_responsibly': True
            },
            'network': {
                'no_dos_attacks': True,
                'no_network_flooding': True,
                'respect_bandwidth_limits': True,
                'no_lateral_movement': True,
                'max_concurrent_connections': 10
            },
            'web_application': {
                'no_account_takeover': True,
                'no_data_destruction': True,
                'no_privilege_escalation': True,
                'respect_user_data': True,
                'no_spam_creation': True,
                'max_requests_per_second': 5
            },
            'data_handling': {
                'no_data_exfiltration': True,
                'no_pii_access': True,
                'secure_evidence_storage': True,
                'data_retention_limit_days': 30,
                'encrypt_sensitive_findings': True
            },
            'reporting': {
                'immediate_critical_findings': True,
                'regular_status_updates': True,
                'detailed_final_report': True,
                'include_remediation_steps': True,
                'proof_of_concept_only': True
            },
            'legal': {
                'stay_within_scope': True,
                'follow_local_laws': True,
                'respect_third_party_systems': True,
                'no_unauthorized_access': True,
                'maintain_confidentiality': True
            }
        }
        
        self.severity_levels = {
            'critical': {
                'description': 'Immediate threat to system security',
                'response_time_hours': 4,
                'escalation_required': True
            },
            'high': {
                'description': 'Significant security vulnerability',
                'response_time_hours': 24,
                'escalation_required': True
            },
            'medium': {
                'description': 'Moderate security concern',
                'response_time_hours': 72,
                'escalation_required': False
            },
            'low': {
                'description': 'Minor security issue',
                'response_time_hours': 168,
                'escalation_required': False
            },
            'info': {
                'description': 'Informational finding',
                'response_time_hours': 336,
                'escalation_required': False
            }
        }
    
    def get_default_rules(self) -> Dict[str, Any]:
        """Get the default set of ground rules."""
        return self.default_rules.copy()
    
    def create_custom_rules(self, base_rules: str = "default") -> Dict[str, Any]:
        """Create a custom rule set based on a template."""
        if base_rules == "default":
            return self.default_rules.copy()
        elif base_rules == "minimal":
            return {
                'general': {
                    'no_destructive_testing': True,
                    'report_findings_responsibly': True
                },
                'legal': {
                    'stay_within_scope': True,
                    'follow_local_laws': True
                }
            }
        elif base_rules == "strict":
            rules = self.default_rules.copy()
            rules['network']['max_concurrent_connections'] = 3
            rules['web_application']['max_requests_per_second'] = 1
            rules['data_handling']['data_retention_limit_days'] = 7
            return rules
        else:
            return self.default_rules.copy()
    
    def validate_rules_compliance(self, scan_config: Dict[str, Any], 
                                 rules: Dict[str, Any]) -> Dict[str, Any]:
        """Validate if a scan configuration complies with the rules."""
        compliance_result = {
            'compliant': True,
            'violations': [],
            'warnings': [],
            'recommendations': []
        }
        
        # Check rate limiting compliance
        if 'web_application' in rules:
            max_rps = rules['web_application'].get('max_requests_per_second', 5)
            scan_rps = scan_config.get('requests_per_second', 1)
            
            if scan_rps > max_rps:
                compliance_result['violations'].append(
                    f"Request rate {scan_rps} exceeds limit of {max_rps}"
                )
                compliance_result['compliant'] = False
        
        # Check concurrent connections
        if 'network' in rules:
            max_conn = rules['network'].get('max_concurrent_connections', 10)
            scan_conn = scan_config.get('concurrent_connections', 1)
            
            if scan_conn > max_conn:
                compliance_result['violations'].append(
                    f"Concurrent connections {scan_conn} exceeds limit of {max_conn}"
                )
                compliance_result['compliant'] = False
        
        # Check destructive testing
        if rules.get('general', {}).get('no_destructive_testing', True):
            if scan_config.get('include_destructive_tests', False):
                compliance_result['violations'].append(
                    "Destructive testing is not allowed"
                )
                compliance_result['compliant'] = False
        
        # Check scope compliance
        if rules.get('legal', {}).get('stay_within_scope', True):
            if not scan_config.get('scope_validated', False):
                compliance_result['warnings'].append(
                    "Scope validation recommended before testing"
                )
        
        return compliance_result
    
    def get_testing_guidelines(self, test_type: str) -> Dict[str, Any]:
        """Get specific guidelines for different types of testing."""
        guidelines = {
            'passive_reconnaissance': {
                'description': 'Information gathering without direct interaction',
                'allowed_techniques': [
                    'DNS enumeration',
                    'WHOIS lookup',
                    'Search engine dorking',
                    'Social media research',
                    'Certificate transparency logs'
                ],
                'restrictions': [
                    'No direct contact with target systems',
                    'Use public information only',
                    'Respect rate limits on public APIs'
                ],
                'tools_suggested': ['nslookup', 'dig', 'whois', 'shodan']
            },
            'active_scanning': {
                'description': 'Direct interaction with target systems',
                'allowed_techniques': [
                    'Port scanning',
                    'Service enumeration',
                    'Vulnerability scanning',
                    'Web application scanning'
                ],
                'restrictions': [
                    'Limit scan intensity',
                    'Avoid DoS conditions',
                    'Respect robots.txt',
                    'Monitor system impact'
                ],
                'tools_suggested': ['nmap', 'masscan', 'nikto', 'dirb']
            },
            'web_application': {
                'description': 'Testing web applications for vulnerabilities',
                'allowed_techniques': [
                    'Input validation testing',
                    'Authentication testing',
                    'Session management testing',
                    'Configuration testing'
                ],
                'restrictions': [
                    'No account takeover',
                    'No data modification',
                    'No privilege escalation',
                    'Limit automated testing'
                ],
                'tools_suggested': ['thornbite', 'owasp-zap', 'sqlmap', 'gobuster']
            },
            'network_penetration': {
                'description': 'Testing network security controls',
                'allowed_techniques': [
                    'Firewall testing',
                    'IDS/IPS evasion',
                    'Protocol fuzzing',
                    'Wireless testing'
                ],
                'restrictions': [
                    'No network disruption',
                    'No unauthorized access',
                    'No lateral movement',
                    'Document all activities'
                ],
                'tools_suggested': ['metasploit', 'aircrack-ng', 'wireshark', 'hping3']
            }
        }
        
        return guidelines.get(test_type, {
            'description': 'Unknown test type',
            'restrictions': ['Follow general ground rules']
        })
    
    def generate_rules_document(self, rules: Dict[str, Any], 
                               project_name: str = "Security Assessment") -> str:
        """Generate a formatted rules document."""
        doc = f"# Ground Rules for {project_name}\n\n"
        doc += f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        doc += "## Overview\n"
        doc += "This document outlines the ground rules and guidelines for the security assessment.\n\n"
        
        for category, category_rules in rules.items():
            doc += f"## {category.replace('_', ' ').title()}\n\n"
            
            for rule_name, rule_value in category_rules.items():
                if isinstance(rule_value, bool):
                    status = "✅ Required" if rule_value else "❌ Prohibited"
                    doc += f"- **{rule_name.replace('_', ' ').title()}**: {status}\n"
                else:
                    doc += f"- **{rule_name.replace('_', ' ').title()}**: {rule_value}\n"
            
            doc += "\n"
        
        doc += "## Severity Levels\n\n"
        for level, details in self.severity_levels.items():
            doc += f"### {level.upper()}\n"
            doc += f"- **Description**: {details['description']}\n"
            doc += f"- **Response Time**: {details['response_time_hours']} hours\n"
            doc += f"- **Escalation Required**: {'Yes' if details['escalation_required'] else 'No'}\n\n"
        
        doc += "## Compliance\n"
        doc += "All testing activities must comply with these ground rules. "
        doc += "Any violations must be reported immediately to the project manager.\n\n"
        
        return doc
    
    def check_finding_severity(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Check and validate finding severity based on rules."""
        severity = finding.get('severity', 'info').lower()
        
        if severity not in self.severity_levels:
            return {
                'valid': False,
                'message': f"Invalid severity level: {severity}",
                'suggested_severity': 'info'
            }
        
        severity_info = self.severity_levels[severity]
        
        result = {
            'valid': True,
            'severity': severity,
            'response_time_hours': severity_info['response_time_hours'],
            'escalation_required': severity_info['escalation_required'],
            'description': severity_info['description']
        }
        
        # Check if escalation is needed
        if severity_info['escalation_required']:
            result['escalation_message'] = f"This {severity} finding requires immediate escalation"
        
        return result
    
    def get_compliance_checklist(self) -> List[Dict[str, Any]]:
        """Get a compliance checklist for testing activities."""
        checklist = [
            {
                'category': 'Pre-Testing',
                'items': [
                    'Scope clearly defined and approved',
                    'Ground rules reviewed and accepted',
                    'Emergency contacts established',
                    'Testing windows scheduled',
                    'Backup and rollback procedures documented'
                ]
            },
            {
                'category': 'During Testing',
                'items': [
                    'Stay within approved scope',
                    'Monitor system impact',
                    'Document all activities',
                    'Report critical findings immediately',
                    'Respect rate limits and restrictions'
                ]
            },
            {
                'category': 'Post-Testing',
                'items': [
                    'Secure all evidence',
                    'Clean up test artifacts',
                    'Submit detailed report',
                    'Provide remediation recommendations',
                    'Schedule findings review meeting'
                ]
            }
        ]
        
        return checklist
    
    def export_rules(self, rules: Dict[str, Any], format_type: str = "json") -> str:
        """Export rules in various formats."""
        if format_type.lower() == "json":
            return json.dumps(rules, indent=2)
        elif format_type.lower() == "markdown":
            return self.generate_rules_document(rules)
        else:
            return json.dumps(rules, indent=2)
    
    def check_compliance(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check compliance with ground rules for a given scope.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Compliance check results
        """
        compliance_result = {
            'compliant': True,
            'violations': [],
            'warnings': [],
            'recommendations': [],
            'risk_level': 'low',
            'checked_at': datetime.now().isoformat()
        }
        
        # Check authorization requirements
        if not scope_data.get('authorized', False):
            compliance_result['violations'].append({
                'rule': 'authorization_required',
                'severity': 'critical',
                'message': 'Testing without proper authorization is prohibited'
            })
            compliance_result['compliant'] = False
            compliance_result['risk_level'] = 'critical'
        
        # Check for high-risk targets
        targets = scope_data.get('targets', {})
        high_risk_domains = self._identify_high_risk_targets(targets)
        if high_risk_domains:
            compliance_result['violations'].append({
                'rule': 'high_risk_targets',
                'severity': 'high',
                'message': f'High-risk targets detected: {", ".join(high_risk_domains)}'
            })
            compliance_result['risk_level'] = 'high'
        
        # Check rate limiting
        rate_limiting = scope_data.get('rate_limiting', {})
        if not rate_limiting.get('enabled', False):
            compliance_result['warnings'].append({
                'rule': 'rate_limiting_recommended',
                'severity': 'medium',
                'message': 'Rate limiting is recommended to minimize impact'
            })
        
        # Check business hours restriction
        if not scope_data.get('business_hours_only', False) and high_risk_domains:
            compliance_result['warnings'].append({
                'rule': 'business_hours_recommended',
                'severity': 'medium',
                'message': 'Business hours restriction recommended for high-risk targets'
            })
        
        # Check exclusions
        exclusions = scope_data.get('exclusions', {})
        if not any(exclusions.values()):
            compliance_result['recommendations'].append({
                'rule': 'exclusions_recommended',
                'severity': 'low',
                'message': 'Consider defining appropriate exclusions'
            })
        
        return compliance_result
    
    def validate_authorization(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate authorization for the scope.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Authorization validation results
        """
        auth_result = {
            'authorized': False,
            'authorization_level': 'none',
            'requirements_met': [],
            'missing_requirements': [],
            'notes': []
        }
        
        # Check if scope is marked as authorized
        if scope_data.get('authorized', False):
            auth_result['authorized'] = True
            auth_result['authorization_level'] = 'basic'
            auth_result['requirements_met'].append('scope_authorized')
        else:
            auth_result['missing_requirements'].append('scope_authorization')
        
        # Check for legal constraints documentation
        if scope_data.get('legal_constraints'):
            auth_result['requirements_met'].append('legal_constraints_documented')
        else:
            auth_result['missing_requirements'].append('legal_constraints_documentation')
        
        # Check for contact information
        contact_info = scope_data.get('contact_info', {})
        if contact_info.get('primary_contact'):
            auth_result['requirements_met'].append('contact_information')
        else:
            auth_result['missing_requirements'].append('contact_information')
        
        # Determine authorization level
        if len(auth_result['requirements_met']) >= 3:
            auth_result['authorization_level'] = 'full'
        elif len(auth_result['requirements_met']) >= 2:
            auth_result['authorization_level'] = 'partial'
        
        return auth_result
    
    def enforce_business_hours(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check business hours enforcement requirements.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Business hours enforcement results
        """
        bh_result = {
            'compliant': True,
            'business_hours_required': False,
            'current_restriction': False,
            'recommendations': [],
            'risk_factors': []
        }
        
        # Check current setting
        bh_result['current_restriction'] = scope_data.get('business_hours_only', False)
        
        # Determine if business hours should be required
        targets = scope_data.get('targets', {})
        high_risk_targets = self._identify_high_risk_targets(targets)
        
        if high_risk_targets:
            bh_result['business_hours_required'] = True
            bh_result['risk_factors'].append('high_risk_targets_present')
            
            if not bh_result['current_restriction']:
                bh_result['compliant'] = False
                bh_result['recommendations'].append(
                    'Enable business hours restriction for high-risk targets'
                )
        
        # Check for production systems
        if self._has_production_indicators(scope_data):
            bh_result['business_hours_required'] = True
            bh_result['risk_factors'].append('production_systems_detected')
            
            if not bh_result['current_restriction']:
                bh_result['compliant'] = False
                bh_result['recommendations'].append(
                    'Enable business hours restriction for production systems'
                )
        
        return bh_result
    
    def check_rate_limiting_requirements(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check rate limiting requirements for the scope.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Rate limiting requirements results
        """
        rl_result = {
            'rate_limiting_required': True,  # Always recommended
            'current_setting': False,
            'recommended_limits': {},
            'justification': []
        }
        
        # Check current rate limiting setting
        rate_limiting = scope_data.get('rate_limiting', {})
        rl_result['current_setting'] = rate_limiting.get('enabled', False)
        
        # Determine recommended limits based on scope
        targets = scope_data.get('targets', {})
        target_count = sum(len(target_list) for target_list in targets.values())
        
        if target_count > 100:
            rl_result['recommended_limits'] = {
                'requests_per_second': 2,
                'burst_limit': 10,
                'justification': 'Large scope requires conservative rate limiting'
            }
        elif target_count > 20:
            rl_result['recommended_limits'] = {
                'requests_per_second': 5,
                'burst_limit': 25,
                'justification': 'Medium scope requires moderate rate limiting'
            }
        else:
            rl_result['recommended_limits'] = {
                'requests_per_second': 10,
                'burst_limit': 50,
                'justification': 'Small scope allows higher rate limits'
            }
        
        # Add justifications
        rl_result['justification'].append('Rate limiting reduces impact on target systems')
        rl_result['justification'].append('Helps maintain good relationship with target organization')
        
        if self._identify_high_risk_targets(targets):
            rl_result['justification'].append('High-risk targets require extra caution')
            # Reduce recommended limits for high-risk targets
            current_rps = rl_result['recommended_limits']['requests_per_second']
            rl_result['recommended_limits']['requests_per_second'] = max(1, current_rps // 2)
        
        return rl_result
    
    def enforce_rules(self, scope_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enforces ground rules on the provided scope data."""
        enforced_scope = []
        for item in scope_data:
            if self._is_compliant(item):
                enforced_scope.append(item)
        return enforced_scope

    def _is_compliant(self, item: Dict[str, Any]) -> bool:
        """Checks if a scope item complies with ground rules."""
        # Example compliance logic
        if item.get("type") in ["domain", "ip", "url"]:
            return True
        return False
    
    def _identify_high_risk_targets(self, targets: Dict[str, List[str]]) -> List[str]:
        """Identify high-risk targets in the scope."""
        high_risk = []
        high_risk_indicators = ['.gov', '.mil', '.edu', 'bank', 'financial', 'healthcare']
        
        for domain in targets.get('domains', []):
            if any(indicator in domain.lower() for indicator in high_risk_indicators):
                high_risk.append(domain)
        
        return high_risk
    
    def _has_production_indicators(self, scope_data: Dict[str, Any]) -> bool:
        """Check if scope has indicators of production systems."""
        targets = scope_data.get('targets', {})
        
        # Check for production-like domain patterns
        production_indicators = ['www.', 'api.', 'app.', 'prod.', 'production.']
        for domain in targets.get('domains', []):
            if any(indicator in domain.lower() for indicator in production_indicators):
                return True
        
        # Check if scope explicitly mentions production
        description = scope_data.get('description', '').lower()
        if any(term in description for term in ['production', 'live', 'customer-facing']):
            return True
        
        return False
        

# Global instance
ground_rules = GroundRules()
