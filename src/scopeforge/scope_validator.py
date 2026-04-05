import re
import socket
import ipaddress
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urlparse

try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

from .scope_parser import ScopeParser

class ScopeValidator:
    """Validates scope configurations and checks for potential issues."""
    
    def __init__(self):
        self.private_ranges = [
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12'),
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('127.0.0.0/8'),
            ipaddress.ip_network('169.254.0.0/16'),
            ipaddress.ip_network('::1/128'),
            ipaddress.ip_network('fc00::/7'),
            ipaddress.ip_network('fe80::/10')
        ]
        
        self.dangerous_tlds = [
            '.gov', '.mil', '.edu', '.bank', '.finance'
        ]
        
        self.common_exclusions = [
            'localhost',
            '127.0.0.1',
            '::1',
            '0.0.0.0'
        ]
    
    def validate_scope_config(self, scope_config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate a complete scope configuration."""
        results = {
            'valid': True,
            'warnings': [],
            'errors': [],
            'recommendations': [],
            'statistics': {},
            'risk_assessment': 'low'
        }
        
        # Validate in-scope targets
        if 'in_scope' in scope_config:
            in_scope_results = self.validate_target_list(scope_config['in_scope'])
            results['warnings'].extend(in_scope_results['warnings'])
            results['errors'].extend(in_scope_results['errors'])
            results['statistics']['in_scope'] = in_scope_results['statistics']
        
        # Validate out-of-scope targets
        if 'out_of_scope' in scope_config:
            out_scope_results = self.validate_target_list(scope_config['out_of_scope'])
            results['warnings'].extend(out_scope_results['warnings'])
            results['errors'].extend(out_scope_results['errors'])
            results['statistics']['out_of_scope'] = out_scope_results['statistics']
        
        # Check for overlaps and conflicts
        if 'in_scope' in scope_config and 'out_of_scope' in scope_config:
            conflicts = self.check_scope_conflicts(
                scope_config['in_scope'], 
                scope_config['out_of_scope']
            )
            results['warnings'].extend(conflicts)
        
        # Generate recommendations
        results['recommendations'] = self.generate_recommendations(scope_config)
        
        # Assess overall risk
        results['risk_assessment'] = self.assess_risk_level(results)
        
        # Mark as invalid if there are errors
        if results['errors']:
            results['valid'] = False
        
        return results
    
    def validate_target_list(self, targets: List[str]) -> Dict[str, Any]:
        """Validate a list of targets."""
        results = {
            'valid_count': 0,
            'invalid_count': 0,
            'warnings': [],
            'errors': [],
            'statistics': {
                'by_type': {},
                'total_targets': len(targets),
                'private_ips': 0,
                'public_ips': 0,
                'domains': 0,
                'wildcards': 0
            }
        }
        
        for target in targets:
            validation = self.validate_single_target(target)
            
            if validation['valid']:
                results['valid_count'] += 1
                target_type = validation['type']
                results['statistics']['by_type'][target_type] = \
                    results['statistics']['by_type'].get(target_type, 0) + 1
                
                # Update statistics
                if target_type == 'ip':
                    properties = validation.get('properties', {})
                    if properties.get('is_private', False):
                        results['statistics']['private_ips'] += 1
                    else:
                        results['statistics']['public_ips'] += 1
                elif target_type == 'domain':
                    results['statistics']['domains'] += 1
                elif target_type == 'wildcard':
                    results['statistics']['wildcards'] += 1
            else:
                results['invalid_count'] += 1
                results['errors'].append(f"Invalid target: {target}")
            
            results['warnings'].extend(validation.get('warnings', []))
            results['errors'].extend(validation.get('errors', []))
        
        return results
    
    def validate_single_target(self, target: str) -> Dict[str, Any]:
        """Validate a single target."""
        parsed = ScopeParser().parse_target(target)
        
        validation_result = {
            'target': target,
            'valid': parsed['valid'],
            'type': parsed['type'],
            'warnings': [],
            'errors': []
        }
        
        if not parsed['valid']:
            validation_result['errors'].append(f"Invalid format: {target}")
            return validation_result
        
        # Type-specific validation
        target_type = parsed['type']
        
        if target_type == 'ip':
            validation_result.update(self._validate_ip_target(target, parsed))
        elif target_type == 'domain':
            validation_result.update(self._validate_domain_target(target, parsed))
        elif target_type == 'wildcard':
            validation_result.update(self._validate_wildcard_target(target, parsed))
        elif target_type == 'cidr':
            validation_result.update(self._validate_cidr_target(target, parsed))
        elif target_type == 'url':
            validation_result.update(self._validate_url_target(target, parsed))
        
        return validation_result
    
    def _validate_ip_target(self, target: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Validate IP address target."""
        result = {'warnings': [], 'errors': [], 'properties': {}}
        
        try:
            ip = ipaddress.ip_address(target)
            result['properties']['is_private'] = ip.is_private
            
            # Check if it's a private IP
            if ip.is_private:
                result['warnings'].append(f"Private IP address: {target}")
            
            # Check if it's localhost
            if ip.is_loopback:
                result['warnings'].append(f"Localhost IP: {target}")
            
            # Check if it's multicast
            if ip.is_multicast:
                result['warnings'].append(f"Multicast IP: {target}")
            
        except ValueError as e:
            result['errors'].append(f"Invalid IP address {target}: {str(e)}")
        
        return result
    
    def _validate_domain_target(self, target: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Validate domain target."""
        result = {'warnings': [], 'errors': [], 'properties': {}}
        
        # Check for dangerous TLDs
        for dangerous_tld in self.dangerous_tlds:
            if target.lower().endswith(dangerous_tld):
                result['warnings'].append(f"Potentially sensitive domain TLD: {target}")
        
        # Check for localhost
        if target.lower() in ['localhost', 'localhost.localdomain']:
            result['warnings'].append(f"Localhost domain: {target}")
        
        # Try to resolve the domain (optional, may be slow)
        try:
            socket.gethostbyname(target)
            result['properties']['resolvable'] = True
        except socket.gaierror:
            result['properties']['resolvable'] = False
            result['warnings'].append(f"Domain does not resolve: {target}")
        
        return result
    
    def _validate_wildcard_target(self, target: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Validate wildcard domain target."""
        result = {'warnings': [], 'errors': []}
        
        base_domain = target[2:]  # Remove *.
        
        # Check if wildcard is on a TLD
        if '.' not in base_domain:
            result['errors'].append(f"Wildcard on TLD not allowed: {target}")
        
        # Check for dangerous TLDs
        for dangerous_tld in self.dangerous_tlds:
            if base_domain.lower().endswith(dangerous_tld):
                result['warnings'].append(f"Wildcard on sensitive TLD: {target}")
        
        # Check if base domain is too broad
        if base_domain.count('.') == 0:  # Only TLD
            result['warnings'].append(f"Very broad wildcard scope: {target}")
        
        return result
    
    def _validate_cidr_target(self, target: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Validate CIDR target."""
        result = {'warnings': [], 'errors': [], 'properties': {}}
        
        try:
            network = ipaddress.ip_network(target, strict=False)
            
            # Check if it's a private network
            if network.is_private:
                result['warnings'].append(f"Private network range: {target}")
                result['properties']['is_private'] = True
            
            # Check for overly broad ranges
            if network.prefixlen < 16:
                result['warnings'].append(f"Very broad network range: {target}")
            
            # Check if it includes localhost
            localhost = ipaddress.ip_address('127.0.0.1')
            if localhost in network:
                result['warnings'].append(f"Network includes localhost: {target}")
            
        except ValueError as e:
            result['errors'].append(f"Invalid CIDR notation {target}: {str(e)}")
        
        return result
    
    def _validate_url_target(self, target: str, parsed: Dict[str, Any]) -> Dict[str, Any]:
        """Validate URL target."""
        result = {'warnings': [], 'errors': []}
        
        try:
            parsed_url = urlparse(target)
            
            # Validate the hostname part
            if parsed_url.hostname:
                hostname_validation = self._validate_domain_target(
                    parsed_url.hostname, {}
                )
                result['warnings'].extend(hostname_validation['warnings'])
                result['errors'].extend(hostname_validation['errors'])
            
            # Check for non-standard ports
            if parsed_url.port and parsed_url.port not in [80, 443]:
                result['warnings'].append(f"Non-standard port in URL: {target}")
            
        except Exception as e:
            result['errors'].append(f"Invalid URL {target}: {str(e)}")
        
        return result
    
    def check_scope_conflicts(self, in_scope: List[str], out_of_scope: List[str]) -> List[str]:
        """Check for conflicts between in-scope and out-of-scope targets."""
        conflicts = []
        
        for in_target in in_scope:
            for out_target in out_of_scope:
                if self._targets_overlap(in_target, out_target):
                    conflicts.append(
                        f"Scope conflict: '{in_target}' (in-scope) overlaps with "
                        f"'{out_target}' (out-of-scope)"
                    )
        
        return conflicts
    
    def _targets_overlap(self, target1: str, target2: str) -> bool:
        """Check if two targets overlap."""
        # Simple overlap detection - can be enhanced
        
        # Exact match
        if target1.lower() == target2.lower():
            return True
        
        # Check wildcard overlaps
        if target1.startswith('*.') and target2.endswith(target1[2:]):
            return True
        if target2.startswith('*.') and target1.endswith(target2[2:]):
            return True
        
        # Check CIDR overlaps (basic)
        try:
            if '/' in target1 and '/' in target2:
                net1 = ipaddress.ip_network(target1, strict=False)
                net2 = ipaddress.ip_network(target2, strict=False)
                return net1.overlaps(net2)
        except ValueError:
            pass
        
        return False
    
    def generate_recommendations(self, scope_config: Dict[str, Any]) -> List[str]:
        """Generate recommendations for improving the scope."""
        recommendations = []
        
        # Check if out-of-scope is defined
        if 'out_of_scope' not in scope_config or not scope_config['out_of_scope']:
            recommendations.append(
                "Consider defining out-of-scope targets to clarify boundaries"
            )
        
        # Check for common exclusions
        in_scope = scope_config.get('in_scope', [])
        out_of_scope = scope_config.get('out_of_scope', [])
        
        for exclusion in self.common_exclusions:
            if any(exclusion in target for target in in_scope):
                if not any(exclusion in target for target in out_of_scope):
                    recommendations.append(
                        f"Consider explicitly excluding '{exclusion}'"
                    )
        
        # Check for overly broad wildcards
        wildcards = [t for t in in_scope if t.startswith('*.')]
        if len(wildcards) > 3:
            recommendations.append(
                "Consider reducing the number of wildcard domains for better focus"
            )
        
        return recommendations
    
    def assess_risk_level(self, validation_results: Dict[str, Any]) -> str:
        """Assess the overall risk level of the scope."""
        error_count = len(validation_results.get('errors', []))
        warning_count = len(validation_results.get('warnings', []))
        
        if error_count > 0:
            return 'high'
        elif warning_count > 5:
            return 'medium'
        elif warning_count > 0:
            return 'low'
        else:
            return 'minimal'
    
    def check_legal_compliance(self, scope_config: Dict[str, Any]) -> Dict[str, Any]:
        """Check for potential legal compliance issues."""
        compliance_issues = {
            'critical': [],
            'warnings': [],
            'recommendations': []
        }
        
        in_scope = scope_config.get('in_scope', [])
        
        # Check for government/military domains
        for target in in_scope:
            for sensitive_tld in ['.gov', '.mil']:
                if target.lower().endswith(sensitive_tld):
                    compliance_issues['critical'].append(
                        f"Government/military domain in scope: {target}"
                    )
        
        # Check for educational domains
        for target in in_scope:
            if target.lower().endswith('.edu'):
                compliance_issues['warnings'].append(
                    f"Educational domain in scope: {target}"
                )
        
        # Check for financial domains
        for target in in_scope:
            if any(keyword in target.lower() for keyword in ['bank', 'finance', 'credit']):
                compliance_issues['warnings'].append(
                    f"Potentially financial domain in scope: {target}"
                )
        
        return compliance_issues
    
    def validate_scope(self, scope_data: Dict[str, Any]) -> Tuple[bool, List[str]]:
        """
        Validate a scope configuration and return validation status and errors.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []
        
        # Check required fields
        if not scope_data.get('name'):
            errors.append("Scope name is required")
        
        if not scope_data.get('targets'):
            errors.append("Scope must have targets defined")
        
        # Check authorization
        if not scope_data.get('authorized', False):
            errors.append("Scope must be authorized before testing")
        
        # Validate targets
        targets = scope_data.get('targets', {})
        for target_type, target_list in targets.items():
            for target in target_list:
                if not self._validate_target(target, target_type):
                    errors.append(f"Invalid {target_type}: {target}")
        
        # Check for dangerous targets
        if self._has_dangerous_targets(scope_data):
            errors.append("Scope contains high-risk targets that require special authorization")
        
        return len(errors) == 0, errors
    
    def validate_targets(self, targets: List[str]) -> List[str]:
        """Validate a list of targets and return valid ones."""
        valid_targets = []
        for target in targets:
            if self._validate_target(target):
                valid_targets.append(target)
        return valid_targets
    
    def check_compliance(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Check compliance of scope configuration.
        
        Args:
            scope_data: Scope configuration dictionary
            
        Returns:
            Compliance check results
        """
        compliance = {
            'score': 0,
            'max_score': 100,
            'checks': {},
            'recommendations': []
        }
        
        # Authorization check (30 points)
        if scope_data.get('authorized', False):
            compliance['score'] += 30
            compliance['checks']['authorization'] = 'passed'
        else:
            compliance['checks']['authorization'] = 'failed'
            compliance['recommendations'].append('Obtain proper authorization before testing')
        
        # Legal constraints check (20 points)
        if scope_data.get('legal_constraints'):
            compliance['score'] += 20
            compliance['checks']['legal_constraints'] = 'passed'
        else:
            compliance['checks']['legal_constraints'] = 'warning'
            compliance['recommendations'].append('Define legal constraints and limitations')
        
        # Business hours check (15 points)
        if scope_data.get('business_hours_only', False):
            compliance['score'] += 15
            compliance['checks']['business_hours'] = 'passed'
        else:
            compliance['checks']['business_hours'] = 'warning'
            compliance['recommendations'].append('Consider restricting testing to business hours')
        
        # Rate limiting check (15 points)
        rate_limiting = scope_data.get('rate_limiting', {})
        if rate_limiting.get('enabled', False):
            compliance['score'] += 15
            compliance['checks']['rate_limiting'] = 'passed'
        else:
            compliance['checks']['rate_limiting'] = 'warning'
            compliance['recommendations'].append('Enable rate limiting to minimize impact')
        
        # Exclusions check (20 points)
        exclusions = scope_data.get('exclusions', {})
        has_exclusions = any(exclusions.values())
        if has_exclusions:
            compliance['score'] += 20
            compliance['checks']['exclusions'] = 'passed'
        else:
            compliance['checks']['exclusions'] = 'warning'
            compliance['recommendations'].append('Define appropriate exclusions')
        
        return compliance
    
    def validate_scope_items(self, scope_data: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validates scope data and returns compliance results."""
        validation_results = []
        for item in scope_data:
            validation_results.append(self._validate_item(item))
        return validation_results

    def _validate_item(self, item: Dict[str, Any]) -> Dict[str, Any]:
        """Validates a single scope item."""
        try:
            if item.get("type") == "ip":
                ipaddress.ip_address(item["target"])
                return {"target": item["target"], "valid": True}
            elif item.get("type") == "domain":
                if re.match(r'^[a-zA-Z0-9.-]+$', item["target"]):
                    return {"target": item["target"], "valid": True}
            elif item.get("type") == "url":
                parsed_url = urlparse(item["target"])
                if parsed_url.scheme and parsed_url.netloc:
                    return {"target": item["target"], "valid": True}
        except Exception:
            pass
        return {"target": item["target"], "valid": False}
    
    def _validate_target(self, target: str, target_type: Optional[str] = None) -> bool:
        """Validate a single target."""
        if not target or not isinstance(target, str):
            return False
        
        # Use scope parser for validation
        parser = ScopeParser()
        parsed = parser.parse_target(target)
        return parsed['valid']
    
    def _has_dangerous_targets(self, scope_data: Dict[str, Any]) -> bool:
        """Check if scope contains dangerous/high-risk targets."""
        targets = scope_data.get('targets', {})
        
        # Check domains for dangerous TLDs
        for domain in targets.get('domains', []):
            if any(tld in domain.lower() for tld in self.dangerous_tlds):
                return True
        
        return False


# Global instance
scope_validator = ScopeValidator()
