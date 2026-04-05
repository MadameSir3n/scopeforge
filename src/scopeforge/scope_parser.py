import re
import ipaddress
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional, Any
import json

class ScopeParser:
    """Parses various scope formats and normalizes them."""
    
    def __init__(self):
        # Common patterns for different scope types
        self.patterns = {
            'ip': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$'),
            'cidr': re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'),
            'domain': re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'),
            'wildcard': re.compile(r'^\*\..*'),
            'url': re.compile(r'^https?://.*'),
            'port_range': re.compile(r'^(\d+)-(\d+)$'),
            'single_port': re.compile(r'^\d+$')
        }
    
    def parse_target(self, target: str) -> Dict[str, Any]:
        """Parse a single target and determine its type and properties."""
        target = target.strip()
        
        result = {
            'original': target,
            'normalized': target,
            'type': 'unknown',
            'valid': False,
            'properties': {}
        }
        
        # Check for IP address
        if self.patterns['ip'].match(target):
            result.update({
                'type': 'ip',
                'valid': self._validate_ip(target),
                'normalized': target,
                'properties': {'ip_version': 4}
            })
        
        # Check for CIDR
        elif self.patterns['cidr'].match(target):
            result.update({
                'type': 'cidr',
                'valid': self._validate_cidr(target),
                'normalized': target,
                'properties': self._parse_cidr_properties(target)
            })
        
        # Check for wildcard domain
        elif self.patterns['wildcard'].match(target):
            domain = target[2:]  # Remove *.
            result.update({
                'type': 'wildcard',
                'valid': self._validate_domain(domain),
                'normalized': target.lower(),
                'properties': {'base_domain': domain.lower()}
            })
        
        # Check for URL
        elif self.patterns['url'].match(target):
            result.update({
                'type': 'url',
                'valid': self._validate_url(target),
                'normalized': target.lower(),
                'properties': self._parse_url_properties(target)
            })
        
        # Check for domain
        elif self.patterns['domain'].match(target):
            result.update({
                'type': 'domain',
                'valid': self._validate_domain(target),
                'normalized': target.lower(),
                'properties': self._parse_domain_properties(target)
            })
        
        # Check for port or port range
        elif self.patterns['single_port'].match(target) or self.patterns['port_range'].match(target):
            result.update({
                'type': 'port',
                'valid': self._validate_port(target),
                'normalized': target,
                'properties': self._parse_port_properties(target)
            })
        
        return result
    
    def parse_scope_list(self, targets: List[str]) -> Dict[str, List[Dict[str, Any]]]:
        """Parse a list of targets and categorize them."""
        results = {
            'valid': [],
            'invalid': [],
            'warnings': []
        }
        
        for target in targets:
            parsed = self.parse_target(target)
            
            if parsed['valid']:
                results['valid'].append(parsed)
            else:
                results['invalid'].append(parsed)
            
            # Check for potential issues
            warnings = self._check_target_warnings(parsed)
            if warnings:
                results['warnings'].extend(warnings)
        
        return results
    
    def parse_scope_from_text(self, text: str) -> Dict[str, List[Dict[str, Any]]]:
        """Parse scope from plain text (newline or comma separated)."""
        # Split by newlines and commas, then clean up
        targets = []
        for line in text.split('\n'):
            for item in line.split(','):
                item = item.strip()
                if item and not item.startswith('#'):  # Skip comments
                    targets.append(item)
        
        return self.parse_scope_list(targets)
    
    def parse_scope_from_json(self, json_data: str) -> Dict[str, Any]:
        """Parse scope from JSON format."""
        try:
            data = json.loads(json_data)
            
            if isinstance(data, dict):
                results = {
                    'in_scope': {'valid': [], 'invalid': [], 'warnings': []},
                    'out_of_scope': {'valid': [], 'invalid': [], 'warnings': []},
                    'metadata': data.get('metadata', {})
                }
                
                # Parse in-scope targets
                if 'in_scope' in data:
                    results['in_scope'] = self.parse_scope_list(data['in_scope'])
                
                # Parse out-of-scope targets
                if 'out_of_scope' in data:
                    results['out_of_scope'] = self.parse_scope_list(data['out_of_scope'])
                
                return results
            
            elif isinstance(data, list):
                # Simple list format
                return {'targets': self.parse_scope_list(data)}
            
            else:
                return {'error': 'Invalid JSON format'}
            
        except json.JSONDecodeError as e:
            return {'error': f'Invalid JSON: {str(e)}'}
    
    def parse_thornbite_scope(self, thornbite_config: Dict[str, Any]) -> Dict[str, Any]:
        """Parse Thornbite scope configuration."""
        results = {
            'in_scope': {'valid': [], 'invalid': [], 'warnings': []},
            'out_of_scope': {'valid': [], 'invalid': [], 'warnings': []}
        }
        
        try:
            # Parse include rules
            if 'target' in thornbite_config and 'scope' in thornbite_config['target']:
                scope = thornbite_config['target']['scope']
                
                if 'include' in scope:
                    for rule in scope['include']:
                        target = self._extract_thornbite_target(rule)
                        if target:
                            parsed = self.parse_target(target)
                            if parsed['valid']:
                                results['in_scope']['valid'].append(parsed)
                            else:
                                results['in_scope']['invalid'].append(parsed)
                
                if 'exclude' in scope:
                    for rule in scope['exclude']:
                        target = self._extract_thornbite_target(rule)
                        if target:
                            parsed = self.parse_target(target)
                            if parsed['valid']:
                                results['out_of_scope']['valid'].append(parsed)
                            else:
                                results['out_of_scope']['invalid'].append(parsed)
        
        except Exception as e:
            return {'error': f'Error parsing Thornbite scope: {str(e)}'}
        
        return results

    def parse_burp_scope(self, burp_config: Dict[str, Any]) -> Dict[str, Any]:
        """Backward-compatible alias for parse_thornbite_scope."""
        return self.parse_thornbite_scope(burp_config)
    
    def _validate_ip(self, ip: str) -> bool:
        """Validate IP address."""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_cidr(self, cidr: str) -> bool:
        """Validate CIDR notation."""
        try:
            ipaddress.ip_network(cidr, strict=False)
            return True
        except ValueError:
            return False
    
    def _validate_domain(self, domain: str) -> bool:
        """Validate domain name."""
        if not domain or len(domain) > 253:
            return False
        
        if domain.endswith('.'):
            domain = domain[:-1]
        
        allowed = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$')
        return all(allowed.match(label) for label in domain.split('.'))
    
    def _validate_url(self, url: str) -> bool:
        """Validate URL."""
        try:
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _validate_port(self, port_str: str) -> bool:
        """Validate port or port range."""
        if self.patterns['single_port'].match(port_str):
            port = int(port_str)
            return 1 <= port <= 65535
        
        elif self.patterns['port_range'].match(port_str):
            start, end = map(int, port_str.split('-'))
            return 1 <= start <= end <= 65535
        
        return False
    
    def _parse_cidr_properties(self, cidr: str) -> Dict[str, Any]:
        """Parse CIDR properties."""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            return {
                'network_address': str(network.network_address),
                'broadcast_address': str(network.broadcast_address),
                'netmask': str(network.netmask),
                'prefix_length': network.prefixlen,
                'num_addresses': network.num_addresses,
                'is_private': network.is_private
            }
        except ValueError:
            return {}
    
    def _parse_url_properties(self, url: str) -> Dict[str, Any]:
        """Parse URL properties."""
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme,
                'hostname': parsed.hostname,
                'port': parsed.port,
                'path': parsed.path,
                'query': parsed.query,
                'fragment': parsed.fragment
            }
        except Exception:
            return {}
    
    def _parse_domain_properties(self, domain: str) -> Dict[str, Any]:
        """Parse domain properties."""
        parts = domain.lower().split('.')
        return {
            'tld': parts[-1] if parts else '',
            'sld': parts[-2] if len(parts) > 1 else '',
            'subdomain_count': len(parts) - 2 if len(parts) > 2 else 0,
            'is_subdomain': len(parts) > 2,
            'root_domain': '.'.join(parts[-2:]) if len(parts) > 1 else domain
        }
    
    def _parse_port_properties(self, port_str: str) -> Dict[str, Any]:
        """Parse port properties."""
        if self.patterns['single_port'].match(port_str):
            port = int(port_str)
            return {
                'port': port,
                'type': 'single',
                'well_known': port < 1024,
                'service': self._get_common_service(port)
            }
        
        elif self.patterns['port_range'].match(port_str):
            start, end = map(int, port_str.split('-'))
            return {
                'start_port': start,
                'end_port': end,
                'type': 'range',
                'count': end - start + 1
            }
        
        return {}
    
    def _get_common_service(self, port: int) -> Optional[str]:
        """Get common service name for port."""
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            993: 'IMAPS',
            995: 'POP3S'
        }
        return common_ports.get(port)
    
    def _check_target_warnings(self, parsed_target: Dict[str, Any]) -> List[str]:
        """Check for potential warnings about the target."""
        warnings = []
        target_type = parsed_target['type']
        properties = parsed_target.get('properties', {})
        
        # Check for private IP ranges
        if target_type == 'ip' and properties.get('is_private'):
            warnings.append(f"Private IP address: {parsed_target['original']}")
        
        # Check for overly broad CIDR ranges
        if target_type == 'cidr' and properties.get('prefix_length', 32) < 16:
            warnings.append(f"Very broad CIDR range: {parsed_target['original']}")
        
        # Check for wildcard domains on TLDs
        if target_type == 'wildcard':
            base_domain = properties.get('base_domain', '')
            if '.' not in base_domain:
                warnings.append(f"Wildcard on TLD: {parsed_target['original']}")
        
        return warnings
    
    def _extract_thornbite_target(self, rule: Dict[str, Any]) -> Optional[str]:
        """Extract target from Thornbite rule."""
        try:
            if 'host' in rule:
                host = rule['host']
                if rule.get('protocol') and rule.get('port'):
                    return f"{rule['protocol']}://{host}:{rule['port']}"
                elif rule.get('protocol'):
                    return f"{rule['protocol']}://{host}"
                else:
                    return host
        except Exception:
            pass
        return None

    def _extract_burp_target(self, rule: Dict[str, Any]) -> Optional[str]:
        """Backward-compatible alias for _extract_thornbite_target."""
        return self._extract_thornbite_target(rule)
    
    def parse_domains(self, targets: List[str]) -> List[str]:
        """Parse and extract valid domains from a list of targets."""
        domains = []
        for target in targets:
            parsed = self.parse_target(target)
            if parsed['valid'] and parsed['type'] in ['domain', 'subdomain']:
                domains.append(parsed['normalized'])
            elif parsed['type'] == 'url':
                # Extract domain from URL
                try:
                    from urllib.parse import urlparse
                    domain = urlparse(target).netloc
                    if domain:
                        domains.append(domain)
                except:
                    pass
        return domains
    
    def parse_ips(self, targets: List[str]) -> List[str]:
        """Parse and extract valid IP addresses from a list of targets."""
        ips = []
        for target in targets:
            parsed = self.parse_target(target)
            if parsed['valid'] and parsed['type'] == 'ip':
                ips.append(parsed['normalized'])
        return ips
    
    def parse_urls(self, targets: List[str]) -> List[str]:
        """Parse and extract valid URLs from a list of targets."""
        urls = []
        for target in targets:
            parsed = self.parse_target(target)
            if parsed['valid'] and parsed['type'] == 'url':
                urls.append(parsed['normalized'])
        return urls
    
    def parse_networks(self, targets: List[str]) -> List[str]:
        """Parse and extract valid network ranges from a list of targets."""
        networks = []
        for target in targets:
            parsed = self.parse_target(target)
            if parsed['valid'] and parsed['type'] == 'cidr':
                networks.append(parsed['normalized'])
        return networks
    
    def normalize_targets(self, targets: List[str]) -> List[str]:
        """Normalize a list of targets."""
        normalized = []
        for target in targets:
            parsed = self.parse_target(target)
            if parsed['valid']:
                normalized.append(parsed['normalized'])
        return normalized
    
    def parse_scope(self, scope_data: List[str]) -> List[Dict[str, Any]]:
        """Parses scope data into structured items."""
        parsed_items = []
        for item in scope_data:
            parsed = self._parse_item(item)
            if parsed:
                parsed_items.append(parsed)
        return parsed_items

    def _parse_item(self, item: str) -> Optional[Dict[str, Any]]:
        """Parses a single scope item."""
        for scope_type, pattern in self.patterns.items():
            if pattern.match(item):
                return {
                    "target": item,
                    "type": scope_type
                }
        return None


# Global instance
scope_parser = ScopeParser()
