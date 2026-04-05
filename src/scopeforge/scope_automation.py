"""
Scope Automation Engine
Advanced scope discovery and validation automation

🔧 Last Modified by Maintainer
📅 Date: 2025-08-01
🛠️ Changes:
- Line 412: Fixed bare except with specific socket.error exception handling
- Line 466: Fixed bare except with proper exception handling
- Line 474: Fixed bare except with specific DNS exception handling
- Line 545: Fixed bare except with IOError exception handling
- Line 676: Fixed bare except with specific exception handling
- Line 687: Fixed bare except with proper exception handling  
- Line 695: Fixed bare except with specific exception handling
"""

import re
import dns.resolver
import socket
import logging
import whois
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set, Tuple
from urllib.parse import urlparse
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

# Set up logging
logger = logging.getLogger(__name__)


class ScopeAutomation:
    """Automated scope generation and management."""
    
    def __init__(self):
        """Initialize the scope automation engine."""
        self.dns_resolver = dns.resolver.Resolver()
        self.dns_resolver.timeout = 5
        self.dns_resolver.lifetime = 10
        logger.info("ScopeAutomation initialized")
    
    def auto_discover_scope(self, initial_targets: List[str], max_depth: int = 2) -> Dict[str, Any]:
        """
        Automatically discover and expand scope based on initial targets.
        
        Args:
            initial_targets: List of initial domains, IPs, or URLs
            max_depth: Maximum discovery depth
            
        Returns:
            Expanded scope configuration
        """
        try:
            discovered_scope = {
                "name": "Auto-discovered Scope",
                "description": f"Automatically discovered from {len(initial_targets)} initial targets",
                "created_at": datetime.now().isoformat(),
                "auto_generated": True,
                "discovery_depth": max_depth,
                "targets": {
                    "domains": set(),
                    "ips": set(),
                    "urls": set(),
                    "networks": set()
                },
                "related_assets": {
                    "subdomains": set(),
                    "ssl_certificates": [],
                    "whois_contacts": [],
                    "technologies": set()
                },
                "metadata": {
                    "discovery_methods": [],
                    "confidence_scores": {},
                    "last_updated": datetime.now().isoformat()
                }
            }
            
            # Process initial targets
            for target in initial_targets:
                self._process_target(target, discovered_scope, max_depth)
            
            # Convert sets to lists for JSON serialization
            for category in discovered_scope["targets"]:
                discovered_scope["targets"][category] = list(discovered_scope["targets"][category])
            
            for category in discovered_scope["related_assets"]:
                if isinstance(discovered_scope["related_assets"][category], set):
                    discovered_scope["related_assets"][category] = list(discovered_scope["related_assets"][category])
            
            logger.info(f"Auto-discovery completed: {sum(len(targets) for targets in discovered_scope['targets'].values())} targets found")
            return discovered_scope
            
        except Exception as e:
            logger.error(f"Error in auto-discovery: {str(e)}")
            raise
    
    def generate_scope_from_organization(self, organization_name: str, include_subsidiaries: bool = True) -> Dict[str, Any]:
        """
        Generate scope based on organization name.
        
        Args:
            organization_name: Name of the organization
            include_subsidiaries: Whether to include subsidiary companies
            
        Returns:
            Generated scope configuration
        """
        try:
            scope = {
                "name": f"Scope for {organization_name}",
                "description": f"Auto-generated scope for {organization_name}",
                "organization": organization_name,
                "created_at": datetime.now().isoformat(),
                "targets": {
                    "domains": [],
                    "ips": [],
                    "urls": [],
                    "networks": []
                },
                "organizational_info": {
                    "primary_domains": [],
                    "subsidiaries": [],
                    "contact_info": {},
                    "business_classification": ""
                }
            }
            
            # Try to find primary domains
            primary_domains = self._find_organization_domains(organization_name)
            scope["organizational_info"]["primary_domains"] = primary_domains
            scope["targets"]["domains"].extend(primary_domains)
            
            # Find subsidiaries if requested
            if include_subsidiaries:
                subsidiaries = self._find_subsidiaries(organization_name)
                scope["organizational_info"]["subsidiaries"] = subsidiaries
                
                for subsidiary in subsidiaries:
                    subsidiary_domains = self._find_organization_domains(subsidiary)
                    scope["targets"]["domains"].extend(subsidiary_domains)
            
            # Remove duplicates
            scope["targets"]["domains"] = list(set(scope["targets"]["domains"]))
            
            logger.info(f"Generated organizational scope with {len(scope['targets']['domains'])} domains")
            return scope
            
        except Exception as e:
            logger.error(f"Error generating organizational scope: {str(e)}")
            raise
    
    def update_scope_dynamically(self, existing_scope: Dict[str, Any], update_interval: str = "daily") -> Dict[str, Any]:
        """
        Update existing scope with newly discovered assets.
        
        Args:
            existing_scope: Existing scope configuration
            update_interval: How often to update ('daily', 'weekly', 'monthly')
            
        Returns:
            Updated scope configuration
        """
        try:
            updated_scope = existing_scope.copy()
            
            # Check when scope was last updated
            last_updated = existing_scope.get("metadata", {}).get("last_updated")
            if last_updated:
                last_update_time = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                
                # Determine if update is needed based on interval
                now = datetime.now()
                update_needed = False
                
                if update_interval == "daily" and (now - last_update_time).days >= 1:
                    update_needed = True
                elif update_interval == "weekly" and (now - last_update_time).days >= 7:
                    update_needed = True
                elif update_interval == "monthly" and (now - last_update_time).days >= 30:
                    update_needed = True
                
                if not update_needed:
                    logger.info("Scope update not needed based on interval")
                    return existing_scope
            
            # Perform incremental discovery
            current_domains = existing_scope.get("targets", {}).get("domains", [])
            new_discoveries = self._incremental_discovery(current_domains)
            
            # Merge new discoveries
            for category, new_targets in new_discoveries.items():
                if category in updated_scope.get("targets", {}):
                    existing_targets = set(updated_scope["targets"][category])
                    existing_targets.update(new_targets)
                    updated_scope["targets"][category] = list(existing_targets)
            
            # Update metadata
            if "metadata" not in updated_scope:
                updated_scope["metadata"] = {}
            
            updated_scope["metadata"]["last_updated"] = datetime.now().isoformat()
            updated_scope["metadata"]["auto_updated"] = True
            updated_scope["metadata"]["update_interval"] = update_interval
            
            logger.info("Dynamic scope update completed")
            return updated_scope
            
        except Exception as e:
            logger.error(f"Error updating scope dynamically: {str(e)}")
            raise
    
    def recommend_scope_improvements(self, scope_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze scope and recommend improvements.
        
        Args:
            scope_data: Current scope configuration
            
        Returns:
            Recommendations for scope improvements
        """
        try:
            recommendations = {
                "analysis_date": datetime.now().isoformat(),
                "scope_id": scope_data.get("id", "unknown"),
                "recommendations": [],
                "risk_analysis": {
                    "missing_exclusions": [],
                    "overly_broad_targets": [],
                    "potential_false_positives": []
                },
                "optimization_suggestions": {
                    "target_consolidation": [],
                    "scope_expansion": [],
                    "precision_improvements": []
                }
            }
            
            # Analyze current targets
            targets = scope_data.get("targets", {})
            exclusions = scope_data.get("exclusions", {})
            
            # Check for missing common exclusions
            self._check_missing_exclusions(targets, exclusions, recommendations)
            
            # Check for overly broad targets
            self._check_broad_targets(targets, recommendations)
            
            # Suggest scope optimizations
            self._suggest_optimizations(targets, recommendations)
            
            # Check for potential security risks
            self._analyze_security_risks(scope_data, recommendations)
            
            logger.info(f"Generated {len(recommendations['recommendations'])} scope recommendations")
            return recommendations
            
        except Exception as e:
            logger.error(f"Error generating scope recommendations: {str(e)}")
            raise
    
    def validate_scope_accessibility(self, scope_data: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
        """
        Validate that targets in scope are accessible.
        
        Args:
            scope_data: Scope configuration to validate
            timeout: Timeout for accessibility checks
            
        Returns:
            Accessibility validation results
        """
        try:
            validation_results = {
                "validation_date": datetime.now().isoformat(),
                "scope_id": scope_data.get("id", "unknown"),
                "accessible_targets": {
                    "domains": [],
                    "ips": [],
                    "urls": []
                },
                "inaccessible_targets": {
                    "domains": [],
                    "ips": [],
                    "urls": []
                },
                "accessibility_stats": {
                    "total_checked": 0,
                    "accessible_count": 0,
                    "inaccessible_count": 0,
                    "accessibility_percentage": 0.0
                },
                "issues_found": []
            }
            
            targets = scope_data.get("targets", {})
            
            # Check domain accessibility
            if "domains" in targets:
                for domain in targets["domains"]:
                    if self._check_domain_accessibility(domain, timeout):
                        validation_results["accessible_targets"]["domains"].append(domain)
                    else:
                        validation_results["inaccessible_targets"]["domains"].append(domain)
                        validation_results["issues_found"].append(f"Domain {domain} is not accessible")
            
            # Check IP accessibility
            if "ips" in targets:
                for ip in targets["ips"]:
                    if self._check_ip_accessibility(ip, timeout):
                        validation_results["accessible_targets"]["ips"].append(ip)
                    else:
                        validation_results["inaccessible_targets"]["ips"].append(ip)
                        validation_results["issues_found"].append(f"IP {ip} is not accessible")
            
            # Check URL accessibility
            if "urls" in targets:
                for url in targets["urls"]:
                    if self._check_url_accessibility(url, timeout):
                        validation_results["accessible_targets"]["urls"].append(url)
                    else:
                        validation_results["inaccessible_targets"]["urls"].append(url)
                        validation_results["issues_found"].append(f"URL {url} is not accessible")
            
            # Calculate statistics
            total_accessible = sum(len(targets) for targets in validation_results["accessible_targets"].values())
            total_inaccessible = sum(len(targets) for targets in validation_results["inaccessible_targets"].values())
            total_checked = total_accessible + total_inaccessible
            
            validation_results["accessibility_stats"]["total_checked"] = total_checked
            validation_results["accessibility_stats"]["accessible_count"] = total_accessible
            validation_results["accessibility_stats"]["inaccessible_count"] = total_inaccessible
            
            if total_checked > 0:
                validation_results["accessibility_stats"]["accessibility_percentage"] = (total_accessible / total_checked) * 100
            
            logger.info(f"Accessibility validation completed: {total_accessible}/{total_checked} targets accessible")
            return validation_results
            
        except Exception as e:
            logger.error(f"Error validating scope accessibility: {str(e)}")
            raise
    
    def discover_targets(self, organization_name: str) -> List[Dict[str, Any]]:
        """Discovers targets dynamically based on organization name."""
        discovered_targets = []
        try:
            response = requests.get(f"https://api.example.com/discover?org={organization_name}")
            if response.status_code == 200:
                discovered_targets = response.json()
        except requests.RequestException as e:
            logger.error(f"Error during discovery: {e}")
        return discovered_targets

    def validate_accessibility(self, targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Validates accessibility of discovered targets."""
        validated_targets = []
        for target in targets:
            try:
                response = requests.head(target["url"], timeout=5)
                target["accessible"] = response.status_code == 200
            except requests.RequestException:
                target["accessible"] = False
            validated_targets.append(target)
        return validated_targets
    
    def _process_target(self, target: str, scope_data: Dict[str, Any], depth: int):
        """Process a single target and discover related assets."""
        if depth <= 0:
            return
        
        try:
            # Determine target type
            if self._is_ip(target):
                scope_data["targets"]["ips"].add(target)
                self._discover_from_ip(target, scope_data, depth - 1)
            elif self._is_url(target):
                scope_data["targets"]["urls"].add(target)
                self._discover_from_url(target, scope_data, depth - 1)
            else:
                # Assume it's a domain
                scope_data["targets"]["domains"].add(target)
                self._discover_from_domain(target, scope_data, depth - 1)
        
        except Exception as e:
            logger.warning(f"Error processing target {target}: {str(e)}")
    
    def _discover_from_domain(self, domain: str, scope_data: Dict[str, Any], depth: int):
        """Discover assets from a domain."""
        try:
            # Find subdomains
            subdomains = self._find_subdomains(domain)
            scope_data["related_assets"]["subdomains"].update(subdomains)
            scope_data["targets"]["domains"].update(subdomains)
            
            # Get IP addresses
            ips = self._resolve_domain_ips(domain)
            scope_data["targets"]["ips"].update(ips)
            
            # Get SSL certificate info
            ssl_info = self._get_ssl_certificate_info(domain)
            if ssl_info:
                scope_data["related_assets"]["ssl_certificates"].append(ssl_info)
            
            # Get WHOIS information
            whois_info = self._get_whois_info(domain)
            if whois_info:
                scope_data["related_assets"]["whois_contacts"].append(whois_info)
            
        except Exception as e:
            logger.warning(f"Error discovering from domain {domain}: {str(e)}")
    
    def _discover_from_ip(self, ip: str, scope_data: Dict[str, Any], depth: int):
        """Discover assets from an IP address."""
        try:
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                scope_data["targets"]["domains"].add(hostname)
            except (socket.error, OSError) as e:
                logger.debug(f"Reverse DNS lookup failed for {ip}: {e}")
                pass
            
            # Check for virtual hosts (simplified)
            virtual_hosts = self._find_virtual_hosts(ip)
            scope_data["targets"]["domains"].update(virtual_hosts)
            
        except Exception as e:
            logger.warning(f"Error discovering from IP {ip}: {str(e)}")
    
    def _discover_from_url(self, url: str, scope_data: Dict[str, Any], depth: int):
        """Discover assets from a URL."""
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            
            if domain:
                scope_data["targets"]["domains"].add(domain)
                self._discover_from_domain(domain, scope_data, depth)
            
        except Exception as e:
            logger.warning(f"Error discovering from URL {url}: {str(e)}")
    
    def _find_subdomains(self, domain: str) -> Set[str]:
        """Find subdomains using various techniques."""
        subdomains = set()
        
        try:
            # Common subdomain list
            common_subs = [
                'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
                'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'mobile', 'm', 'dev',
                'test', 'staging', 'admin', 'api', 'blog', 'shop', 'secure', 'vpn'
            ]
            
            for sub in common_subs:
                subdomain = f"{sub}.{domain}"
                if self._check_domain_exists(subdomain):
                    subdomains.add(subdomain)
            
        except Exception as e:
            logger.warning(f"Error finding subdomains for {domain}: {str(e)}")
        
        return subdomains
    
    def _resolve_domain_ips(self, domain: str) -> Set[str]:
        """Resolve domain to IP addresses."""
        ips = set()
        
        try:
            # Use socket for basic resolution
            try:
                ip = socket.gethostbyname(domain)
                ips.add(ip)
            except (socket.error, OSError) as e:
                logger.debug(f"DNS resolution failed for {domain}: {e}")
                pass
            
            # Try to get all addresses
            try:
                _, _, addresses = socket.gethostbyname_ex(domain)
                for addr in addresses:
                    ips.add(addr)
            except (socket.error, OSError) as e:
                logger.debug(f"Extended DNS resolution failed for {domain}: {e}")
                pass
            
        except Exception as e:
            logger.warning(f"Error resolving IPs for {domain}: {str(e)}")
        
        return ips
    
    def _get_ssl_certificate_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get SSL certificate information."""
        try:
            import ssl
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    if not cert:
                        return None
                    
                    # Safely extract subject and issuer information
                    subject_dict = {}
                    if cert.get('subject'):
                        for item in cert['subject']:
                            if isinstance(item, tuple) and len(item) >= 2:
                                subject_dict[item[0]] = item[1]
                    
                    issuer_dict = {}
                    if cert.get('issuer'):
                        for item in cert['issuer']:
                            if isinstance(item, tuple) and len(item) >= 2:
                                issuer_dict[item[0]] = item[1]
                    
                    return {
                        "domain": domain,
                        "subject": subject_dict,
                        "issuer": issuer_dict,
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }
        except Exception:
            return None
    
    def _get_whois_info(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS information."""
        try:
            w = whois.whois(domain)
            return {
                "domain": domain,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date),
                "expiration_date": str(w.expiration_date),
                "name_servers": w.name_servers,
                "emails": w.emails
            }
        except Exception:
            return None
    
    def _find_virtual_hosts(self, ip: str) -> Set[str]:
        """Find virtual hosts on an IP."""
        # This is a simplified implementation
        # In practice, you might use tools like virtual-host-discovery
        return set()
    
    def _check_domain_exists(self, domain: str) -> bool:
        """Check if a domain exists."""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.error, OSError):
            return False
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        try:
            socket.inet_aton(target)
            return True
        except socket.error:
            return False
    
    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        return target.startswith(('http://', 'https://'))
    
    def _incremental_discovery(self, existing_domains: List[str]) -> Dict[str, Set[str]]:
        """Perform incremental discovery on existing domains."""
        new_discoveries = {
            "domains": set(),
            "ips": set(),
            "urls": set()
        }
        
        for domain in existing_domains:
            try:
                # Find new subdomains
                subdomains = self._find_subdomains(domain)
                new_discoveries["domains"].update(subdomains)
                
                # Resolve new IPs
                ips = self._resolve_domain_ips(domain)
                new_discoveries["ips"].update(ips)
                
            except Exception as e:
                logger.warning(f"Error in incremental discovery for {domain}: {str(e)}")
        
        return new_discoveries
    
    def _find_organization_domains(self, organization: str) -> List[str]:
        """Find domains associated with an organization."""
        # This is a simplified implementation
        # In practice, you might use commercial APIs or databases
        domains = []
        
        # Simple heuristic: try common domain patterns
        org_name = organization.lower().replace(' ', '').replace(',', '').replace('.', '')
        common_tlds = ['.com', '.org', '.net', '.io', '.co']
        
        for tld in common_tlds:
            potential_domain = f"{org_name}{tld}"
            if self._check_domain_exists(potential_domain):
                domains.append(potential_domain)
        
        return domains
    
    def _find_subsidiaries(self, organization: str) -> List[str]:
        """Find subsidiary companies."""
        # This is a placeholder implementation
        # In practice, you might use business intelligence APIs
        return []
    
    def _check_missing_exclusions(self, targets: Dict, exclusions: Dict, recommendations: Dict):
        """Check for commonly missing exclusions."""
        common_exclusions = [
            'localhost',
            '127.0.0.1',
            '*.local',
            '*.test',
            '*.dev',
            '*.example.com'
        ]
        
        current_exclusions = set()
        for exclusion_list in exclusions.values():
            current_exclusions.update(exclusion_list)
        
        for exclusion in common_exclusions:
            if exclusion not in current_exclusions:
                recommendations["risk_analysis"]["missing_exclusions"].append(exclusion)
                recommendations["recommendations"].append({
                    "type": "exclusion",
                    "priority": "medium",
                    "suggestion": f"Consider excluding {exclusion}",
                    "rationale": "Common development/test target that should typically be excluded"
                })
    
    def _check_broad_targets(self, targets: Dict, recommendations: Dict):
        """Check for overly broad target specifications."""
        for domain in targets.get("domains", []):
            if domain.startswith("*."):
                base_domain = domain[2:]
                recommendations["risk_analysis"]["overly_broad_targets"].append(domain)
                recommendations["recommendations"].append({
                    "type": "precision",
                    "priority": "high",
                    "suggestion": f"Wildcard domain {domain} may be too broad",
                    "rationale": "Wildcard domains can include unintended subdomains"
                })
    
    def _suggest_optimizations(self, targets: Dict, recommendations: Dict):
        """Suggest scope optimizations."""
        # Check for duplicate or overlapping targets
        domains = targets.get("domains", [])
        for i, domain1 in enumerate(domains):
            for domain2 in domains[i+1:]:
                if domain1 in domain2 or domain2 in domain1:
                    recommendations["optimization_suggestions"]["target_consolidation"].append({
                        "overlapping_targets": [domain1, domain2],
                        "suggestion": "Consider consolidating overlapping domains"
                    })
    
    def _analyze_security_risks(self, scope_data: Dict, recommendations: Dict):
        """Analyze security risks in the scope."""
        targets = scope_data.get("targets", {})
        
        # Check for high-risk domains
        high_risk_indicators = ['.gov', '.mil', '.edu']
        for domain in targets.get("domains", []):
            if any(indicator in domain.lower() for indicator in high_risk_indicators):
                recommendations["recommendations"].append({
                    "type": "security",
                    "priority": "critical",
                    "suggestion": f"High-risk domain detected: {domain}",
                    "rationale": "Government, military, or educational domains require special authorization"
                })
    
    def _check_domain_accessibility(self, domain: str, timeout: int) -> bool:
        """Check if domain is accessible."""
        try:
            socket.gethostbyname(domain)
            return True
        except (socket.error, OSError):
            return False
    
    def _check_ip_accessibility(self, ip: str, timeout: int) -> bool:
        """Check if IP is accessible."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, 80))
            sock.close()
            return result == 0
        except (socket.error, OSError):
            return False
    
    def _check_url_accessibility(self, url: str, timeout: int) -> bool:
        """Check if URL is accessible."""
        try:
            response = requests.head(url, timeout=timeout, allow_redirects=True)
            return response.status_code < 400
        except (requests.RequestException, requests.exceptions.Timeout, ConnectionError):
            return False


# Convenience functions
def auto_discover_scope(initial_targets: List[str], max_depth: int = 2) -> Dict[str, Any]:
    """Quick function for auto-discovery."""
    automation = ScopeAutomation()
    return automation.auto_discover_scope(initial_targets, max_depth)


def generate_org_scope(organization_name: str, include_subsidiaries: bool = True) -> Dict[str, Any]:
    """Quick function for organizational scope generation."""
    automation = ScopeAutomation()
    return automation.generate_scope_from_organization(organization_name, include_subsidiaries)


def validate_scope_accessibility(scope_data: Dict[str, Any], timeout: int = 10) -> Dict[str, Any]:
    """Quick function for scope accessibility validation."""
    automation = ScopeAutomation()
    return automation.validate_scope_accessibility(scope_data, timeout)
