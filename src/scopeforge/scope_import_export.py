"""
Scope Import/Export Module for ThornCipher

This module provides functionality to import and export scope configurations
from various formats and external sources.
"""

import json
import csv
import yaml
import xml.etree.ElementTree as ET
import logging
from typing import Dict, List, Any, Optional, Union
from pathlib import Path
import io

# Set up logging
logger = logging.getLogger(__name__)


class ScopeImportExport:
    """Handle import and export of scope configurations."""
    
    def __init__(self):
        """Initialize the import/export handler."""
        self.supported_formats = ['json', 'csv', 'yaml', 'xml', 'nessus', 'nmap']
        self.format_handlers = {
            'json': {'import': self._import_json, 'export': self._export_json},
            'csv': {'import': self._import_csv, 'export': self._export_csv},
            'yaml': {'import': self._import_yaml, 'export': self._export_yaml},
            'xml': {'import': self._import_xml, 'export': self._export_xml},
            'nessus': {'import': self._import_nessus, 'export': None},
            'nmap': {'import': self._import_nmap, 'export': self._export_nmap}
        }
        logger.info("ScopeImportExport initialized")
    
    def import_scope(self, file_path: str, format_type: str = "auto") -> Dict[str, Any]:
        """
        Import scope configuration from a file.
        
        Args:
            file_path: Path to the file to import
            format_type: Format of the file ('auto', 'json', 'csv', 'yaml', 'xml', 'nessus', 'nmap')
            
        Returns:
            Dictionary containing the imported scope configuration
        """
        try:
            if format_type == "auto":
                format_type = self._detect_format(file_path)
            
            if format_type not in self.supported_formats:
                raise ValueError(f"Unsupported format: {format_type}")
            
            handler = self.format_handlers[format_type]['import']
            if handler is None:
                raise ValueError(f"Import not supported for format: {format_type}")
            
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            scope_data = handler(content)
            logger.info(f"Successfully imported scope from {file_path} (format: {format_type})")
            return scope_data
            
        except Exception as e:
            logger.error(f"Error importing scope from {file_path}: {str(e)}")
            raise
    
    def export_scope(self, scope_data: Dict[str, Any], file_path: str, format_type: str = "json") -> bool:
        """
        Export scope configuration to a file.
        
        Args:
            scope_data: Scope configuration to export
            file_path: Path where to save the exported file
            format_type: Format for export ('json', 'csv', 'yaml', 'xml', 'nmap')
            
        Returns:
            True if export was successful
        """
        try:
            if format_type not in self.supported_formats:
                raise ValueError(f"Unsupported export format: {format_type}")
            
            handler = self.format_handlers[format_type]['export']
            if handler is None:
                raise ValueError(f"Export not supported for format: {format_type}")
            
            content = handler(scope_data)
            
            Path(file_path).parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, 'w', encoding='utf-8') as f:
                f.write(content)
            
            logger.info(f"Successfully exported scope to {file_path} (format: {format_type})")
            return True
            
        except Exception as e:
            logger.error(f"Error exporting scope to {file_path}: {str(e)}")
            raise
    
    def import_from_nmap(self, nmap_xml_path: str) -> Dict[str, Any]:
        """
        Import scope from Nmap XML output.
        
        Args:
            nmap_xml_path: Path to Nmap XML file
            
        Returns:
            Scope configuration extracted from Nmap results
        """
        return self.import_scope(nmap_xml_path, "nmap")
    
    def import_from_nessus(self, nessus_file_path: str) -> Dict[str, Any]:
        """
        Import scope from Nessus .nessus file.
        
        Args:
            nessus_file_path: Path to Nessus file
            
        Returns:
            Scope configuration extracted from Nessus results
        """
        return self.import_scope(nessus_file_path, "nessus")
    
    def export_to_nmap_targets(self, scope_data: Dict[str, Any], output_path: str) -> bool:
        """
        Export scope targets in Nmap-compatible format.
        
        Args:
            scope_data: Scope configuration
            output_path: Path to save Nmap targets file
            
        Returns:
            True if export was successful
        """
        return self.export_scope(scope_data, output_path, "nmap")
    
    def batch_import(self, file_paths: List[str]) -> List[Dict[str, Any]]:
        """
        Import multiple scope files at once.
        
        Args:
            file_paths: List of file paths to import
            
        Returns:
            List of imported scope configurations
        """
        imported_scopes = []
        
        for file_path in file_paths:
            try:
                scope_data = self.import_scope(file_path)
                imported_scopes.append(scope_data)
            except Exception as e:
                logger.warning(f"Failed to import {file_path}: {str(e)}")
                continue
        
        logger.info(f"Batch import completed: {len(imported_scopes)}/{len(file_paths)} files imported")
        return imported_scopes
    
    def _detect_format(self, file_path: str) -> str:
        """Detect file format based on extension and content."""
        file_path_obj = Path(file_path)
        extension = file_path_obj.suffix.lower()
        
        format_map = {
            '.json': 'json',
            '.csv': 'csv',
            '.yaml': 'yaml',
            '.yml': 'yaml',
            '.xml': 'xml',
            '.nessus': 'nessus'
        }
        
        if extension in format_map:
            return format_map[extension]
        
        # Try to detect based on content
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read(1000)  # Read first 1KB
            
            if content.strip().startswith('{') or content.strip().startswith('['):
                return 'json'
            elif content.strip().startswith('<?xml') or '<nmaprun' in content:
                if 'nessus' in content.lower():
                    return 'nessus'
                elif 'nmaprun' in content:
                    return 'nmap'
                else:
                    return 'xml'
            elif ',' in content and '\n' in content:
                return 'csv'
            else:
                return 'yaml'
                
        except Exception:
            return 'json'  # Default fallback
    
    def import_scope_data(self, file_path: str, format: str = "json") -> Union[List[Dict[str, Any]], None]:
        """Imports scope data from a file."""
        if format == "json":
            return self._import_json(file_path)
        elif format == "csv":
            return self._import_csv(file_path)
        else:
            logger.error(f"Unsupported format: {format}")
            return None

    def export_scope_data(self, scope_data: List[Dict[str, Any]], file_path: str, format: str = "json") -> None:
        """Exports scope data to a file."""
        if format == "json":
            self._export_json(scope_data, file_path)
        elif format == "csv":
            self._export_csv(scope_data, file_path)
        else:
            logger.error(f"Unsupported format: {format}")

    def _import_json(self, file_path: str) -> List[Dict[str, Any]]:
        """Imports scope data from a JSON file."""
        with open(file_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _import_csv(self, file_path: str) -> List[Dict[str, Any]]:
        """Imports scope data from a CSV file."""
        scope_data = []
        with open(file_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                scope_data.append(row)
        return scope_data

    def _export_json(self, scope_data: List[Dict[str, Any]], file_path: str) -> None:
        """Exports scope data to a JSON file."""
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(scope_data, f, indent=2)

    def _export_csv(self, scope_data: List[Dict[str, Any]], file_path: str) -> None:
        """Exports scope data to a CSV file."""
        with open(file_path, "w", encoding="utf-8", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["target", "type"])
            writer.writeheader()
            writer.writerows(scope_data)
    
    def _import_yaml(self, content: str) -> Dict[str, Any]:
        """Import from YAML format."""
        try:
            import yaml
            return yaml.safe_load(content)
        except ImportError:
            raise ImportError("PyYAML is required for YAML import/export")
    
    def _export_yaml(self, scope_data: Dict[str, Any]) -> str:
        """Export to YAML format."""
        try:
            import yaml
            return yaml.dump(scope_data, default_flow_style=False, indent=2)
        except ImportError:
            raise ImportError("PyYAML is required for YAML import/export")
    
    def _import_xml(self, content: str) -> Dict[str, Any]:
        """Import from XML format."""
        root = ET.fromstring(content)
        
        scope_data = {
            "name": root.get('name', 'Imported from XML'),
            "description": "Scope imported from XML file",
            "targets": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            },
            "exclusions": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            }
        }
        
        # Parse targets
        for target_elem in root.findall('.//target'):
            target_type = target_elem.get('type', '').lower()
            target_value = target_elem.text or target_elem.get('value', '')
            is_excluded = target_elem.get('excluded', '').lower() in ['true', 'yes', '1']
            
            if target_value:
                category = 'exclusions' if is_excluded else 'targets'
                
                if target_type in ['domain', 'domains']:
                    scope_data[category]['domains'].append(target_value)
                elif target_type in ['ip', 'ips']:
                    scope_data[category]['ips'].append(target_value)
                elif target_type in ['url', 'urls']:
                    scope_data[category]['urls'].append(target_value)
                elif target_type in ['network', 'networks']:
                    scope_data[category]['networks'].append(target_value)
        
        return scope_data
    
    def _export_xml(self, scope_data: Dict[str, Any]) -> str:
        """Export to XML format."""
        root = ET.Element('scope')
        root.set('name', scope_data.get('name', 'Exported Scope'))
        root.set('description', scope_data.get('description', ''))
        
        # Add targets
        targets_elem = ET.SubElement(root, 'targets')
        targets = scope_data.get('targets', {})
        
        for target_type, target_list in targets.items():
            for target in target_list:
                target_elem = ET.SubElement(targets_elem, 'target')
                target_elem.set('type', target_type)
                target_elem.text = target
        
        # Add exclusions
        exclusions_elem = ET.SubElement(root, 'exclusions')
        exclusions = scope_data.get('exclusions', {})
        
        for target_type, target_list in exclusions.items():
            for target in target_list:
                target_elem = ET.SubElement(exclusions_elem, 'target')
                target_elem.set('type', target_type)
                target_elem.set('excluded', 'true')
                target_elem.text = target
        
        return ET.tostring(root, encoding='unicode', xml_declaration=True)
    
    def _import_nmap(self, content: str) -> Dict[str, Any]:
        """Import from Nmap XML output."""
        root = ET.fromstring(content)
        
        scope_data = {
            "name": "Imported from Nmap",
            "description": f"Scope imported from Nmap scan: {root.get('start', '')}",
            "targets": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            },
            "exclusions": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            },
            "scan_results": {
                "scanner": "nmap",
                "version": root.get('version', ''),
                "start_time": root.get('start', ''),
                "args": root.get('args', '')
            }
        }
        
        # Extract hosts
        for host in root.findall('.//host'):
            # Get IP address
            addr_elem = host.find('.//address[@addrtype="ipv4"]')
            if addr_elem is not None:
                ip = addr_elem.get('addr')
                if ip:
                    scope_data['targets']['ips'].append(ip)
            
            # Get hostnames
            for hostname in host.findall('.//hostname'):
                name = hostname.get('name')
                if name:
                    scope_data['targets']['domains'].append(name)
        
        return scope_data
    
    def _export_nmap(self, scope_data: Dict[str, Any]) -> str:
        """Export targets in Nmap-compatible format."""
        targets = []
        
        # Add IPs and networks
        targets.extend(scope_data.get('targets', {}).get('ips', []))
        targets.extend(scope_data.get('targets', {}).get('networks', []))
        targets.extend(scope_data.get('targets', {}).get('domains', []))
        
        return '\n'.join(targets)
    
    def _import_nessus(self, content: str) -> Dict[str, Any]:
        """Import from Nessus .nessus file."""
        root = ET.fromstring(content)
        
        scope_data = {
            "name": "Imported from Nessus",
            "description": "Scope imported from Nessus scan file",
            "targets": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            },
            "exclusions": {
                "domains": [],
                "ips": [],
                "urls": [],
                "networks": []
            },
            "scan_results": {
                "scanner": "nessus",
                "policy_name": "",
                "scan_name": ""
            }
        }
        
        # Extract policy info
        policy = root.find('.//Policy')
        if policy is not None:
            policy_name = policy.find('.//policyName')
            if policy_name is not None:
                scope_data['scan_results']['policy_name'] = policy_name.text
        
        # Extract targets from report hosts
        for report_host in root.findall('.//ReportHost'):
            host_name = report_host.get('name')
            if host_name:
                # Check if it's an IP or domain
                if any(char.isalpha() for char in host_name):
                    scope_data['targets']['domains'].append(host_name)
                else:
                    scope_data['targets']['ips'].append(host_name)
        
        return scope_data


# Convenience functions
def import_scope_from_file(file_path: str, format_type: str = "auto") -> Dict[str, Any]:
    """Quick function to import scope from a file."""
    importer = ScopeImportExport()
    return importer.import_scope(file_path, format_type)


def export_scope_to_file(scope_data: Dict[str, Any], file_path: str, format_type: str = "json") -> bool:
    """Quick function to export scope to a file."""
    exporter = ScopeImportExport()
    return exporter.export_scope(scope_data, file_path, format_type)


def convert_scope_format(input_path: str, output_path: str, input_format: str = "auto", output_format: str = "json") -> bool:
    """
    Convert scope file from one format to another.
    
    Args:
        input_path: Path to input file
        output_path: Path to output file
        input_format: Input file format
        output_format: Output file format
        
    Returns:
        True if conversion was successful
    """
    try:
        scope_data = import_scope_from_file(input_path, input_format)
        return export_scope_to_file(scope_data, output_path, output_format)
    except Exception as e:
        logger.error(f"Error converting scope format: {str(e)}")
        return False
