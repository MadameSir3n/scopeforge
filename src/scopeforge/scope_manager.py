import json
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, asdict
from urllib.parse import urlparse

@dataclass
class ScopeItem:
    """Represents a single scope item."""
    target: str
    type: str  # 'domain', 'subdomain', 'ip', 'cidr', 'url', 'wildcard'
    included: bool = True
    notes: str = ""
    added_at: str = ""
    
    def __post_init__(self):
        if not self.added_at:
            self.added_at = datetime.now().isoformat()

@dataclass
class ScopeConfig:
    """Represents a complete scope configuration."""
    scope_id: str
    name: str
    description: str
    created_at: str
    updated_at: str
    in_scope: List[ScopeItem]
    out_of_scope: List[ScopeItem]
    rules: Dict[str, Any]
    metadata: Dict[str, Any]
    
    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().isoformat()
        if not self.updated_at:
            self.updated_at = datetime.now().isoformat()

class ScopeManager:
    """
    Manages the full lifecycle of scopes, including creation, updating, and deletion.
    """

    def __init__(self, data_dir: str = "thorncipher/data/scope_forge"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.scopes_file = self.data_dir / "scopes.json"
        self._load_scopes()
    
    def _load_scopes(self):
        """Load scopes from storage."""
        if self.scopes_file.exists():
            try:
                with open(self.scopes_file, 'r') as f:
                    data = json.load(f)
                    self.scopes = {
                        scope_id: ScopeConfig(**scope_data) 
                        for scope_id, scope_data in data.items()
                    }
            except (json.JSONDecodeError, KeyError) as e:
                print(f"Error loading scopes: {e}")
                self.scopes = {}
        else:
            self.scopes = {}
    
    def _save_scopes(self):
        """Save scopes to storage."""
        try:
            data = {
                scope_id: asdict(scope_config) 
                for scope_id, scope_config in self.scopes.items()
            }
            with open(self.scopes_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"Error saving scopes: {e}")
            return False
        return True
    
    def create_scope(self, name: str, description: str = "") -> str:
        """Create a new scope configuration."""
        scope_id = str(uuid.uuid4())
        scope_config = ScopeConfig(
            scope_id=scope_id,
            name=name,
            description=description,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat(),
            in_scope=[],
            out_of_scope=[],
            rules={},
            metadata={}
        )
        
        self.scopes[scope_id] = scope_config
        self._save_scopes()
        return scope_id
    
    def get_scope(self, scope_id: str) -> Optional[ScopeConfig]:
        """Get a scope configuration by ID."""
        return self.scopes.get(scope_id)
    
    def list_scopes(self) -> List[Dict[str, Any]]:
        """List all scope configurations."""
        return [
            {
                "scope_id": scope_id,
                "name": config.name,
                "description": config.description,
                "created_at": config.created_at,
                "in_scope_count": len(config.in_scope),
                "out_of_scope_count": len(config.out_of_scope)
            }
            for scope_id, config in self.scopes.items()
        ]
    
    def delete_scope(self, scope_id: str) -> bool:
        """Delete a scope configuration."""
        if scope_id in self.scopes:
            del self.scopes[scope_id]
            self._save_scopes()
            return True
        return False
    
    def add_scope_item(self, scope_id: str, target: str, item_type: str, 
                      included: bool = True, notes: str = "") -> bool:
        """Add an item to scope."""
        if scope_id not in self.scopes:
            return False
        
        scope_item = ScopeItem(
            target=target,
            type=item_type,
            included=included,
            notes=notes
        )
        
        if included:
            self.scopes[scope_id].in_scope.append(scope_item)
        else:
            self.scopes[scope_id].out_of_scope.append(scope_item)
        
        self.scopes[scope_id].updated_at = datetime.now().isoformat()
        self._save_scopes()
        return True
    
    def remove_scope_item(self, scope_id: str, target: str, included: bool = True) -> bool:
        """Remove an item from scope."""
        if scope_id not in self.scopes:
            return False
        
        scope_list = self.scopes[scope_id].in_scope if included else self.scopes[scope_id].out_of_scope
        
        for i, item in enumerate(scope_list):
            if item.target == target:
                scope_list.pop(i)
                self.scopes[scope_id].updated_at = datetime.now().isoformat()
                self._save_scopes()
                return True
        
        return False
    
    def update_scope_metadata(self, scope_id: str, metadata: Dict[str, Any]) -> bool:
        """Update scope metadata."""
        if scope_id not in self.scopes:
            return False
        
        self.scopes[scope_id].metadata.update(metadata)
        self.scopes[scope_id].updated_at = datetime.now().isoformat()
        self._save_scopes()
        return True
    
    def update_scope_rules(self, scope_id: str, rules: Dict[str, Any]) -> bool:
        """Update scope rules."""
        if scope_id not in self.scopes:
            return False
        
        self.scopes[scope_id].rules.update(rules)
        self.scopes[scope_id].updated_at = datetime.now().isoformat()
        self._save_scopes()
        return True
    
    def get_scope_summary(self, scope_id: str) -> Optional[Dict[str, Any]]:
        """Get a summary of the scope."""
        if scope_id not in self.scopes:
            return None
        
        config = self.scopes[scope_id]
        
        # Count items by type
        in_scope_by_type = {}
        out_of_scope_by_type = {}
        
        for item in config.in_scope:
            in_scope_by_type[item.type] = in_scope_by_type.get(item.type, 0) + 1
        
        for item in config.out_of_scope:
            out_of_scope_by_type[item.type] = out_of_scope_by_type.get(item.type, 0) + 1
        
        return {
            "scope_id": scope_id,
            "name": config.name,
            "description": config.description,
            "created_at": config.created_at,
            "updated_at": config.updated_at,
            "total_in_scope": len(config.in_scope),
            "total_out_of_scope": len(config.out_of_scope),
            "in_scope_by_type": in_scope_by_type,
            "out_of_scope_by_type": out_of_scope_by_type,
            "has_rules": bool(config.rules),
            "metadata_keys": list(config.metadata.keys())
        }
    
    def export_scope(self, scope_id: str, format_type: str = "json") -> Optional[Dict[str, Any]]:
        """Export scope in various formats."""
        if scope_id not in self.scopes:
            return None
        
        config = self.scopes[scope_id]
        
        if format_type.lower() == "json":
            return asdict(config)
        elif format_type.lower() == "simple":
            return {
                "name": config.name,
                "in_scope": [item.target for item in config.in_scope],
                "out_of_scope": [item.target for item in config.out_of_scope]
            }
        elif format_type.lower() == "targets_only":
            return {
                "targets": [item.target for item in config.in_scope if item.included]
            }
        else:
            return asdict(config)
    
    def import_scope_from_dict(self, scope_data: Dict[str, Any]) -> Optional[str]:
        """Import scope from dictionary data."""
        try:
            # Generate new ID if not provided
            if "scope_id" not in scope_data:
                scope_data["scope_id"] = str(uuid.uuid4())
            
            # Convert scope items if they're dictionaries
            if "in_scope" in scope_data:
                scope_data["in_scope"] = [
                    ScopeItem(**item) if isinstance(item, dict) else item
                    for item in scope_data["in_scope"]
                ]
            
            if "out_of_scope" in scope_data:
                scope_data["out_of_scope"] = [
                    ScopeItem(**item) if isinstance(item, dict) else item
                    for item in scope_data["out_of_scope"]
                ]
            
            config = ScopeConfig(**scope_data)
            self.scopes[config.scope_id] = config
            self._save_scopes()
            return config.scope_id
            
        except Exception as e:
            print(f"Error importing scope: {e}")
            return None
    
    def duplicate_scope(self, scope_id: str, new_name: str) -> Optional[str]:
        """Duplicate an existing scope with a new name."""
        if scope_id not in self.scopes:
            return None
        
        original = self.scopes[scope_id]
        new_scope_id = str(uuid.uuid4())
        
        # Create a copy with new ID and name
        scope_data = asdict(original)
        scope_data["scope_id"] = new_scope_id
        scope_data["name"] = new_name
        scope_data["created_at"] = datetime.now().isoformat()
        scope_data["updated_at"] = datetime.now().isoformat()
        
        return self.import_scope_from_dict(scope_data)


# Global instance
scope_manager = ScopeManager()
