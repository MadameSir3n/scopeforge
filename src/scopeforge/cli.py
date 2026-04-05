#!/usr/bin/env python3
"""
ScopeForge CLI - Command line interface for scope management
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

from .scope_manager import ScopeManager
from .scope_parser import ScopeParser
from .scope_validator import ScopeValidator


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="ScopeForge - Advanced scope management")
    subparsers = parser.add_subparsers(dest="command", help="Command to execute")
    
    # Create scope command
    create_parser = subparsers.add_parser("create", help="Create a new scope")
    create_parser.add_argument("name", help="Name of the scope")
    create_parser.add_argument("--description", help="Scope description", default="")
    
    # List scopes command
    list_parser = subparsers.add_parser("list", help="List all scopes")
    
    # Parse scope command
    parse_parser = subparsers.add_parser("parse", help="Parse scope targets")
    parse_parser.add_argument("targets", nargs="+", help="Targets to parse")
    
    # Validate scope command
    validate_parser = subparsers.add_parser("validate", help="Validate scope targets")
    validate_parser.add_argument("targets", nargs="+", help="Targets to validate")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    try:
        if args.command == "create":
            manager = ScopeManager()
            scope_id = manager.create_scope(args.name, args.description)
            print(f"Created scope '{args.name}' with ID: {scope_id}")
            
        elif args.command == "list":
            manager = ScopeManager()
            scopes = manager.list_scopes()
            if not scopes:
                print("No scopes found")
            else:
                for scope_id, scope in scopes.items():
                    print(f"{scope_id}: {scope['name']} - {scope['description']}")
                    
        elif args.command == "parse":
            parser = ScopeParser()
            results = []
            for target in args.targets:
                result = parser.parse_target(target)
                results.append(result)
            print(json.dumps(results, indent=2))
            
        elif args.command == "validate":
            validator = ScopeValidator()
            results = []
            for target in args.targets:
                result = validator.validate_target(target)
                results.append(result)
            print(json.dumps(results, indent=2))
            
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()