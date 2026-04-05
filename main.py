"""
ScopeForge
Entry point: parse and validate bug bounty scope targets.

Usage:
    pip install -e .
    python main.py parse "*.acme.com" "10.0.0.0/8"
    python main.py validate "admin.acme.com"

    Or use the installed CLI:
    scopeforge parse "*.acme.com"
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from scopeforge.cli import main

if __name__ == "__main__":
    main()
