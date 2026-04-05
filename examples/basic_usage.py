"""
ScopeForge Basic Usage Example
================================
Demonstrates the core scope lifecycle: parse → validate → manage.
"""
import sys
from pathlib import Path
import tempfile

# Allow running from the examples/ directory
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scopeforge.scope_parser import ScopeParser
from scopeforge.scope_validator import ScopeValidator
from scopeforge.scope_manager import ScopeManager

# ── 1. Parse targets ────────────────────────────────────────────────────────
print("=== 1. Parsing targets ===")
parser = ScopeParser()

targets = [
    "example.com",
    "*.api.example.com",
    "192.0.2.0/24",
    "https://admin.example.com/dashboard",
    "10.0.0.1",          # private – will trigger a validator warning
    "target.gov",        # dangerous TLD – will trigger a validator warning
]

for t in targets:
    result = parser.parse_target(t)
    status = "✓" if result.get("valid") else "✗"
    print(f"  {status} {t!r:45s} → type={result.get('type', 'unknown')}")

# ── 2. Validate a scope configuration ───────────────────────────────────────
print("\n=== 2. Validating scope config ===")
validator = ScopeValidator()

scope_config = {
    "in_scope": [
        "example.com",
        "*.api.example.com",
        "192.0.2.0/24",
        "https://admin.example.com",
    ],
    "out_of_scope": [
        "legacy.example.com",
        "10.0.0.0/8",
    ],
}

report = validator.validate_scope_config(scope_config)
print(f"  Valid:           {report['valid']}")
print(f"  Risk assessment: {report['risk_assessment']}")
if report["warnings"]:
    print(f"  Warnings ({len(report['warnings'])}):")
    for w in report["warnings"]:
        print(f"    - {w}")
if report["errors"]:
    print(f"  Errors ({len(report['errors'])}):")
    for e in report["errors"]:
        print(f"    - {e}")
if report["recommendations"]:
    print(f"  Recommendations:")
    for r in report["recommendations"]:
        print(f"    - {r}")

# ── 3. Manage scope lifecycle ────────────────────────────────────────────────
print("\n=== 3. Managing scopes ===")
with tempfile.TemporaryDirectory() as tmpdir:
    manager = ScopeManager(data_dir=tmpdir)

    # Create a scope
    scope_id = manager.create_scope(
        name="example-bug-bounty",
        description="HackerOne program — example.com",
    )
    print(f"  Created scope: {scope_id}")

    # Populate in-scope targets
    for target, ttype in [
        ("example.com", "domain"),
        ("*.api.example.com", "wildcard"),
        ("192.0.2.0/24", "cidr"),
    ]:
        manager.add_scope_item(scope_id, target, ttype, included=True)

    # Populate out-of-scope targets
    manager.add_scope_item(scope_id, "legacy.example.com", "domain", included=False)

    scope = manager.get_scope(scope_id)
    print(f"  In-scope  ({len(scope.in_scope)}): {[i.target for i in scope.in_scope]}")
    print(f"  Out-scope ({len(scope.out_of_scope)}): {[i.target for i in scope.out_of_scope]}")

    # List all scopes
    all_scopes = manager.list_scopes()
    print(f"  Total scopes stored: {len(all_scopes)}")

    # Clean up
    manager.delete_scope(scope_id)
    print(f"  Deleted scope — remaining: {len(manager.list_scopes())}")

print("\nDone.")
