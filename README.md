# ScopeForge 🔭

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/Focus-Bug%20Bounty-red.svg)](https://github.com/MadameSir3n/scopeforge)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](tests/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue.svg)](https://docker.com)

Advanced scope lifecycle management, validation, and legal-boundary parsing for bug bounty programs and penetration tests.

> **Why does this exist?**  
> Bug bounty hunters and pentesters waste hours manually checking whether a target is in-scope, parsing program rules from PDFs and wiki pages, and ensuring they never accidentally touch out-of-scope assets. ScopeForge automates all of that — from ingesting raw HackerOne/Bugcrowd/Intigriti program scopes to enforcing legal ground rules at runtime.

---

## ✨ Features

| Feature | Description |
|---|---|
| **Smart Parsing** | Auto-detects domains, IPs, CIDRs, URLs, wildcards from any format |
| **Validation Engine** | Flags private ranges, dangerous TLDs, scope conflicts in real time |
| **Legal Ground Rules** | Built-in ethical testing policy engine (no DoS, rate limits, data handling) |
| **Import / Export** | HackerOne, Bugcrowd, Intigriti, and raw JSON formats |
| **Report Generator** | JSON, CSV, and HTML compliance reports for each engagement |
| **Automation API** | Python library + CLI for scripting and CI pipeline integration |
| **Platform Presets** | Pre-configured scope templates for popular bug bounty platforms |

---

## 📦 Installation

```bash
# Clone and install locally
git clone https://github.com/MadameSir3n/scopeforge.git
cd scopeforge
pip install -e .
```

---

## 🚀 Quick Start

### CLI

```bash
# Parse and classify targets
scopeforge parse "*.acme.com" "10.0.0.0/8" "https://api.acme.com:8443"

# Validate a target list against program rules
scopeforge validate "admin.acme.com" "localhost" "acme.gov"

# Create and manage a named scope
scopeforge create "Acme Corp Q2 Pentest" --description "External ASM scope"
scopeforge list
```

### Python API

```python
from scopeforge import ScopeManager, ScopeParser, ScopeValidator

# --- Parse raw targets ---
parser = ScopeParser()
for target in ["*.acme.com", "192.168.1.0/24", "https://api.acme.com"]:
    result = parser.parse_target(target)
    print(f"{target}  →  type={result['type']}  valid={result['valid']}")

# --- Validate against legal boundaries ---
validator = ScopeValidator()
result = validator.validate_target("acme.gov")
if not result["is_valid"]:
    for err in result["errors"]:
        print(f"[BLOCKED] {err}")

# --- Manage named scopes ---
manager = ScopeManager()
scope_id = manager.create_scope("Acme Q2", "External perimeter")
manager.add_target(scope_id, "acme.com", included=True)
manager.add_target(scope_id, "hr.acme.com", included=False)  # out-of-scope
print(manager.get_scope(scope_id))
```

---

## 🏗️ Project Structure

```
scopeforge/
├── src/scopeforge/
│   ├── cli.py                  # CLI entry point
│   ├── scope_manager.py        # CRUD lifecycle for named scopes
│   ├── scope_parser.py         # Target normalisation & type detection
│   ├── scope_validator.py      # Legal / ethical / technical validation
│   ├── scope_automation.py     # Batch and automated scope processing
│   ├── scope_import_export.py  # HackerOne / Bugcrowd / Intigriti adapters
│   ├── scope_report_generator.py  # JSON / CSV / HTML reports
│   ├── ground_rules.py         # Ethical testing policy engine
│   ├── scope_presets/          # Platform-specific default templates
│   │   ├── hackerone.json
│   │   ├── pentesterlab.json
│   │   └── tryhackme.json
│   └── templates/
│       └── scope_template.json
├── tests/
│   ├── test_scope_parser.py
│   ├── test_scope_validator.py
│   └── test_scope_manager.py
├── examples/
│   └── basic_usage.py
├── data/                       # Local scope storage (gitignored in prod)
├── requirements.txt
└── setup.py
```

---

## 🛡️ Legal Safety Features

ScopeForge actively prevents accidental out-of-scope testing:

- **Private range blocking** — refuses to add RFC1918 / loopback IPs without explicit override  
- **Dangerous TLD warnings** — flags `.gov`, `.mil`, `.edu`, `.bank` targets  
- **Conflict detection** — warns when an in-scope wildcard overlaps an out-of-scope host  
- **Ground rules engine** — configurable per-engagement ethical policy (rate limits, no-DoS, data handling)  
- **Audit log** — every scope change is timestamped for compliance documentation  

---

## 🔌 Platform Support

| Platform | Import | Export |
|---|---|---|
| HackerOne | ✅ | ✅ |
| Bugcrowd | ✅ | ✅ |
| Intigriti | ✅ | ✅ |
| TryHackMe | ✅ | — |
| PentesterLab | ✅ | — |
| Raw JSON | ✅ | ✅ |
| CSV | ✅ | ✅ |

---

## 🧪 Testing

```bash
pip install pytest
pytest tests/ -v
```

---

## 📄 License

MIT — see [LICENSE](LICENSE).
