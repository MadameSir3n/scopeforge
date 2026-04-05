# ScopeForge

A scope management library and CLI for bug bounty hunters that parses targets from any format, validates legal boundaries in real time, and prevents accidental out-of-scope testing.

---

## Problem

Bug bounty hunters waste hours manually checking whether a target is in scope — parsing PDF program rules, cross-referencing wildcard domains, and second-guessing whether an IP falls inside a listed CIDR. One mistake risks violating a program's legal terms.

## Solution

ScopeForge ingests raw scope definitions from any format or platform, normalizes every target, validates it against legal and ethical rules in real time, and provides a Python API and CLI that return a definitive in/out-of-scope answer before any request is sent.

## Key Features

- Parses domains, IPs, CIDRs, URLs, and wildcards from any text format
- Real-time validation: blocks private ranges, dangerous TLDs, scope conflicts
- Legal safety engine: configurable per-engagement ethical ground rules
- Import from HackerOne, Bugcrowd, Intigriti, and raw JSON
- Export scope reports as JSON, CSV, or HTML
- Full Python API and CLI for automation and CI pipeline integration

## Tech Stack

- **Python** — all logic
- **click** — CLI interface
- **JSON** — scope storage and platform adapters
- **pytest** — 34-test suite covering parsing, validation, and lifecycle

## Example Flow

```
1. scopeforge parse "*.acme.com" "10.0.0.0/8" "https://api.acme.com:8443"
   → *.acme.com    type=wildcard_domain  valid=True
   → 10.0.0.0/8    type=cidr             valid=False  [BLOCKED: private range]
   → api.acme.com  type=url              valid=True

2. scopeforge validate "admin.acme.com"
   → in_scope=True   (matched by *.acme.com wildcard)

3. scopeforge validate "acme.gov"
   → in_scope=False  [BLOCKED: dangerous TLD .gov]
```

## How to Run

```bash
git clone https://github.com/MadameSir3n/scopeforge.git
cd scopeforge
pip install -r requirements.txt
pip install -e .
python main.py parse "*.acme.com" "10.0.0.0/8"
```

Run tests:

```bash
python -m pytest tests/ -v
```

## Known Limitations

- Platform import adapters (HackerOne, Bugcrowd) require live API keys for full sync
- Some components are still being refined
- This is an active development system

## Sample Test Output

```
tests/test_scope_parser.py::test_parse_domain PASSED
tests/test_scope_parser.py::test_parse_wildcard PASSED
tests/test_scope_parser.py::test_parse_cidr PASSED
tests/test_scope_validator.py::test_private_range_blocked PASSED
tests/test_scope_validator.py::test_dangerous_tld_flagged PASSED
tests/test_scope_manager.py::test_create_scope PASSED
tests/test_scope_manager.py::test_add_target PASSED
...

34 passed in 0.62s
```

## Why This Matters

Legal compliance is non-negotiable in security testing. This project demonstrates how structured scope enforcement can be automated into a tool that removes human error from the process — turning a manual checklist into a programmable, auditable boundary layer that integrates directly into recon pipelines.
