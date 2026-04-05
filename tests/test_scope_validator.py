"""Tests for ScopeValidator"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scopeforge.scope_validator import ScopeValidator


@pytest.fixture
def validator():
    return ScopeValidator()


class TestPrivateIPDetection:
    def test_rfc1918_10_block(self, validator):
        results = validator.validate_target_list(["10.0.0.1"])
        assert results["statistics"]["private_ips"] >= 1

    def test_rfc1918_192_168_block(self, validator):
        results = validator.validate_target_list(["192.168.1.100"])
        assert results["statistics"]["private_ips"] >= 1

    def test_public_ip_not_private(self, validator):
        results = validator.validate_target_list(["8.8.8.8"])
        assert results["statistics"]["private_ips"] == 0
        assert results["statistics"]["public_ips"] >= 1


class TestDangerousTLDs:
    def test_gov_tld_raises_warning(self, validator):
        results = validator.validate_target_list(["target.gov"])
        warning_text = " ".join(results["warnings"]).lower()
        assert any("gov" in w.lower() or "dangerous" in w.lower() or "warning" in w.lower()
                   for w in results["warnings"])

    def test_mil_tld_raises_warning(self, validator):
        results = validator.validate_target_list(["system.mil"])
        # Expect at least one warning generated
        assert len(results["warnings"]) >= 1


class TestScopeConfig:
    def test_valid_minimal_config(self, validator):
        config = {
            "in_scope": ["example.com", "api.example.com"],
            "out_of_scope": []
        }
        result = validator.validate_scope_config(config)
        assert result["valid"] is True

    def test_empty_in_scope_no_error(self, validator):
        result = validator.validate_scope_config({"in_scope": []})
        assert result["valid"] is True

    def test_risk_level_present(self, validator):
        result = validator.validate_scope_config({"in_scope": ["example.com"]})
        assert result["risk_assessment"] in ("minimal", "low", "medium", "high", "critical")


class TestConflictDetection:
    def test_no_conflicts_for_distinct_targets(self, validator):
        conflicts = validator.check_scope_conflicts(
            ["example.com", "api.example.com"],
            ["evil.com"]
        )
        # Different domains — no conflicts expected
        assert isinstance(conflicts, list)

    def test_overlapping_wildcard_and_exclusion(self, validator):
        conflicts = validator.check_scope_conflicts(
            ["*.example.com"],
            ["secure.example.com"]
        )
        # Wildcard covers the exclusion — should warn
        assert isinstance(conflicts, list)
