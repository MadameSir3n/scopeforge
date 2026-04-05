"""Tests for ScopeParser"""
import pytest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scopeforge.scope_parser import ScopeParser


@pytest.fixture
def parser():
    return ScopeParser()


class TestIPParsing:
    def test_valid_ipv4(self, parser):
        r = parser.parse_target("192.168.1.1")
        assert r["type"] == "ip"
        assert r["valid"] is True

    def test_invalid_ip_octet(self, parser):
        r = parser.parse_target("999.1.1.1")
        assert r["valid"] is False

    def test_cidr_v4(self, parser):
        r = parser.parse_target("10.0.0.0/8")
        assert r["type"] == "cidr"
        assert r["valid"] is True

    def test_invalid_cidr_prefix(self, parser):
        r = parser.parse_target("10.0.0.0/99")
        assert r["valid"] is False


class TestDomainParsing:
    def test_simple_domain(self, parser):
        r = parser.parse_target("example.com")
        assert r["type"] == "domain"
        assert r["valid"] is True

    def test_subdomain(self, parser):
        r = parser.parse_target("api.example.com")
        assert r["type"] == "domain"
        assert r["valid"] is True

    def test_wildcard(self, parser):
        r = parser.parse_target("*.example.com")
        assert r["type"] == "wildcard"
        assert r["valid"] is True

    def test_normalised_to_lowercase(self, parser):
        r = parser.parse_target("EXAMPLE.COM")
        assert r["normalized"] == "example.com"


class TestURLParsing:
    def test_https_url(self, parser):
        r = parser.parse_target("https://api.example.com")
        assert r["type"] == "url"
        assert r["valid"] is True

    def test_url_with_port(self, parser):
        r = parser.parse_target("https://api.example.com:8443")
        assert r["type"] == "url"
        assert r["valid"] is True

    def test_url_with_path(self, parser):
        r = parser.parse_target("https://example.com/admin")
        assert r["type"] == "url"
        assert r["valid"] is True


class TestUnknownTargets:
    def test_empty_string(self, parser):
        r = parser.parse_target("")
        assert r["valid"] is False

    def test_random_string(self, parser):
        r = parser.parse_target("not_a_target!!!")
        assert r["type"] == "unknown"
