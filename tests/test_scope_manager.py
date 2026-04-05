"""Tests for ScopeManager"""
import pytest
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from scopeforge.scope_manager import ScopeManager


@pytest.fixture
def manager(tmp_path):
    """Fresh manager backed by a temp directory so tests are isolated."""
    return ScopeManager(data_dir=str(tmp_path))


class TestCreateScope:
    def test_returns_uuid_string(self, manager):
        scope_id = manager.create_scope("Test Scope")
        assert isinstance(scope_id, str)
        assert len(scope_id) == 36  # UUID length

    def test_scope_persisted_in_list(self, manager):
        scope_id = manager.create_scope("BugBountyProg")
        scopes = manager.list_scopes()
        ids = [s["scope_id"] for s in scopes]
        assert scope_id in ids

    def test_scope_has_correct_name(self, manager):
        scope_id = manager.create_scope("MyScope", "desc here")
        scope = manager.get_scope(scope_id)
        assert scope.name == "MyScope"
        assert scope.description == "desc here"

    def test_new_scope_empty_targets(self, manager):
        scope_id = manager.create_scope("EmptyScope")
        scope = manager.get_scope(scope_id)
        assert scope.in_scope == []
        assert scope.out_of_scope == []


class TestAddScopeItem:
    def test_add_domain_to_in_scope(self, manager):
        scope_id = manager.create_scope("Test")
        result = manager.add_scope_item(scope_id, "example.com", "domain", included=True)
        assert result is True
        scope = manager.get_scope(scope_id)
        targets = [item.target for item in scope.in_scope]
        assert "example.com" in targets

    def test_add_to_out_of_scope(self, manager):
        scope_id = manager.create_scope("Test")
        manager.add_scope_item(scope_id, "internal.example.com", "domain", included=False)
        scope = manager.get_scope(scope_id)
        targets = [item.target for item in scope.out_of_scope]
        assert "internal.example.com" in targets

    def test_add_to_nonexistent_scope_returns_false(self, manager):
        result = manager.add_scope_item("nonexistent-id", "example.com", "domain")
        assert result is False


class TestDeleteScope:
    def test_delete_existing_scope(self, manager):
        scope_id = manager.create_scope("ToDelete")
        assert manager.delete_scope(scope_id) is True
        assert manager.get_scope(scope_id) is None

    def test_delete_nonexistent_returns_false(self, manager):
        assert manager.delete_scope("does-not-exist") is False

    def test_deleted_scope_not_in_list(self, manager):
        scope_id = manager.create_scope("Gone")
        manager.delete_scope(scope_id)
        ids = [s["scope_id"] for s in manager.list_scopes()]
        assert scope_id not in ids


class TestPersistence:
    def test_scopes_reload_from_disk(self, tmp_path):
        m1 = ScopeManager(data_dir=str(tmp_path))
        scope_id = m1.create_scope("Persistent")
        # Create a new manager instance pointing to same dir
        m2 = ScopeManager(data_dir=str(tmp_path))
        assert m2.get_scope(scope_id) is not None
        assert m2.get_scope(scope_id).name == "Persistent"
