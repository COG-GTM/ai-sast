#!/usr/bin/env python3
"""Feedback lookups must only return rows for the exact repository."""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.databricks import DatabricksClient
from src.integrations.repo_identity import canonical_repository, repository_aliases
from src.integrations.scan_database import ScanDatabase

TARGET = "https://github.com/org/app"

OTHER_REPOS = [
    "https://github.com/other-org/app",
    "https://github.com/org/app-backend",
    "https://github.com/acme/docs-app",
    "https://github.com/org/apps",
    "https://gitlab.com/org/app",
    "github.com/other-org/app",
]


@pytest.fixture
def db(tmp_path):
    return ScanDatabase(db_path=str(tmp_path / "scans.db"))


def _feedback(db, repo, vuln_id, status):
    assert db.store_feedback(
        repo_url=repo,
        pr_number=1,
        file_path=f"{vuln_id}.py",
        vulnerability_id=vuln_id,
        issue=f"issue {vuln_id}",
        severity="High",
        status=status,
        user="mallory",
    )


def _insert_raw(db, repo, vuln_id, status):
    """Simulate a row written before repository values were canonicalised."""
    conn = sqlite3.connect(db.db_path)
    conn.execute(
        "INSERT INTO feedback (timestamp, repository, pr_number, file_path, vuln_id, issue,"
        " severity, status, created_at) VALUES (datetime('now'), ?, 1, 'f.py', ?, 'i', 'High', ?, datetime('now'))",
        (repo, vuln_id, status),
    )
    conn.commit()
    conn.close()


@pytest.mark.parametrize("status", ["false_positive", "confirmed_vulnerability"])
def test_other_repositories_feedback_is_not_returned(db, status):
    for i, repo in enumerate(OTHER_REPOS):
        _feedback(db, repo, f"other-{i}", status)

    assert db.get_false_positives_for_project(TARGET) == []
    assert db.get_confirmed_vulnerabilities_for_project(TARGET) == []


def test_like_wildcards_in_names_do_not_match(db):
    _feedback(db, "https://github.com/org/my-app", "dash", "false_positive")
    _feedback(db, "https://github.com/org/my_app", "underscore", "false_positive")
    _feedback(db, "https://github.com/org/myXapp", "x", "false_positive")

    rows = db.get_false_positives_for_project("https://github.com/org/my_app")
    assert [r["vuln_id"] for r in rows] == ["underscore"]
    assert db.get_false_positives_for_project("https://github.com/org/my%app") == []


def test_raw_legacy_rows_for_other_repositories_do_not_match(db):
    _insert_raw(db, "https://github.com/other-org/app", "legacy-other", "false_positive")
    _insert_raw(db, "https://github.com/org/app-backend", "legacy-backend", "false_positive")

    assert db.get_false_positives_for_project(TARGET) == []


def test_own_feedback_is_returned_for_equivalent_urls(db):
    _feedback(db, "https://github.com/Org/App.git", "own", "false_positive")
    _feedback(db, TARGET, "own-cv", "confirmed_vulnerability")
    _feedback(db, "https://github.com/other-org/app", "other", "false_positive")

    for url in [TARGET, f"{TARGET}/", f"{TARGET}.git", "http://github.com/ORG/app", "git@github.com:org/app.git"]:
        assert [r["vuln_id"] for r in db.get_false_positives_for_project(url)] == ["own"], url
        assert [r["vuln_id"] for r in db.get_confirmed_vulnerabilities_for_project(url)] == ["own-cv"], url


def test_legacy_rows_for_same_repository_still_match(db):
    _insert_raw(db, "https://github.com/Org/App", "legacy-own", "false_positive")

    rows = db.get_false_positives_for_project("https://github.com/Org/App")
    assert [r["vuln_id"] for r in rows] == ["legacy-own"]


def test_statistics_are_scoped_to_repository(db):
    _feedback(db, TARGET, "own", "false_positive")
    for i, repo in enumerate(OTHER_REPOS):
        _feedback(db, repo, f"other-{i}", "false_positive")
        assert db.store_scan_result("s1", repo, 1, "f.py", f"other-{i}", "i", "High")
    assert db.store_scan_result("s1", TARGET, 1, "f.py", "own", "i", "High")

    stats = db.get_statistics(TARGET)
    assert stats["total_feedback"] == 1
    assert stats["false_positives"] == 1
    assert stats["total_scan_results"] == 1


def test_validator_update_matches_stored_scan_result(db):
    assert db.store_scan_result("s1", "https://github.com/Org/App", 1, "f.py", "v1", "i", "High")
    assert db.update_validator_result("s1", "https://github.com/Org/App", "v1", "bedrock", "ok")


def test_canonical_repository():
    assert canonical_repository("https://github.com/Org/App.git/") == "github.com/org/app"
    assert canonical_repository("git@github.com:Org/App.git") == "github.com/org/app"
    assert canonical_repository("https://user:token@github.com/org/app") == "github.com/org/app"
    assert canonical_repository("/home/runner/work/App/") == "/home/runner/work/App"
    assert "github.com/org/app" in repository_aliases(TARGET)
    assert all("other-org" not in a and "backend" not in a for a in repository_aliases(TARGET))


class _RecordingCursor:
    def __init__(self):
        self.calls = []
        self.description = []

    def execute(self, sql, params=None):
        self.calls.append((sql, params))

    def fetchall(self):
        return []


def test_databricks_queries_use_exact_bound_repository(monkeypatch):
    client = DatabricksClient(catalog="c", schema="s", table="t")
    client.is_configured = True
    client.connection = object()
    client.cursor = _RecordingCursor()

    client.get_false_positives_for_project("https://github.com/org/app'--")
    client.get_confirmed_vulnerabilities_for_project(TARGET)

    for sql, params in client.cursor.calls:
        assert "LIKE" not in sql
        assert "org/app" not in sql
        assert "repository IN (" in sql
        assert params is not None
    assert "github.com/org/app" in client.cursor.calls[1][1]
