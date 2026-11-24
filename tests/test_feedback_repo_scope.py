#!/usr/bin/env python3
"""
Feedback lookups must return rows for the scanned repository only.

Rows for another owner (other-org/app), for a repository whose name contains
this one (org/app-backend), or that only match via a LIKE wildcard (org/axp
for org/a_p) must not be returned, and feedback text must not be printed.
"""

import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.databricks import DatabricksClient
from src.integrations.repo_identity import normalize_repo_identifier
from src.integrations.scan_database import ScanDatabase

REPO = "https://github.com/org/app"
OWN_REPOSITORY_VALUES = [
    "https://github.com/org/app",
    "https://github.com/Org/App.git",
    "github.com/org/app/",
]
FOREIGN_REPOSITORY_VALUES = [
    "https://github.com/other-org/app",
    "https://github.com/org/app-backend",
    "https://github.com/org/app2",
    "https://gitlab.com/org/app",
]


@pytest.mark.parametrize("url,expected", [
    ("https://github.com/Org/App.git", "github.com/org/app"),
    ("git@github.com:org/app.git", "github.com/org/app"),
    ("https://user:token@github.com/org/app/", "github.com/org/app"),
    ("org/app", "org/app"),
    ("", ""),
])
def test_normalize_repo_identifier(url, expected):
    assert normalize_repo_identifier(url) == expected


# --- SQLite backend ---------------------------------------------------------

@pytest.fixture
def sqlite_db(tmp_path):
    db = ScanDatabase(db_path=str(tmp_path / "scans.db"))
    rows = [(r, f"own-{i}") for i, r in enumerate(OWN_REPOSITORY_VALUES)]
    rows += [(r, f"foreign-{i}") for i, r in enumerate(FOREIGN_REPOSITORY_VALUES)]
    for repository, vuln_id in rows:
        for status in ("false_positive", "confirmed_vulnerability"):
            assert db.store_feedback(
                repo_url=repository, pr_number=1, file_path=f"{vuln_id}.py",
                vulnerability_id=vuln_id, issue=f"{vuln_id} issue",
                severity="HIGH", status=status,
            )
    return db


def _ids(rows):
    return sorted(r["vuln_id"] for r in rows)


def test_sqlite_false_positives_scoped_to_repository(sqlite_db):
    assert _ids(sqlite_db.get_false_positives_for_project(REPO)) == ["own-0", "own-1", "own-2"]


def test_sqlite_confirmed_scoped_to_repository(sqlite_db):
    assert _ids(sqlite_db.get_confirmed_vulnerabilities_for_project(REPO)) == ["own-0", "own-1", "own-2"]


def test_sqlite_underscore_is_not_a_wildcard(sqlite_db):
    sqlite_db.store_feedback(
        repo_url="https://github.com/org/axp", pr_number=1, file_path="x.py",
        vulnerability_id="axp", issue="x", severity="HIGH", status="false_positive",
    )
    assert sqlite_db.get_false_positives_for_project("https://github.com/org/a_p") == []


def test_sqlite_statistics_scoped_to_repository(sqlite_db):
    stats = sqlite_db.get_statistics(REPO)
    assert stats["false_positives"] == 3
    assert stats["confirmed_vulnerabilities"] == 3


# --- Databricks backend (SQL executed against SQLite) -----------------------

class _SqliteBackedCursor:
    """Runs the client's Databricks SQL on SQLite, using qmark bound parameters."""

    def __init__(self, conn, table_ref):
        self._cursor = conn.cursor()
        self._table_ref = table_ref
        self.executed = []

    def execute(self, sql, params=None):
        self.executed.append((sql, params))
        self._cursor.execute(sql.replace(self._table_ref, "feedback"), params or ())

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def description(self):
        return self._cursor.description


@pytest.fixture
def databricks_client(monkeypatch):
    for name, value in {
        "AI_SAST_DATABRICKS_HOST": "example.cloud.databricks.com",
        "AI_SAST_DATABRICKS_HTTP_PATH": "/sql/1.0/warehouses/x",
        "AI_SAST_DATABRICKS_TOKEN": "test-token",
        "AI_SAST_DATABRICKS_CATALOG": "cat",
        "AI_SAST_DATABRICKS_SCHEMA": "sch",
        "AI_SAST_DATABRICKS_TABLE": "tbl",
    }.items():
        monkeypatch.setenv(name, value)

    conn = sqlite3.connect(":memory:")
    conn.execute(
        "CREATE TABLE feedback (timestamp TEXT, vuln_id TEXT, comments TEXT, user TEXT, "
        "repository TEXT, issue TEXT, severity TEXT, file_path TEXT, location TEXT, status TEXT)"
    )
    now = datetime.now().isoformat()
    rows = [(r, f"own-{i}") for i, r in enumerate(OWN_REPOSITORY_VALUES)]
    rows += [(r, f"foreign-{i}") for i, r in enumerate(FOREIGN_REPOSITORY_VALUES)]
    rows += [("https://github.com/org/axp", "axp")]
    for repository, vuln_id in rows:
        for status in ("False Positive", "Confirmed"):
            conn.execute(
                "INSERT INTO feedback VALUES (?, ?, '', 'u', ?, ?, 'HIGH', ?, '', ?)",
                (now, vuln_id, repository, f"{vuln_id} issue", f"{vuln_id}.py", status),
            )

    client = DatabricksClient()
    assert client.is_configured
    client.connection = conn
    client.cursor = _SqliteBackedCursor(conn, "cat.sch.tbl")
    return client


def test_databricks_false_positives_scoped_to_repository(databricks_client):
    rows = databricks_client.get_false_positives_for_project(REPO)
    assert _ids(rows) == ["own-0", "own-1", "own-2"]


def test_databricks_confirmed_scoped_to_repository(databricks_client):
    rows = databricks_client.get_confirmed_vulnerabilities_for_project(REPO)
    assert _ids(rows) == ["own-0", "own-1", "own-2"]


def test_databricks_underscore_is_not_a_wildcard(databricks_client):
    assert databricks_client.get_false_positives_for_project("https://github.com/org/a_p") == []


def test_databricks_repo_url_is_bound_not_interpolated(databricks_client):
    hostile = "https://github.com/org/app' OR '1'='1"
    assert databricks_client.get_false_positives_for_project(hostile) == []
    sql, params = databricks_client.cursor.executed[-1]
    assert "org/app" not in sql
    assert any("org/app' or '1'='1" in p for p in params)


def test_format_feedback_does_not_print_feedback_text(databricks_client, capsys):
    rows = databricks_client.get_confirmed_vulnerabilities_for_project(REPO)
    context = databricks_client.format_feedback_for_context([], rows)
    assert "own-0 issue" in context
    assert "own-0 issue" not in capsys.readouterr().out
