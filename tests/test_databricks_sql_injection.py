"""
Regression tests: Databricks feedback queries must not let repo_url change the SQL.

The Databricks cursor is replaced by an in-memory SQLite cursor that runs the
exact SQL text and parameters the client sends (only the three-part table name
is mapped to a local table).
"""

import sqlite3
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.databricks import DatabricksClient  # noqa: E402

CATALOG, SCHEMA, TABLE = "cat", "sch", "feedback"
OWN_REPO = "https://github.com/acme/project"
OTHER_REPO = "https://github.com/other/private-repo"
SECRET = "dapi-super-secret-token"


class SQLiteCursor:
    def __init__(self, conn):
        self._cursor = conn.cursor()
        self.statements = []
        self.errors = []

    def execute(self, sql, params=None):
        sql = sql.replace(f"{CATALOG}.{SCHEMA}.{TABLE}", TABLE)
        self.statements.append((sql, params))
        try:
            if params is None:
                return self._cursor.execute(sql)
            return self._cursor.execute(sql, params)
        except Exception as e:
            self.errors.append(e)
            raise

    def fetchall(self):
        return self._cursor.fetchall()

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        pass


@pytest.fixture
def client(monkeypatch):
    for name, value in {
        "AI_SAST_DATABRICKS_HOST": "example.cloud.databricks.com",
        "AI_SAST_DATABRICKS_HTTP_PATH": "/sql/1.0/warehouses/test",
        "AI_SAST_DATABRICKS_TOKEN": "test-token",
        "AI_SAST_DATABRICKS_CATALOG": CATALOG,
        "AI_SAST_DATABRICKS_SCHEMA": SCHEMA,
        "AI_SAST_DATABRICKS_TABLE": TABLE,
    }.items():
        monkeypatch.setenv(name, value)

    conn = sqlite3.connect(":memory:")
    conn.execute(
        f"CREATE TABLE {TABLE} (timestamp TEXT, vuln_id TEXT, comments TEXT, user TEXT, "
        "repository TEXT, issue TEXT, severity TEXT, file_path TEXT, location TEXT, status TEXT)"
    )
    conn.execute("CREATE TABLE secrets (token TEXT)")
    conn.execute("INSERT INTO secrets VALUES (?)", (SECRET,))
    now = datetime.now().isoformat()
    for repo in (OWN_REPO, OTHER_REPO):
        for status in ("False Positive", "Confirmed"):
            conn.execute(
                f"INSERT INTO {TABLE} VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now, f"{repo.rsplit('/', 1)[-1]}-{status}", "c", "u", repo,
                 "issue", "High", "a.py", "Line 1", status),
            )

    c = DatabricksClient()
    assert c.is_configured
    c.connection = conn
    c.cursor = SQLiteCursor(conn)
    yield c
    conn.close()


FETCHERS = ["get_false_positives_for_project", "get_confirmed_vulnerabilities_for_project"]


@pytest.mark.parametrize("fetch", FETCHERS)
def test_single_quote_in_repo_url_runs_without_sql_error(client, fetch):
    records = getattr(client, fetch)("https://github.com/acme/it's-a-repo")

    assert client.cursor.errors == []
    assert records == []


@pytest.mark.parametrize("fetch", FETCHERS)
def test_union_select_payload_does_not_leak_other_tables(client, fetch):
    cols = ", ".join(["token"] * 9)
    payload = f"https://github.com/acme/x') UNION SELECT {cols} FROM secrets /*"

    records = getattr(client, fetch)(payload)

    assert client.cursor.errors == []
    assert records == []
    assert SECRET not in repr(records)


@pytest.mark.parametrize("fetch", FETCHERS)
def test_like_wildcards_in_repo_url_match_literally(client, fetch):
    records = getattr(client, fetch)("https://github.com/%")

    assert client.cursor.errors == []
    assert records == []


@pytest.mark.parametrize("fetch,status", zip(FETCHERS, ["False Positive", "Confirmed"]))
def test_own_repository_records_still_returned(client, fetch, status):
    records = getattr(client, fetch)(OWN_REPO + "/", limit=10)

    assert client.cursor.errors == []
    assert [r["repo"] for r in records] == [OWN_REPO]
    assert records[0]["vuln_id"] == f"project-{status}"


@pytest.mark.parametrize("fetch", FETCHERS)
def test_non_integer_limit_is_rejected(client, fetch):
    records = getattr(client, fetch)(OWN_REPO, limit="1 UNION SELECT token FROM secrets")

    assert records == []
    assert all("secrets" not in sql for sql, _ in client.cursor.statements)


@pytest.mark.parametrize("field", ["catalog", "schema", "table"])
def test_unsafe_table_identifiers_disable_client(monkeypatch, field):
    monkeypatch.setenv("AI_SAST_DATABRICKS_HOST", "example.cloud.databricks.com")
    monkeypatch.setenv("AI_SAST_DATABRICKS_HTTP_PATH", "/sql/1.0/warehouses/test")
    monkeypatch.setenv("AI_SAST_DATABRICKS_TOKEN", "test-token")
    names = {"catalog": CATALOG, "schema": SCHEMA, "table": TABLE}
    names[field] = "x WHERE 1=1 UNION SELECT token FROM secrets --"

    c = DatabricksClient(**names)

    assert c.is_configured is False
    assert c.get_false_positives_for_project(OWN_REPO) == []
