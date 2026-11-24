import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.scan_database import ScanDatabase
from src.integrations.feedback import get_feedback_client

REPO = "https://github.com/acme/app"


def _plant_false_positive(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    ScanDatabase(db_path=str(db_path)).store_feedback(
        repo_url=REPO, pr_number=1, file_path="app.py", vulnerability_id="planted",
        issue="SQL Injection", severity="high", status="false_positive",
    )


@pytest.fixture
def actions_env(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_WORKSPACE", str(workspace))
    monkeypatch.delenv("AI_SAST_FEEDBACK_BACKEND", raising=False)
    monkeypatch.delenv("AI_SAST_DATABRICKS_HOST", raising=False)
    return workspace


def test_db_committed_in_checkout_is_rejected(actions_env, monkeypatch):
    planted = actions_env / ".ai-sast-db" / "scans.db"
    monkeypatch.delenv("GITHUB_ACTIONS")
    _plant_false_positive(planted)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("AI_SAST_DB_PATH", str(planted))

    with pytest.raises(ValueError, match="inside the checked-out workspace"):
        get_feedback_client()
    with pytest.raises(ValueError):
        ScanDatabase(db_path=str(actions_env / "sub" / ".." / ".ai-sast-db" / "scans.db"))


def test_db_symlinked_into_checkout_is_rejected(actions_env, tmp_path):
    link = tmp_path / "outside-link"
    link.symlink_to(actions_env, target_is_directory=True)
    with pytest.raises(ValueError):
        ScanDatabase(db_path=str(link / "scans.db"))


def test_db_outside_checkout_is_used(actions_env, tmp_path, monkeypatch):
    db_path = tmp_path / "runner-temp" / "ai-sast-db" / "scans.db"
    _plant_false_positive(db_path)
    monkeypatch.setenv("AI_SAST_DB_PATH", str(db_path))

    client = get_feedback_client()
    assert client.is_configured
    assert [fp["vuln_id"] for fp in client.get_false_positives_for_project(REPO)] == ["planted"]


def test_workspace_db_allowed_outside_actions(tmp_path, monkeypatch):
    monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
    monkeypatch.setenv("GITHUB_WORKSPACE", str(tmp_path))
    db = ScanDatabase(db_path=str(tmp_path / "scans.db"))
    assert db.is_configured
    assert sqlite3.connect(db.db_path).execute("SELECT COUNT(*) FROM feedback").fetchone() == (0,)
