"""PR scan exclusions: generic file names must not opt out of the scan, and
every file that is not analyzed must be named in the PR comment."""

import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

# Allow importing the scanner without the Vertex SDK installed (the LLM is mocked below).
if importlib.util.find_spec("google.cloud") is None or importlib.util.find_spec("google.genai") is None:
    for name in ("google.cloud", "google.cloud.aiplatform", "google.genai", "google.genai.types"):
        sys.modules.setdefault(name, types.ModuleType(name))
    sys.modules["google.cloud"].aiplatform = sys.modules["google.cloud.aiplatform"]
    sys.modules["google.genai"].Client = object
    sys.modules["google.genai"].types = sys.modules["google.genai.types"]

from src.core.scanner import SecurityScanner, get_exclude_keywords, is_path_excluded  # noqa: E402
from src.main import pr_scan  # noqa: E402

COMMAND_INJECTION = "import os, sys\nos.system('ping ' + sys.argv[1])\n"


def _diff(code: str) -> str:
    return "\n".join("+" + line for line in code.splitlines())


class FakeScanner:
    scanned = []

    def __init__(self, repo_url=None):
        pass

    _load_file_extensions = staticmethod(SecurityScanner._load_file_extensions)

    def _detect_language(self, file_path):
        return "Python"

    def scan_code_content_batch(self, batch, batch_descriptor=""):
        FakeScanner.scanned.extend(path for _, path, _ in batch)
        return [
            {"file_path": path, "language": lang, "analysis": "No vulnerabilities found.", "status": "success"}
            for _, path, lang in batch
        ]


@pytest.fixture
def run_pr_scan(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("AI_SAST_EXCLUDE_PATHS", raising=False)
    monkeypatch.delenv("AI_SAST_STORE_FINDINGS", raising=False)
    monkeypatch.setattr(pr_scan, "SecurityScanner", FakeScanner)
    monkeypatch.setattr(pr_scan, "WebhookClient", None)
    FakeScanner.scanned = []

    def run(paths):
        changes = [{"new_path": p, "deleted_file": False, "diff": _diff(COMMAND_INJECTION)} for p in paths]
        monkeypatch.setattr(pr_scan, "get_pr_changes_from_github", lambda: changes)
        pr_scan.main()
        comment = tmp_path / "pr_comment.md"
        return comment.read_text() if comment.exists() else None

    return run


@pytest.mark.parametrize("path", [
    "scripts/run.py",
    "scripts/deploy.sh",
    "src/billing/local.py",
    "api/log.py",
    "app/mock_payments.py",
    "tests/conftest.py",
    "src/e2e/handler.js",
])
def test_generic_names_are_not_excluded_by_default(monkeypatch, path):
    monkeypatch.delenv("AI_SAST_EXCLUDE_PATHS", raising=False)
    assert not is_path_excluded(path, get_exclude_keywords())


@pytest.mark.parametrize("path", ["node_modules/lodash/index.js", "web/node_modules/a.js", ".git/hooks/pre-commit.py"])
def test_dependency_folders_are_excluded_by_default(monkeypatch, path):
    monkeypatch.delenv("AI_SAST_EXCLUDE_PATHS", raising=False)
    assert is_path_excluded(path, get_exclude_keywords())


def test_operator_can_opt_in_with_anchored_path(monkeypatch):
    monkeypatch.setenv("AI_SAST_EXCLUDE_PATHS", "tools/scripts, docs/*.md")
    keywords = get_exclude_keywords()
    assert is_path_excluded("tools/scripts/run.py", keywords)
    assert is_path_excluded("docs/README.md", keywords)
    assert not is_path_excluded("scripts/run.py", keywords)


def test_script_file_is_scanned_by_default(run_pr_scan):
    run_pr_scan(["scripts/run.py"])
    assert FakeScanner.scanned == ["scripts/run.py"]


def test_comment_names_excluded_file_when_every_file_is_excluded(run_pr_scan, monkeypatch):
    monkeypatch.setenv("AI_SAST_EXCLUDE_PATHS", "scripts")
    comment = run_pr_scan(["scripts/run.py"])
    assert FakeScanner.scanned == []
    assert comment is not None
    assert pr_scan.COMMENT_TITLE in comment
    assert "Excluded from scan (1 file(s)" in comment
    assert "`scripts/run.py`" in comment


def test_comment_names_excluded_file_when_other_files_are_clean(run_pr_scan, monkeypatch):
    monkeypatch.setenv("AI_SAST_EXCLUDE_PATHS", "scripts")
    comment = run_pr_scan(["scripts/run.py", "src/app.py"])
    assert FakeScanner.scanned == ["src/app.py"]
    assert comment is not None
    assert pr_scan.COMMENT_TITLE in comment
    assert "### Scan coverage" in comment
    assert "`scripts/run.py`" in comment


def test_comment_names_size_skipped_file_without_findings(run_pr_scan, monkeypatch):
    monkeypatch.setenv("AI_SAST_PR_SCAN_MAX_FILE_SIZE", "10")
    comment = run_pr_scan(["src/big.py"])
    assert comment is not None
    assert "Skipped due to size/count limits (1 file(s)):** `src/big.py`" in comment


def test_no_comment_when_everything_was_scanned_and_clean(run_pr_scan):
    assert run_pr_scan(["src/app.py"]) is None
    assert FakeScanner.scanned == ["src/app.py"]
