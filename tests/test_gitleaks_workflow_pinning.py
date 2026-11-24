"""Regression checks for .github/workflows/gitleaks.yml supply-chain hardening."""

import re
from pathlib import Path

WORKFLOW = Path(__file__).parent.parent / ".github" / "workflows" / "gitleaks.yml"
USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)", re.MULTILINE)
FULL_SHA = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")


def test_every_action_is_pinned_to_full_commit_sha():
    uses = USES.findall(WORKFLOW.read_text())
    assert uses
    unpinned = [u for u in uses if not FULL_SHA.match(u)]
    assert not unpinned, f"actions not pinned to a 40-char commit SHA: {unpinned}"


def test_token_has_no_security_events_write():
    text = WORKFLOW.read_text()
    assert re.search(r"^\s*contents:\s*read\s*$", text, re.MULTILINE)
    assert not re.search(r"^\s*security-events:\s*write\s*$", text, re.MULTILINE)
