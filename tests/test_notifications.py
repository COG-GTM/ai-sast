#!/usr/bin/env python3
"""Tests that chat alert formatters escape model-written finding text."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations.notifications import MAX_ALERT_FIELD_LENGTH, WebhookClient

MALICIOUS_ISSUE = (
    "SQL injection <!channel> see <https://evil.example/login|internal docs> "
    "or [security wiki](https://evil.example/phish) @everyone <@&123>"
)

VULNERABILITY = {
    "severity": "Critical",
    "issue": MALICIOUS_ISSUE,
    "file": "app/<!here>.py",
    "location": "L10",
    "cvss_vector": "CVSS:3.1/AV:N",
}


def _alert_payload(monkeypatch, webhook_type):
    monkeypatch.setenv("AI_SAST_WEBHOOK_URL", "https://hooks.example.invalid/webhook")
    monkeypatch.setenv("AI_SAST_WEBHOOK_TYPE", webhook_type)
    client = WebhookClient()
    sent = []
    monkeypatch.setattr(client, "_send_webhook", lambda payload: sent.append(payload) or True)
    assert client.send_critical_alert("myorg/myapp", 42, VULNERABILITY)
    assert len(sent) == 1
    return sent[0]


def test_slack_alert_escapes_links_and_mentions(monkeypatch):
    payload = _alert_payload(monkeypatch, "slack")
    text = payload["blocks"][1]["text"]["text"]

    assert "<!channel>" not in text
    assert "<https://evil.example/login|internal docs>" not in text
    assert "<!here>" not in text
    assert "&lt;!channel&gt;" in text
    assert "&lt;https://evil.example/login|internal docs&gt;" in text
    assert "*File:* app/&lt;!here&gt;.py" in text


def test_teams_alert_disables_markdown_and_escapes(monkeypatch):
    payload = _alert_payload(monkeypatch, "teams")
    section = payload["sections"][0]
    issue = next(f["value"] for f in section["facts"] if f["name"] == "Issue")

    assert section["markdown"] is False
    assert "<!channel>" not in issue
    assert "&lt;https://evil.example/login|internal docs&gt;" in issue


def test_discord_alert_escapes_markdown_and_blocks_mentions(monkeypatch):
    payload = _alert_payload(monkeypatch, "discord")
    fields = payload["embeds"][0]["fields"]
    issue = next(f["value"] for f in fields if f["name"] == "Issue")

    assert payload["allowed_mentions"] == {"parse": []}
    assert "[security wiki](https://evil.example/phish)" not in issue
    assert r"\[security wiki\]\(https://evil.example/phish\)" in issue
    assert r"\@everyone" in issue
    assert r"\<\@&123\>" in issue


def test_discord_scan_completed_blocks_mentions(monkeypatch):
    monkeypatch.setenv("AI_SAST_WEBHOOK_URL", "https://hooks.example.invalid/webhook")
    monkeypatch.setenv("AI_SAST_WEBHOOK_TYPE", "discord")
    client = WebhookClient()
    sent = []
    monkeypatch.setattr(client, "_send_webhook", lambda payload: sent.append(payload) or True)
    client.send_scan_completed("myorg/myapp", 1, {"critical": 1})
    assert sent[0]["allowed_mentions"] == {"parse": []}


@pytest.mark.parametrize("webhook_type", ["slack", "teams", "discord"])
def test_alert_issue_text_is_length_limited(monkeypatch, webhook_type):
    vuln = dict(VULNERABILITY, issue="A" * 5000)
    monkeypatch.setenv("AI_SAST_WEBHOOK_URL", "https://hooks.example.invalid/webhook")
    monkeypatch.setenv("AI_SAST_WEBHOOK_TYPE", webhook_type)
    client = WebhookClient()
    sent = []
    monkeypatch.setattr(client, "_send_webhook", lambda payload: sent.append(payload) or True)
    client.send_critical_alert("myorg/myapp", 1, vuln)

    serialized = json.dumps(sent[0])
    assert "A" * (MAX_ALERT_FIELD_LENGTH + 1) not in serialized
    assert "A" * (MAX_ALERT_FIELD_LENGTH - 1) in serialized


def test_generic_alert_payload_is_unchanged(monkeypatch):
    payload = _alert_payload(monkeypatch, "generic")
    assert payload["vulnerability"]["issue"] == MALICIOUS_ISSUE
