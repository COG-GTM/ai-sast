"""Tests for the vector client's endpoint handling (no network access)."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.integrations import vector
from src.integrations.vector import VectorClient, build_endpoint_url, send_security_event


class _Response:
    def raise_for_status(self):
        pass


@pytest.fixture
def posts(monkeypatch):
    calls = []

    def fake_post(url, json=None, headers=None, timeout=None):
        calls.append({"url": url, "headers": headers})
        return _Response()

    monkeypatch.setattr(vector.requests, "post", fake_post)
    for name in ("AI_SAST_VECTOR_URL", "AI_SAST_VECTOR_TOKEN", "AI_SAST_VECTOR_ALLOW_INSECURE_HTTP"):
        monkeypatch.delenv(name, raising=False)
    return calls


def _send():
    return send_security_event(
        repo_url="https://github.com/acme/repo",
        target_url="HIGH",
        category="AI-SAST",
        message="test",
        assertion_condition=False,
    )


def test_bare_host_uses_https(posts, monkeypatch):
    monkeypatch.setenv("AI_SAST_VECTOR_URL", "logs.acme.example")
    monkeypatch.setenv("AI_SAST_VECTOR_TOKEN", "secret-token")

    assert _send() is True
    assert posts[0]["url"] == "https://logs.acme.example:8088/services/collector"
    assert posts[0]["headers"]["Authorization"] == "Splunk secret-token"


def test_bare_host_with_port_keeps_port():
    assert build_endpoint_url("logs.acme.example:9443") == "https://logs.acme.example:9443/services/collector"


def test_https_url_used_as_is():
    url = "https://logs.acme.example:8088/collector"
    assert build_endpoint_url(url) == url


@pytest.mark.parametrize("url", ["http://logs.acme.example:8088/services/collector", "HTTP://logs.acme.example"])
def test_http_url_refused_without_opt_in(posts, monkeypatch, url):
    monkeypatch.setenv("AI_SAST_VECTOR_URL", url)
    monkeypatch.setenv("AI_SAST_VECTOR_TOKEN", "secret-token")

    assert _send() is False
    assert posts == []


def test_http_url_allowed_with_opt_in(posts, monkeypatch):
    url = "http://localhost:8088/services/collector"
    monkeypatch.setenv("AI_SAST_VECTOR_URL", url)
    monkeypatch.setenv("AI_SAST_VECTOR_TOKEN", "secret-token")
    monkeypatch.setenv("AI_SAST_VECTOR_ALLOW_INSECURE_HTTP", "true")

    assert _send() is True
    assert posts[0]["url"] == url


@pytest.mark.parametrize("value", ["ftp://logs.acme.example", "https://", "logs.acme.example/path", ""])
def test_unusable_endpoints_rejected(value):
    assert build_endpoint_url(value) is None


def test_vector_client_uses_constructor_endpoint(posts):
    client = VectorClient(endpoint="logs.acme.example", token="secret-token")

    assert client.log_vulnerability(
        repo_url="https://github.com/acme/repo", file_path="app.py", severity="HIGH", issue="SQLi"
    ) is True
    assert posts[0]["url"] == "https://logs.acme.example:8088/services/collector"


def test_vector_client_refuses_http_endpoint(posts):
    client = VectorClient(endpoint="http://logs.acme.example", token="secret-token")

    assert client.log_scan_complete(repo_url="https://github.com/acme/repo", total_files=1, vulnerabilities_found=0) is False
    assert posts == []
