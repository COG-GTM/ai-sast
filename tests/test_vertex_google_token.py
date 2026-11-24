#!/usr/bin/env python3
"""
GOOGLE_TOKEN service account keys must stay in memory: no temp credentials
file may be left behind and GOOGLE_APPLICATION_CREDENTIALS must not be set.
"""

import base64
import importlib.util
import json
import os
import sys
import tempfile
import types
from pathlib import Path

import pytest

pytest.importorskip("google.oauth2.service_account")
rsa = pytest.importorskip("cryptography.hazmat.primitives.asymmetric.rsa")
from cryptography.hazmat.primitives import serialization

VERTEX_PATH = Path(__file__).parent.parent / "src" / "core" / "vertex.py"


def _service_account_json():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()
    return json.dumps({
        "type": "service_account",
        "project_id": "test-project",
        "private_key_id": "test-key-id",
        "private_key": pem,
        "client_email": "scanner@test-project.iam.gserviceaccount.com",
        "client_id": "1234567890",
        "token_uri": "https://oauth2.googleapis.com/token",
    })


@pytest.fixture
def vertex(monkeypatch, tmp_path):
    calls = {}

    class FakeClient:
        def __init__(self, **kwargs):
            calls["client"] = kwargs

    def fake_init(**kwargs):
        calls["aiplatform_init"] = kwargs

    genai = types.ModuleType("google.genai")
    genai.Client = FakeClient
    genai.types = types.ModuleType("google.genai.types")
    aiplatform = types.ModuleType("google.cloud.aiplatform")
    aiplatform.init = fake_init
    cloud = types.ModuleType("google.cloud")
    cloud.aiplatform = aiplatform

    monkeypatch.setitem(sys.modules, "google.genai", genai)
    monkeypatch.setitem(sys.modules, "google.genai.types", genai.types)
    monkeypatch.setitem(sys.modules, "google.cloud", cloud)
    monkeypatch.setitem(sys.modules, "google.cloud.aiplatform", aiplatform)

    spec = importlib.util.spec_from_file_location("vertex_under_test", VERTEX_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))
    monkeypatch.delenv("GOOGLE_APPLICATION_CREDENTIALS", raising=False)
    return module, calls, tmp_path


@pytest.mark.parametrize("encoding", ["raw", "base64"])
def test_service_account_token_not_written_to_disk(vertex, monkeypatch, capsys, encoding):
    module, calls, tmp_path = vertex
    token = _service_account_json()
    if encoding == "base64":
        token = base64.b64encode(token.encode()).decode()
    monkeypatch.setenv("GOOGLE_TOKEN", token)

    module.VertexAIClient("test-project", "us-central1")
    module.VertexAIClient("test-project", "us-central1")

    assert list(tmp_path.iterdir()) == []
    assert "GOOGLE_APPLICATION_CREDENTIALS" not in os.environ
    assert "Created temporary credentials file" not in capsys.readouterr().out

    credentials = calls["client"]["credentials"]
    assert credentials is not None
    assert credentials.service_account_email == "scanner@test-project.iam.gserviceaccount.com"
    assert calls["aiplatform_init"]["credentials"] is credentials


def test_access_token_falls_back_to_default_credentials(vertex, monkeypatch):
    module, calls, tmp_path = vertex
    monkeypatch.setenv("GOOGLE_TOKEN", "ya29.not-a-service-account-key")

    module.VertexAIClient("test-project", "us-central1")

    assert list(tmp_path.iterdir()) == []
    assert calls["client"]["credentials"] is None
    assert calls["aiplatform_init"]["credentials"] is None


def test_no_google_token_uses_default_credentials(vertex, monkeypatch):
    module, calls, _ = vertex
    monkeypatch.delenv("GOOGLE_TOKEN", raising=False)

    module.VertexAIClient("test-project", "us-central1")

    assert calls["client"]["credentials"] is None
    assert calls["aiplatform_init"]["credentials"] is None
