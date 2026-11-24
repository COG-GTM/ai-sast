#!/usr/bin/env python3
"""Braces in stored feedback/Jira/custom text must not break single-file prompt building."""

import importlib
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def _stub_missing(name, **attrs):
    try:
        importlib.import_module(name)
    except ImportError:
        module = types.ModuleType(name)
        for key, value in attrs.items():
            setattr(module, key, value)
        sys.modules[name] = module


_stub_missing("google")
_stub_missing("google.cloud")
_stub_missing("google.cloud.aiplatform")
_stub_missing("google.genai", Client=object, types=types.SimpleNamespace())
_stub_missing("google.genai.types")

from src.core.scanner import SecurityScanner  # noqa: E402

BRACE_PAYLOADS = ["{", "}", "{x}", "{0}", "{file_path!z}", "${userInput}", "{ {x} {"]


class StubClient:
    def __init__(self):
        self.prompts = []

    def _record(self, prompt, **_kwargs):
        self.prompts.append(prompt)
        return "No vulnerabilities found."

    generate_with_gemini = _record
    generate_with_bedrock = _record
    generate_with_ollama = _record


def _scanner(feedback="", jira="", custom=""):
    scanner = SecurityScanner.__new__(SecurityScanner)
    scanner.client = StubClient()
    scanner.backend = "vertex"
    scanner.DEFAULT_PROMPT = SecurityScanner._load_default_prompt()
    scanner.feedback_context = feedback
    scanner.jira_context = jira
    scanner.custom_instructions = custom
    scanner.logger = __import__("logging").getLogger("test")
    return scanner


@pytest.mark.parametrize("payload", BRACE_PAYLOADS)
@pytest.mark.parametrize("field", ["feedback", "jira", "custom"])
def test_braces_in_context_reach_model_verbatim(field, payload):
    text = f"- **Issue**: {payload} in [src/{payload}.js] reason: uses {payload}"
    scanner = _scanner(**{field: text})

    result = scanner.scan_code_content("const a = `${b}`;", "src/app.js", "javascript")

    assert result["status"] == "success"
    assert len(scanner.client.prompts) == 1
    prompt = scanner.client.prompts[0]
    assert text in prompt
    assert "File: src/app.js" in prompt
    assert "const a = `${b}`;" in prompt
    assert "{custom_instructions}" not in prompt
    assert "{file_path}" not in prompt


def test_single_file_batch_with_brace_feedback_is_scanned():
    scanner = _scanner(feedback="- **Issue**: {")

    results = scanner.scan_code_content_batch([("print(1)", "a.py", "python")])

    assert results[0]["status"] == "success"
    assert len(scanner.client.prompts) == 1


def test_scan_file_with_brace_feedback_is_scanned(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("print(1)\n")
    scanner = _scanner(feedback="{x} and a lone {")

    result = scanner.scan_file(str(source))

    assert result["status"] == "success"
    assert "Error reading file" not in result["analysis"]
    assert len(scanner.client.prompts) == 1


def test_template_escapes_still_unescaped():
    scanner = _scanner()
    scanner.scan_code_content("x = 1", "a.py", "python")
    prompt = scanner.client.prompts[0]
    assert "{{" not in prompt
    assert "import { getToken }" in prompt


def test_broken_template_fails_the_job_instead_of_empty_result(tmp_path):
    source = tmp_path / "a.py"
    source.write_text("print(1)\n")
    scanner = _scanner()
    scanner.DEFAULT_PROMPT = "File: {file_path}\n{unknown_placeholder}\n{code_content}"

    with pytest.raises(SystemExit) as exc:
        scanner.scan_file(str(source))

    assert exc.value.code == 1
    assert scanner.client.prompts == []
