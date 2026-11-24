"""PR scan must list renamed files by their new path and paths Git would quote verbatim."""

import json
import os
import subprocess
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))


def _stub_missing(name, **attrs):
    try:
        __import__(name)
    except ImportError:
        parts = name.split('.')
        for i in range(1, len(parts) + 1):
            mod_name = '.'.join(parts[:i])
            if mod_name not in sys.modules:
                sys.modules[mod_name] = types.ModuleType(mod_name)
            if i > 1:
                setattr(sys.modules['.'.join(parts[:i - 1])], parts[i - 1], sys.modules[mod_name])
        for k, v in attrs.items():
            setattr(sys.modules[name], k, v)


# LLM SDKs are not needed to exercise the git change listing
_stub_missing('google.cloud.aiplatform')
_stub_missing('google.genai', Client=object, types=types.ModuleType('google.genai.types'))
_stub_missing('google.genai.types')

from src.main import pr_scan  # noqa: E402

EVAL_LINE = "result = eval(request.args.get('expr'))"


def _git(repo, *args):
    subprocess.run(['git', *args], cwd=repo, check=True, capture_output=True)


def _rev(repo):
    return subprocess.run(['git', 'rev-parse', 'HEAD'], cwd=repo, check=True,
                          capture_output=True, text=True).stdout.strip()


@pytest.fixture
def repo(tmp_path, monkeypatch):
    repo = tmp_path / 'repo'
    repo.mkdir()
    _git(repo, 'init', '-q', '-b', 'main')
    _git(repo, 'config', 'user.email', 't@example.com')
    _git(repo, 'config', 'user.name', 't')
    _git(repo, 'config', 'commit.gpgsign', 'false')
    (repo / 'src').mkdir()
    (repo / 'src' / 'auth.py').write_text(
        ''.join(f"def check_{i}(user):\n    return user.role == 'admin_{i}'\n\n" for i in range(20)))
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-qm', 'base')
    monkeypatch.chdir(repo)
    return repo


def _commit_and_collect(repo, base, monkeypatch, tmp_path):
    _git(repo, 'add', '-A')
    _git(repo, 'commit', '-qm', 'head')
    head = _rev(repo)
    event = tmp_path / 'event.json'
    event.write_text(json.dumps({'pull_request': {'base': {'sha': base}, 'head': {'sha': head}, 'number': 1}}))
    monkeypatch.setenv('GITHUB_EVENT_PATH', str(event))
    return {c['new_path']: c for c in pr_scan.get_pr_changes_from_github()}


def _added(change):
    return pr_scan.parse_added_lines_from_diff(change['diff'])


def test_renamed_and_edited_file_uses_new_path(repo, monkeypatch, tmp_path):
    base = _rev(repo)
    _git(repo, 'mv', 'src/auth.py', 'src/auth_v2.py')
    with open(repo / 'src' / 'auth_v2.py', 'a') as f:
        f.write(EVAL_LINE + '\n')

    changes = _commit_and_collect(repo, base, monkeypatch, tmp_path)

    assert 'src/auth.py' not in changes
    assert EVAL_LINE in _added(changes['src/auth_v2.py'])


@pytest.mark.parametrize('path', [
    'src/módulo/handler.py',
    'src/we"ird/handler.py',
    'src/back\\slash.py',
    'src/tab\tname.py',
    'src/new\nline.py',
    'src/[ab].py',
    'src/*.py',
])
def test_special_paths_are_listed_verbatim(repo, monkeypatch, tmp_path, path):
    base = _rev(repo)
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(EVAL_LINE + '\n')

    changes = _commit_and_collect(repo, base, monkeypatch, tmp_path)

    assert list(changes) == [path]
    assert _added(changes[path]) == EVAL_LINE


def test_binary_attribute_does_not_hide_added_lines(repo, monkeypatch, tmp_path):
    base = _rev(repo)
    (repo / '.gitattributes').write_text('*.py binary\n')
    (repo / 'src' / 'handler.py').write_text(EVAL_LINE + '\n')

    changes = _commit_and_collect(repo, base, monkeypatch, tmp_path)

    assert _added(changes['src/handler.py']) == EVAL_LINE


def test_rename_detection_config_is_ignored(repo, monkeypatch, tmp_path):
    _git(repo, 'config', 'diff.renames', 'copies')
    base = _rev(repo)
    _git(repo, 'mv', 'src/auth.py', 'src/auth_v2.py')

    changes = _commit_and_collect(repo, base, monkeypatch, tmp_path)

    assert list(changes) == ['src/auth_v2.py']
    assert 'check_0' in _added(changes['src/auth_v2.py'])


class _FakeScanner:
    scanned = []

    def __init__(self, repo_url=None):
        pass

    def _load_file_extensions(self):
        return ['*.py']

    def _detect_language(self, path):
        return 'python'

    def scan_code_content_batch(self, batch, batch_descriptor=None):
        _FakeScanner.scanned.extend(batch)
        return []


def test_main_scans_renamed_and_non_ascii_files(repo, monkeypatch, tmp_path, capsys):
    base = _rev(repo)
    _git(repo, 'mv', 'src/auth.py', 'src/auth_v2.py')
    with open(repo / 'src' / 'auth_v2.py', 'a') as f:
        f.write(EVAL_LINE + '\n')
    (repo / 'src' / 'módulo').mkdir()
    (repo / 'src' / 'módulo' / 'handler.py').write_text(EVAL_LINE + '\n')
    _commit_and_collect(repo, base, monkeypatch, tmp_path)

    _FakeScanner.scanned = []
    monkeypatch.setattr(pr_scan, 'SecurityScanner', _FakeScanner)
    pr_scan.main()

    out = capsys.readouterr().out
    assert 'Scanned: src/auth_v2.py' in out
    assert 'Scanned: src/módulo/handler.py' in out
    assert all(EVAL_LINE in code for code, _, _ in _FakeScanner.scanned)


def test_main_names_changed_file_with_empty_diff_in_pr_comment(repo, monkeypatch, tmp_path):
    monkeypatch.setattr(pr_scan, 'get_pr_changes_from_github', lambda: [
        {'new_path': 'src/ghost.py', 'deleted_file': False, 'diff': ''},
    ])
    monkeypatch.setattr(pr_scan, 'SecurityScanner', _FakeScanner)

    pr_scan.main()

    comment = (repo / 'pr_comment.md').read_text()
    assert 'AI-SAST Security Scan' in comment
    assert '`src/ghost.py`' in comment
