"""Tests that report links and model text cannot inject HTML or Markdown."""

import importlib.util
import re
from html.parser import HTMLParser
from pathlib import Path

# Load report.py directly so the test does not need the LLM SDKs that src.core imports.
_spec = importlib.util.spec_from_file_location(
    "ai_sast_report", Path(__file__).parent.parent / "src" / "core" / "report.py"
)
_report = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_report)
HTMLReportGenerator = _report.HTMLReportGenerator

REPO_URL = "https://github.com/acme/project.git"
EVIL_PATH = 'src/x" onmouseover="alert(1)"><img src=x onerror=alert(2)>`) [y](https://evil.example).py'
EVIL_REF = 'main"><script>alert(3)</script>'


def _results(path=EVIL_PATH, issue="SQL injection", risk="Data loss", fix="Use params"):
    return [{
        "file_path": path,
        "analysis": (
            "- **Vulnerability Level**: CRITICAL\n"
            f"- **Issue**: {issue}\n"
            "- **Location**: Line 42\n"
            f"- **Risk**: {risk}\n"
            f"- **Fix**: {fix}\n"
        ),
    }]


class _TagCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


def _tags(markup):
    parser = _TagCollector()
    parser.feed(markup)
    return parser.tags


def test_hyperlink_percent_encodes_ref_and_path_segments():
    link = HTMLReportGenerator()._create_hyperlink(REPO_URL, "feature/a b", 'dir/we"ird)`.py', 7)
    assert link == "https://github.com/acme/project/blob/feature/a%20b/dir/we%22ird%29%60.py#L7"


def test_hyperlink_gitlab_format_is_encoded():
    link = HTMLReportGenerator()._create_hyperlink("https://gitlab.com/g/p", "main", "a/<b>.py", None)
    assert link == "https://gitlab.com/g/p/-/blob/main/a/%3Cb%3E.py"


def test_hyperlink_rejects_non_http_repo_url():
    gen = HTMLReportGenerator()
    assert gen._create_hyperlink("javascript:alert(1)//github.com/a/b", "main", "a.py", 1) is None
    assert gen._create_hyperlink('https://github.com/a/b"onclick=x', "main", "a.py", 1) is None


def test_html_report_href_cannot_break_out_of_attribute():
    report = HTMLReportGenerator().generate_report(_results(), REPO_URL, EVIL_REF)
    anchors = [attrs for tag, attrs in _tags(report) if tag == "a" and "target" in attrs]
    assert len(anchors) == 1
    href = anchors[0]["href"]
    assert set(anchors[0]) == {"href", "target", "rel"}
    assert "%22" in href and '"' not in href
    assert href.startswith("https://github.com/acme/project/blob/main%22%3E%3Cscript%3E")
    tag_names = [tag for tag, _ in _tags(report)]
    assert "img" not in tag_names
    assert "script" not in tag_names


def test_markdown_report_contains_a_single_link():
    md = HTMLReportGenerator().generate_markdown_report(
        _results(issue="See [click here](https://evil.example) ![i](https://evil.example/x.png) @octocat"),
        "AI SAST", REPO_URL, EVIL_REF,
    )
    location = next(line for line in md.splitlines() if line.startswith("**Location**"))
    # The path is shown in one code span (backticks removed) followed by the link target.
    assert location.count("`") == 2
    outside_code = re.sub(r"`[^`]*`", "", location)
    link_targets = re.findall(r"\]\(([^)]*)\)", outside_code)
    assert len(link_targets) == 1
    target = link_targets[0]
    assert " " not in target and "(" not in target and ")" not in target
    assert "%22" in target and "%29" in target and "%60" in target

    issue_line = next(line for line in md.splitlines() if line.startswith("**Issue**"))
    assert "](" not in issue_line
    assert "\\[click here\\]\\(https://evil\\.example\\)" in issue_line
    assert "\\!\\[i\\]" in issue_line
    assert "@octocat" not in issue_line


def test_markdown_remediation_fence_cannot_be_closed_by_model_text():
    md = HTMLReportGenerator().generate_markdown_report(
        _results(fix="use x ``` then [phish](https://evil.example)"), "AI SAST", REPO_URL, "main",
    )
    assert "\n````\nuse x ``` then [phish](https://evil.example)\n````\n" in md


def test_markdown_renders_one_anchor_when_markdown_lib_available():
    markdown = __import__("pytest").importorskip("markdown")
    md = HTMLReportGenerator().generate_markdown_report(
        _results(issue="[click](https://evil.example)", risk="![x](https://evil.example/p.png)"),
        "AI SAST", REPO_URL, EVIL_REF,
    )
    # python-markdown leaves Markdown inside raw <details> blocks unparsed; drop the wrappers.
    rendered = markdown.markdown(re.sub(r"</?details>|<summary>.*?</summary>", "", md))
    tags = _tags(rendered)
    assert len([t for t, _ in tags if t == "a"]) == 1
    assert not [t for t, _ in tags if t in ("img", "script")]
