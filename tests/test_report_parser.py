#!/usr/bin/env python3
"""
Regression tests for finding parsing: a finding whose one-line Fix ends the
analysis text (no trailing newline) must not be dropped.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.core.finding_parser import parse_findings
from src.core.report import HTMLReportGenerator
from src.core.scanner import SecurityScanner


SINGLE_FINDING = (
    "- **Vulnerability Level**: HIGH\n"
    "- **Issue**: SQL injection in get_user\n"
    "- **Location**: Line 12\n"
    "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n"
    "- **Risk**: Attacker can read the whole users table.\n"
    "- **Fix**: Use bound query parameters."
)


def test_one_line_fix_without_trailing_newline_is_parsed():
    vulns = HTMLReportGenerator()._parse_vulnerabilities(SINGLE_FINDING)

    assert len(vulns["High"]) == 1
    finding = vulns["High"][0]
    assert finding["issue"] == "SQL injection in get_user"
    assert finding["location"] == "Line 12"
    assert finding["cvss_vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert finding["fix"] == "Use bound query parameters."


def test_last_finding_of_batch_file_reaches_report():
    response = (
        "Analysis of 2 files.\n## File: app/db.py\n" + SINGLE_FINDING + "\n\n"
        "## File: app/views.py\nNo vulnerabilities found.\n"
    )
    scanner = object.__new__(SecurityScanner)
    results = scanner._parse_batch_response(response, ["app/db.py", "app/views.py"])

    by_severity = HTMLReportGenerator()._process_results_by_severity(results)

    assert [v["file_path"] for v in by_severity["High"]] == ["app/db.py"]


def test_every_finding_parsed_with_and_without_blank_line_separators():
    second = SINGLE_FINDING.replace("HIGH", "LOW").replace("SQL injection", "Debug flag")
    for separator in ("\n", "\n\n"):
        text = SINGLE_FINDING + separator + second
        vulns = HTMLReportGenerator()._parse_vulnerabilities(text)
        assert len(vulns["High"]) == 1, separator
        assert len(vulns["Low"]) == 1, separator
        assert len(parse_findings(text)) == 2, separator


def test_report_and_storage_parsers_agree():
    text = SINGLE_FINDING + "\n\n" + SINGLE_FINDING.replace("HIGH", "INFO")
    stored = parse_findings(text)
    reported = HTMLReportGenerator()._parse_vulnerabilities(text)

    assert [f["severity"] for f in stored] == ["HIGH", "INFO"]
    assert stored[0]["location"] == reported["High"][0]["location"]
    assert stored[0]["issue"] == reported["High"][0]["issue"]
    assert stored[0]["fix"] == reported["High"][0]["fix"]


def test_finding_without_cvss_vector_is_parsed():
    text = SINGLE_FINDING.replace(
        "- **CVSS Vector**: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H\n", ""
    )
    vulns = HTMLReportGenerator()._parse_vulnerabilities(text)

    assert len(vulns["High"]) == 1
    assert vulns["High"][0]["location"] == "Line 12"
    assert "cvss_vector" not in vulns["High"][0]
