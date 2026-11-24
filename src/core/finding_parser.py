"""
Shared parser for the finding format the scanner asks the LLM to produce.
"""

import re
from typing import Dict, List

FINDING_PATTERN = re.compile(
    r"-\s*\*\*Vulnerability Level\*\*:\s*(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*\n"
    r"-\s*\*\*Issue\*\*:\s*(.*?)\n"
    r"-\s*\*\*Location\*\*:\s*(.*?)\n"
    r"(?:-\s*\*\*CVSS Vector\*\*:\s*(.*?)\n)?"
    r"-\s*\*\*Risk\*\*:\s*(.*?)\n"
    r"-\s*\*\*Fix\*\*:\s*(.*?)(?=\n-|\n\n|\Z)",
    re.DOTALL | re.IGNORECASE
)


def parse_findings(analysis_text: str) -> List[Dict]:
    """Return every finding in the analysis text, including one whose Fix ends the text."""
    findings = []
    for match in FINDING_PATTERN.finditer(analysis_text or ""):
        level, issue, location, cvss_vector, risk, fix = match.groups()
        findings.append({
            "severity": level.strip(),
            "issue": issue.strip(),
            "location": location.strip(),
            "cvss_vector": cvss_vector.strip() if cvss_vector else None,
            "risk": risk.strip(),
            "fix": fix.strip(),
        })
    return findings
