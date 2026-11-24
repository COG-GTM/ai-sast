import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.main.pr_scan import parse_added_lines_from_diff


def test_added_line_starting_with_plus_plus_is_kept():
    diff = (
        "diff --git a/app.c b/app.c\n"
        "index 1111111..2222222 100644\n"
        "--- a/app.c\n"
        "+++ b/app.c\n"
        "@@ -1,2 +1,4 @@\n"
        " int main() {\n"
        "+++counter; system(cmd);\n"
        "+    return 0;\n"
        " }\n"
    )
    assert parse_added_lines_from_diff(diff) == "++counter; system(cmd);\n    return 0;"


def test_js_line_starting_with_plus_plus_and_removed_dash_dash():
    diff = (
        "--- a/x.js\n"
        "+++ b/x.js\n"
        "@@ -3,2 +3,2 @@ function f() {\n"
        "---i;\n"
        "+++globalThis.n; require(\"child_process\").exec(req.query.cmd);\n"
        " end();\n"
    )
    assert parse_added_lines_from_diff(diff) == (
        "++globalThis.n; require(\"child_process\").exec(req.query.cmd);"
    )


def test_headers_not_treated_as_code():
    diff = (
        "diff --git a/new.py b/new.py\n"
        "new file mode 100644\n"
        "--- /dev/null\n"
        "+++ b/new.py\n"
        "@@ -0,0 +1,2 @@\n"
        "+import os\n"
        "+os.system(x)\n"
        "\\ No newline at end of file\n"
    )
    assert parse_added_lines_from_diff(diff) == "import os\nos.system(x)"


def test_multiple_hunks_and_files():
    diff = (
        "--- a/a.c\n"
        "+++ b/a.c\n"
        "@@ -1 +1 @@\n"
        "-old\n"
        "+++a;\n"
        "@@ -10,0 +11 @@\n"
        "+b();\n"
        "diff --git a/b.c b/b.c\n"
        "--- a/b.c\n"
        "+++ b/b.c\n"
        "@@ -5,1 +5,2 @@\n"
        " ctx\n"
        "+++c;\n"
    )
    assert parse_added_lines_from_diff(diff) == "++a;\nb();\n++c;"


def test_empty_and_header_only_diff():
    assert parse_added_lines_from_diff("") == ""
    assert parse_added_lines_from_diff("--- a/x\n+++ b/x\n") == ""
