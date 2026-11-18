# slopguard: ignore-file  (fixtures below intentionally contain vulnerable code)
import json
import os
import textwrap

import pytest

from slopguard.cli import main
from slopguard.languages import classify_lines, file_info
from slopguard.models import Severity
from slopguard.report import to_json, to_markdown, to_sarif, to_text
from slopguard.scanner import health_score, scan


def make(tmp_path, files):
    for name, body in files.items():
        p = tmp_path / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(body).lstrip("\n"))
    return str(tmp_path)


def ids(result):
    return {f.rule_id for f in result.findings}


def test_detects_hardcoded_secret_and_ignores_env_lookup(tmp_path):
    root = make(tmp_path, {"a.py": """
        import os
        password = "Zq8!vN3xLp0Rt5Wb"
        token = os.environ["TOKEN"]
        api_key = "your_api_key_here"
        """})
    r = scan(root)
    secrets = [f for f in r.findings if f.rule_id == "SEC004"]
    assert [f.line for f in secrets] == [2]


def test_aws_key_and_private_key(tmp_path):
    key = "AKIA" + "Q3X9TRVLMD4HZPW2"
    root = make(tmp_path, {"c.js": f'const k = "{key}";\n',
                           "k.txt.md": "-----BEGIN RSA PRIVATE KEY-----\n"})
    assert {"SEC001", "SEC002"} <= ids(scan(root))


def test_sql_injection_and_shell(tmp_path):
    root = make(tmp_path, {"a.py": """
        def f(uid, host):
            db.execute("SELECT * FROM t WHERE id=" + uid)
            os.system(f"ping {host}")
            return eval(host)
        """})
    assert {"SEC010", "SEC008", "SEC007"} <= ids(scan(root))


def test_parameterised_sql_not_flagged(tmp_path):
    root = make(tmp_path, {"a.py": 'db.execute("SELECT * FROM t WHERE id=?", (uid,))\n'})
    assert "SEC010" not in ids(scan(root))


def test_comment_vs_string_scoping(tmp_path):
    root = make(tmp_path, {"a.py": '''
        url = "see # TODO in docs"
        x = 1  # TODO: real one
        '''})
    todos = [f for f in scan(root).findings if f.rule_id == "GAP001"]
    assert [f.line for f in todos] == [2]


def test_swallowed_exception_multiline(tmp_path):
    root = make(tmp_path, {"a.py": """
        try:
            x()
        except ValueError:
            pass
        """, "b.js": "try { a(); } catch (e) {\n}\n"})
    r = scan(root)
    assert sum(1 for f in r.findings if f.rule_id == "SLP001") == 2


def test_unused_import_python(tmp_path):
    root = make(tmp_path, {"a.py": """
        import os
        import sys
        print(sys.argv)
        """})
    msgs = [f.message for f in scan(root).findings if f.rule_id == "SLP013"]
    assert any("`os`" in m for m in msgs) and not any("`sys`" in m for m in msgs)


def test_ai_leftover_and_stub(tmp_path):
    root = make(tmp_path, {"a.py": """
        # Here is the updated code
        def f():
            raise NotImplementedError
        """})
    assert {"SLP005", "GAP002"} <= ids(scan(root))


def test_commented_out_code_block(tmp_path):
    root = make(tmp_path, {"a.js": """
        // if (user.valid) {
        //   save(user);
        //   notify(user);
        // }
        run();
        """})
    assert "SLP012" in ids(scan(root))


def test_duplicate_blocks(tmp_path):
    body = "\n".join(f"    value_{i} = compute_something_long({i}, 'argument_{i}')" for i in range(10))
    root = make(tmp_path, {"a.py": f"def a():\n{body}\n", "b.py": f"def b():\n{body}\n"})
    assert "SLP014" in ids(scan(root))


def test_test_files_are_downgraded(tmp_path):
    root = make(tmp_path, {"src/a.py": "x = eval(y)\n", "tests/test_a.py": "x = eval(y)\n"})
    r = scan(root)
    by_path = {f.path: f for f in r.findings if f.rule_id == "SEC007"}
    assert by_path["tests/test_a.py"].severity < by_path["src/a.py"].severity


def test_suppression_comment(tmp_path):
    root = make(tmp_path, {"a.py": "x = eval(y)  # slopguard: ignore SEC007\nz = eval(q)\n"})
    r = scan(root)
    assert [f.line for f in r.findings if f.rule_id == "SEC007"] == [2]
    assert r.suppressed == 1


def test_ignore_file_and_node_modules(tmp_path):
    root = make(tmp_path, {"node_modules/x.js": "eval(a)\n", "gen/y.py": "eval(a)\n",
                           ".slopguardignore": "gen/*\n"})
    assert "SEC007" not in ids(scan(root))


def test_project_checks(tmp_path):
    root = make(tmp_path, {"a.py": "x=1\n", "b.py": "y=2\n", "c.py": "z=3\n", ".env": "A=1\n"})
    r = ids(scan(root))
    assert {"GAP020", "GAP022", "SEC026"} <= r


def test_requirements_unpinned(tmp_path):
    root = make(tmp_path, {"requirements.txt": "flask\nrequests==2.0\n"})
    hits = [f for f in scan(root).findings if f.rule_id == "GAP007"]
    assert len(hits) == 1 and "flask" in hits[0].snippet


def test_dockerfile_and_shell(tmp_path):
    root = make(tmp_path, {"Dockerfile": "FROM python:latest\nUSER root\n",
                           "i.sh": "curl https://x.io/i.sh | bash\n"})
    assert {"SEC022", "SEC023"} <= ids(scan(root))


def test_min_severity_filter(tmp_path):
    root = make(tmp_path, {"a.py": "x = eval(y)  # TODO later\n"})
    r = scan(root, min_severity=Severity.HIGH)
    assert all(f.severity >= Severity.HIGH for f in r.findings) and r.findings


def test_notebook_support(tmp_path):
    nb = {"cells": [{"cell_type": "code", "source": ["x = eval(input())\n"]}]}
    (tmp_path / "n.ipynb").write_text(json.dumps(nb))
    assert "SEC007" in ids(scan(str(tmp_path)))


def test_lexer_handles_block_comments_and_docstrings():
    lang = file_info("a.js")[2]
    out = classify_lines(["/* a", "b */ x();", "y(); // z"], lang)
    assert out[0][1] and out[1][0].strip() == "x();" and out[2][1] == "// z"
    py = file_info("a.py")[2]
    out = classify_lines(['"""doc', 'more', '"""', 'x = "#not comment"'], py)
    assert out[1][1] == "more" and out[3][1] == ""


def test_reports_render(tmp_path):
    root = make(tmp_path, {"a.py": "x = eval(y)\n"})
    r = scan(root)
    assert "SEC007" in to_text(r)
    assert "# SlopGuard report" in to_markdown(r)
    assert json.loads(to_json(r))["findings"]
    assert json.loads(to_sarif(r))["runs"][0]["results"]
    assert 0 <= health_score(r) <= 100


def test_clean_code_scores_high(tmp_path):
    root = make(tmp_path, {"README.md": "# x\n", "LICENSE": "MIT\n", ".gitignore": "x\n",
                           "a.py": "def add(a, b):\n    return a + b\n"})
    assert health_score(scan(root)) >= 95


def test_cli_fail_on_and_output(tmp_path, capsys):
    root = make(tmp_path, {"a.py": "x = eval(y)\n"})
    out = tmp_path / "r.md"
    assert main([root, "-f", "markdown", "-o", str(out), "--fail-on", "high"]) == 1
    assert "SEC007" in out.read_text()
    assert main([root, "--fail-on", "critical"]) == 0
    assert main(["/does/not/exist"]) == 2
    assert main(["--list-rules"]) == 0


def test_llm_triage_without_key_is_graceful(tmp_path, monkeypatch):
    from slopguard.triage import llm_triage
    for k in ("ANTHROPIC_API_KEY", "OPENAI_API_KEY", "SLOPGUARD_API_KEY"):
        monkeypatch.delenv(k, raising=False)
    r = scan(make(tmp_path, {"a.py": "x = eval(y)\n"}))
    assert llm_triage(r)["enabled"] is False


def test_llm_triage_applies_verdicts(tmp_path, monkeypatch):
    from slopguard import triage
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k")
    r = scan(make(tmp_path, {"a.py": "x = eval(y)\n"}), only={"security"})
    monkeypatch.setattr(triage, "_call", lambda *a, **k: json.dumps(
        [{"id": 0, "verdict": "false_positive", "explanation": "constant", "fix": ""}]))
    info = triage.llm_triage(r)
    assert info["dismissed"] == 1 and r.findings[0].dismissed


def test_token_type_and_lowercase_words_not_secrets(tmp_path):
    root = make(tmp_path, {"a.py": "token_type = 'encoded-word'\nauth_token = 'quoted-string'\n"})
    assert "SEC004" not in ids(scan(root))
