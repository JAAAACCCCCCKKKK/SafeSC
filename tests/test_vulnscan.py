"""tools/vulnscan.py — deterministic hidden-risk leads in a dependency's own source."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from safesc.tools.vulnscan import declared_dependencies, exact_pin, scan_tree, search_tree


def _tree(root: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return root


@pytest.fixture()
def project(tmp_path):
    return _tree(tmp_path, {
        "src/parse.c": "void f(char *in) {\n  char buf[16];\n  strcpy(buf, in);\n  gets(buf);\n}\n",
        "lib/auth.py": (
            "import hashlib, pickle, yaml\n"
            "def store(password):\n"
            "    return hashlib.md5(password.encode()).hexdigest()\n"
            "def load(blob):\n"
            "    return pickle.loads(blob)\n"
            "cfg = yaml.load(open('c'))\n"
            "safe = yaml.load(open('c'), Loader=yaml.SafeLoader)\n"
            "def check(token, other):\n"
            "    return token == other\n"
        ),
        "lib/net.js": (
            "const vm2 = require('vm2');\n"
            "exec(`rm -rf ${dir}`);\n"
            "const opts = { rejectUnauthorized: false };\n"
            "const API_KEY = 'abcdefghijklmnop1234';\n"
        ),
        "tests/test_auth.py": "import pickle\nx = pickle.loads(b'')\n",
        "node_modules/x/index.js": "eval(x)\n",
        "dist/app.min.js": "eval(x)\n",
    })


def test_scan_finds_the_requested_classes(project):
    report = scan_tree(project)
    ids = {(f.rule_id, f.file) for f in report.findings}
    assert ("C-STRCPY", "src/parse.c") in ids and ("C-GETS", "src/parse.c") in ids          # unsafe C functions
    assert ("PY-SECRET-HASH", "lib/auth.py") in ids                                          # unsalted hash of a password
    assert ("PY-DESERIALIZE", "lib/auth.py") in ids and ("PY-YAML-LOAD", "lib/auth.py") in ids
    assert ("PY-SECRET-COMPARE", "lib/auth.py") in ids
    assert ("IMPORT-UNSAFE", "lib/auth.py") in ids and ("IMPORT-UNSAFE", "lib/net.js") in ids  # publicly unsafe modules
    assert ("JS-EXEC", "lib/net.js") in ids and ("JS-TLS-OFF", "lib/net.js") in ids
    assert ("SECRET-LITERAL", "lib/net.js") in ids


def test_scan_respects_safe_forms_and_skips(project):
    report = scan_tree(project)
    yaml_lines = [f.line for f in report.findings if f.rule_id == "PY-YAML-LOAD"]
    assert yaml_lines == [6]  # the SafeLoader call on line 7 is not a lead
    files = {f.file for f in report.findings}
    assert not any(f.startswith(("node_modules/", "dist/")) for f in files)


def test_test_code_is_marked_and_sorted_last(project):
    report = scan_tree(project)
    tagged = [f for f in report.findings if f.file.startswith("tests/")]
    assert tagged and all(f.in_test_code for f in tagged)
    assert report.findings[-1].in_test_code


def test_scan_report_is_bounded_and_serialisable(tmp_path):
    _tree(tmp_path, {"a.c": "strcpy(a,b);\n" * 40})
    report = scan_tree(tmp_path)
    assert report.counts["C-STRCPY"] == 40 and len(report.findings) == 15 and report.truncated
    json.dumps(report.as_dict())


def test_search_is_literal_not_regex(tmp_path):
    _tree(tmp_path, {"a.py": "x = '(a+)+$'\nprint('Hello')\n"})
    assert [h["line"] for h in search_tree(tmp_path, "(a+)+$")] == [1]
    assert [h["line"] for h in search_tree(tmp_path, "hello")] == [2]
    assert search_tree(tmp_path, "   ") == []


def test_declared_dependencies_per_ecosystem(tmp_path):
    _tree(tmp_path / "js", {"package/package.json": json.dumps({"dependencies": {"request": "2.88.2", "left-pad": "^1.0"}})})
    _tree(tmp_path / "py", {"pkg-1.0/PKG-INFO": "Name: x\nRequires-Dist: pycrypto (==2.6.1)\nRequires-Dist: requests>=2; extra == 'a'\n"})
    _tree(tmp_path / "rs", {"Cargo.toml": '[dependencies]\nserde = "1.0"\nopenssl = { version = "0.10" }\n'})
    _tree(tmp_path / "go", {"go.mod": "module x\nrequire (\n\tgithub.com/a/b v1.2.3\n)\n"})
    _tree(tmp_path / "java", {"pom.xml": "<dependency><groupId>g</groupId><artifactId>a</artifactId><version>1.0</version></dependency>"})
    assert {d["name"] for d in declared_dependencies(tmp_path / "js", "javascript")} == {"request", "left-pad"}
    assert [d["name"] for d in declared_dependencies(tmp_path / "py", "python")] == ["pycrypto", "requests"]
    assert {d["name"]: d["spec"] for d in declared_dependencies(tmp_path / "rs", "rust")} == {"serde": "1.0", "openssl": "0.10"}
    assert declared_dependencies(tmp_path / "go", "go")[0]["name"] == "github.com/a/b"
    assert declared_dependencies(tmp_path / "java", "java")[0]["name"] == "g:a"


@pytest.mark.parametrize("spec,pin", [("==2.6.1", "2.6.1"), ("2.88.2", "2.88.2"), ("v1.2.3", "1.2.3"), ("^1.0", None), (">=2", None), ("", None)])
def test_exact_pin(spec, pin):
    assert exact_pin(spec) == pin
