"""Cross-line and cross-file detectors that plain per-line regexes cannot do."""

from __future__ import annotations

import ast
import hashlib
import os
import re
from typing import Dict, Iterable, List, Tuple

from .models import FileCtx, Finding, Severity

S = Severity

CODE_HINT = re.compile(
    r"""(?x)(?:;\s*$|\{\s*$|^\s*\}|\)\s*\{|^\s*(?:if|for|while|return|import|from|def|class|function|const|let|var|try|except|else|elif)\b.*[:({;]?\s*$|
    \w+\s*=\s*[\w"'\[(].*|\w+\.\w+\(.*\)|^\s*[\w.]+\([^)]*\)\s*;?\s*$)"""
)
PROSE_HINT = re.compile(r"^\s*[A-Z][a-z]+(?:\s+[a-z]+){3,}[.!?]?\s*$")


def _strip_marker(c: str) -> str:
    return re.sub(r"^\s*(?://+|#+|--+|/\*+|\*+/?)\s?", "", c).rstrip()


def commented_out_code(f: FileCtx) -> List[Finding]:
    """Runs of >=3 consecutive comment lines that look like code."""
    if f.kind != "code":
        return []
    out: List[Finding] = []
    run: List[int] = []

    def flush():
        if len(run) >= 3:
            i = run[0]
            out.append(Finding(
                "SLP012", "slop", S.LOW, "Block of commented-out code",
                f"{len(run)} consecutive comment lines look like disabled code.",
                f.path, i + 1, f.lines[i].strip()[:120], 0.6,
                "Delete it - version control remembers.", f.is_test))
        run.clear()

    for idx, (code, comment) in enumerate(f.cls):
        is_c = comment.strip() and not code.strip()
        text = _strip_marker(comment) if is_c else ""
        if (is_c and text and not PROSE_HINT.match(text) and CODE_HINT.search(text)
                and not re.match(r"^\s*(?:TODO|FIXME|NOTE|XXX|HACK)", text)
                and not text.lstrip().startswith(("http", "@", "-", "*"))):
            run.append(idx)
        else:
            flush()
    flush()
    return out


def unused_python_imports(f: FileCtx) -> List[Finding]:
    if f.lang != "python" or f.path.endswith("__init__.py"):
        return []
    try:
        tree = ast.parse("\n".join(f.lines))
    except (SyntaxError, ValueError):
        return []
    imported: Dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                imported[(a.asname or a.name).split(".")[0]] = node.lineno
        elif isinstance(node, ast.ImportFrom):
            if node.module == "__future__":
                continue
            for a in node.names:
                if a.name != "*":
                    imported[a.asname or a.name] = node.lineno
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    used |= {n.value.id for n in ast.walk(tree)
             if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)}
    exported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and any(
                isinstance(t, ast.Name) and t.id == "__all__" for t in node.targets):
            exported |= {e.value for e in getattr(node.value, "elts", []) if isinstance(e, ast.Constant)}
    text_no_imports = "\n".join(
        l for l in f.lines if not re.match(r"\s*(?:from\s+\S+\s+)?import\s", l))
    out = []
    for name, line in sorted(imported.items(), key=lambda kv: kv[1]):
        if name in used or name in exported:
            continue
        if re.search(rf"[\"'][^\"'\n]*\b{re.escape(name)}\b", text_no_imports):
            continue  # referenced in a string annotation
        out.append(Finding(
            "SLP013", "slop", S.LOW, "Unused import",
            f"`{name}` is imported but never used.", f.path, line,
            f.lines[line - 1].strip()[:120], 0.9,
            "Remove the import.", f.is_test))
    return out


def unused_js_imports(f: FileCtx) -> List[Finding]:
    if f.lang not in ("javascript", "typescript"):
        return []
    src = "\n".join(c for c, _ in f.cls)
    out = []
    for i, (code, _) in enumerate(f.cls):
        m = re.match(r"\s*import\s+(?:type\s+)?(?P<names>[^'\"]+?)\s+from\s+['\"]", code)
        if not m:
            continue
        names = re.findall(r"[A-Za-z_$][\w$]*", re.sub(r"\bas\b|\btype\b", " ", m.group("names")))
        for n in names:
            if len(re.findall(rf"(?<![\w$]){re.escape(n)}(?![\w$])", src)) <= 1:
                out.append(Finding(
                    "SLP013", "slop", S.LOW, "Unused import",
                    f"`{n}` is imported but never used.", f.path, i + 1,
                    f.lines[i].strip()[:120], 0.75, "Remove the import.", f.is_test))
    return out


def _norm(line: str) -> str:
    return re.sub(r"\s+", " ", line.strip())


def duplicate_blocks(files: Iterable[FileCtx], window: int = 8) -> List[Finding]:
    """Copy-pasted code: identical windows of `window` meaningful lines."""
    seen: Dict[str, Tuple[str, int]] = {}
    out: List[Finding] = []
    reported = set()
    for f in files:
        if f.kind != "code" or f.lang in ("css", "scss", "html", "sql", "notebook"):
            continue
        norm = [(i, _norm(c)) for i, (c, _) in enumerate(f.cls) if len(_norm(c)) > 3]
        norm = [(i, n) for i, n in norm if n not in {"{", "}", ")", "});", "end", "else:", "try:", "else {", "};"}]
        skip_until = -1
        for k in range(len(norm) - window + 1):
            start_line = norm[k][0]
            if start_line <= skip_until:
                continue
            chunk = [n for _, n in norm[k:k + window]]
            if sum(len(c) for c in chunk) < window * 14:
                continue
            h = hashlib.blake2b("\n".join(chunk).encode(), digest_size=16).hexdigest()
            if h in seen:
                of, ol = seen[h]
                key = (f.path, of, h)
                if of == f.path and abs(ol - start_line) < window:
                    continue
                if key not in reported:
                    reported.add(key)
                    out.append(Finding(
                        "SLP014", "slop", S.MEDIUM, "Copy-pasted block",
                        f"These {window}+ lines duplicate code at {of}:{ol + 1}.",
                        f.path, start_line + 1, f.lines[start_line].strip()[:120], 0.7,
                        "Extract a shared function.", f.is_test))
                skip_until = norm[k + window - 1][0]
            else:
                seen[h] = (f.path, start_line)
    return out


def long_functions(f: FileCtx, limit: int = 80) -> List[Finding]:
    if f.lang != "python":
        return []
    try:
        tree = ast.parse("\n".join(f.lines))
    except (SyntaxError, ValueError):
        return []
    out = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            if end - node.lineno + 1 > limit:
                out.append(Finding(
                    "SLP015", "slop", S.LOW, "Very long function",
                    f"`{node.name}` spans {end - node.lineno + 1} lines.", f.path, node.lineno,
                    f.lines[node.lineno - 1].strip()[:120], 0.5,
                    "Split it into smaller, named steps.", f.is_test))
    return out


def project_checks(root: str, files: List[FileCtx], all_paths: List[str]) -> List[Finding]:
    """Repository-level gaps: README, license, tests, ignore files, secrets files."""
    out: List[Finding] = []
    low = {p.lower() for p in all_paths}
    names = {os.path.basename(p).lower() for p in all_paths}

    def gap(rule, sev, title, msg, fix, path=".", conf=0.7, cat="gap"):
        out.append(Finding(rule, cat, sev, title, msg, path, 1, "", conf, fix))

    if not any(n.startswith("readme") for n in names):
        gap("GAP020", S.MEDIUM, "No README", "The repository has no README.", "Add a README.md.")
    if not any(n.startswith(("license", "licence", "copying")) for n in names):
        gap("GAP021", S.LOW, "No LICENSE", "No license file found.", "Add a LICENSE.", conf=0.5)
    code_files = [f for f in files if f.kind == "code"]
    if len(code_files) >= 3 and not any(f.is_test for f in code_files):
        gap("GAP022", S.MEDIUM, "No tests", "Source files exist but no tests were found.",
            "Add automated tests.", conf=0.6)
    if code_files and ".gitignore" not in names:
        gap("GAP023", S.LOW, "No .gitignore", "Missing .gitignore.", "Add one to avoid committing build/secret files.", conf=0.5)
    for p in all_paths:
        base = os.path.basename(p).lower()
        if (base == ".env" or (base.startswith(".env.") and not base.endswith((".example", ".sample", ".template")))
                or base.endswith((".pem", ".p12", ".pfx", ".keystore", ".jks")) or base in ("id_rsa", "id_dsa", "id_ed25519")):
            out.append(Finding("SEC026", "security", S.HIGH, "Sensitive file in repository",
                               f"`{p}` usually holds secrets and should not be committed.", p, 1, "", 0.8,
                               "Remove it from history and add it to .gitignore.", False))
    return out


def multiline_patterns(f: FileCtx) -> List[Finding]:
    """Patterns that span two lines: swallowed exceptions, empty handlers/bodies."""
    if f.kind != "code":
        return []
    out: List[Finding] = []
    code = [c.strip() for c, _ in f.cls]

    def nxt(i):
        j = i + 1
        while j < len(code) and not code[j]:
            j += 1
        return j

    for i, c in enumerate(code):
        if not c:
            continue
        j = nxt(i)
        n = code[j] if j < len(code) else ""
        if f.lang == "python":
            if re.match(r"except\b[^:]*:\s*$", c) and n in ("pass", "...", "continue"):
                out.append(Finding("SLP001", "slop", S.MEDIUM, "Swallowed exception",
                                   "An error is caught and silently ignored.", f.path, i + 1,
                                   f"{f.lines[i].strip()} / {n}", 0.8,
                                   "Log it, handle it or re-raise it.", f.is_test))
            elif re.match(r"(?:async\s+)?def\s+\w+\(.*\)\s*(?:->.*)?:\s*$", c) and n in ("pass", "..."):
                out.append(Finding("GAP003", "gap", S.LOW, "Empty function / placeholder body",
                                   "Function body is empty.", f.path, i + 1, f.lines[i].strip(), 0.45,
                                   "Implement it, or document that it is an abstract hook.", f.is_test))
        elif f.lang in ("javascript", "typescript", "java", "kotlin", "csharp", "php", "swift", "dart", "scala"):
            if re.search(r"\bcatch\s*(?:\([^)]*\))?\s*\{$", c) and n == "}":
                out.append(Finding("SLP001", "slop", S.MEDIUM, "Swallowed exception",
                                   "An error is caught and silently ignored.", f.path, i + 1,
                                   f.lines[i].strip(), 0.8, "Log it, handle it or re-raise it.", f.is_test))
        elif f.lang == "go":
            if re.match(r"if\s+err\s*!=\s*nil\s*\{$", c) and n == "}":
                out.append(Finding("SLP001", "slop", S.MEDIUM, "Swallowed exception",
                                   "An error is checked and then ignored.", f.path, i + 1,
                                   f.lines[i].strip(), 0.8, "Return or log the error.", f.is_test))
    return out
