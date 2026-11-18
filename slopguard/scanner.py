"""The scanning engine: walk -> lex -> rules + detectors -> rank."""

from __future__ import annotations

import fnmatch
import os
import re
from typing import Dict, Iterable, List, Optional, Set

from . import detectors
from .languages import classify_lines, file_info, is_test_path
from .models import FileCtx, Finding, ScanResult, Severity
from .rules import RULES, Rule

IGNORE_DIRS = {
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__", "dist",
    "build", ".tox", ".mypy_cache", ".pytest_cache", ".idea", ".vscode", "vendor",
    "target", ".next", ".nuxt", "coverage", ".gradle", "bower_components", "site-packages",
    ".eggs", ".terraform", "Pods", ".cache",
}
MAX_BYTES = 1_000_000
SUPPRESS_RE = re.compile(r"slopguard:\s*(?:ignore|disable)(?:\s*[:=]?\s*(?P<ids>[A-Z]{3}\d{3}(?:\s*,\s*[A-Z]{3}\d{3})*))?", re.I)

CATEGORY_WEIGHT = {"security": 1.25, "gap": 1.0, "slop": 0.9}
SEV_POINTS = {Severity.INFO: 1, Severity.LOW: 4, Severity.MEDIUM: 12, Severity.HIGH: 30, Severity.CRITICAL: 60}


def load_ignore_file(root: str) -> List[str]:
    p = os.path.join(root, ".slopguardignore")
    if not os.path.isfile(p):
        return []
    with open(p, encoding="utf-8", errors="ignore") as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def walk(root: str, ignore_globs: Iterable[str] = ()) -> List[str]:
    ignore_globs = list(ignore_globs)
    found = []
    if os.path.isfile(root):
        return [os.path.basename(root)]
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if d not in IGNORE_DIRS)
        for name in sorted(filenames):
            rel = os.path.relpath(os.path.join(dirpath, name), root).replace(os.sep, "/")
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in ignore_globs):
                continue
            found.append(rel)
    return found


def read_file(root: str, rel: str) -> Optional[FileCtx]:
    info = file_info(rel)
    if info is None:
        return None
    kind, lang, syntax = info
    abspath = root if os.path.isfile(root) else os.path.join(root, rel)
    try:
        if os.path.getsize(abspath) > MAX_BYTES:
            return None
        with open(abspath, "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    if b"\x00" in raw[:4096]:
        return None
    text = raw.decode("utf-8", errors="replace")
    lines = text.splitlines()
    if lang == "notebook":
        lines = _notebook_lines(text) or lines
        syntax = file_info("x.py")[2]
        lang = "python"
    # minified / generated: a few huge lines
    if lines and (sum(len(l) for l in lines) / len(lines) > 400):
        return None
    return FileCtx(rel, abspath, kind, lang, syntax, lines, classify_lines(lines, syntax),
                   is_test=is_test_path(rel))


def _notebook_lines(text: str) -> List[str]:
    import json
    try:
        nb = json.loads(text)
    except ValueError:
        return []
    out: List[str] = []
    for cell in nb.get("cells", []):
        if cell.get("cell_type") == "code":
            src = cell.get("source", [])
            out.extend((src if isinstance(src, list) else src.splitlines(True)))
            out.append("\n")
    return [l.rstrip("\n") for l in out]


def _suppressed(f: FileCtx, line_no: int, rule_id: str) -> bool:
    for ln in (line_no, line_no - 1):
        if 1 <= ln <= len(f.lines):
            # the line above only counts when it is a comment-only line
            if ln != line_no and f.cls[ln - 1][0].strip():
                continue
            m = SUPPRESS_RE.search(f.lines[ln - 1])
            if m:
                ids = m.group("ids")
                if not ids or rule_id in [i.strip().upper() for i in ids.split(",")]:
                    return True
    return False


CLI_RE = re.compile(r"argparse|click\.|typer|sys\.argv|__main__|yargs|commander|cobra|flag\.Parse|process\.argv")
IGNORE_FILE_RE = re.compile(r"slopguard:\s*ignore-file", re.I)
PRINT_RULES = {"SLP003"}


def file_ignored(f: FileCtx) -> bool:
    return any(IGNORE_FILE_RE.search(l) for l in f.lines[:5])


def apply_rules(f: FileCtx, rules: List[Rule]) -> List[Finding]:
    out: List[Finding] = []
    is_cli = f.kind == "code" and bool(CLI_RE.search("\n".join(f.lines)))
    for rule in rules:
        if rule.id in PRINT_RULES and is_cli:
            continue
        if f.kind not in rule.kinds:
            continue
        if rule.langs and f.lang not in rule.langs:
            continue
        if f.lang in rule.not_langs:
            continue
        for i, raw in enumerate(f.lines):
            code, comment = f.cls[i]
            if rule.scope == "code":
                text = code
            elif rule.scope == "comment":
                text = comment
            else:
                text = raw
            if not text.strip() or len(text) > 600:
                continue
            m = rule.pattern.search(text)
            if not m or (rule.ok and not rule.ok(m)):
                continue
            out.append(Finding(
                rule.id, rule.category, rule.severity, rule.title, rule.message,
                f.path, i + 1, raw.strip()[:160], rule.confidence, rule.fix,
                in_test=f.is_test and not rule.keep_in_tests))
    return out


def rank(findings: List[Finding]) -> None:
    """Assign each finding a score and downgrade test/example hits."""
    for fd in findings:
        if fd.in_test:
            fd.severity = fd.severity.lowered()
            fd.confidence *= 0.7
            fd.note = "in test/example code"
        fd.score = SEV_POINTS[fd.severity] * fd.confidence * CATEGORY_WEIGHT.get(fd.category, 1.0)
    findings.sort(key=lambda x: (-x.score, x.path, x.line))


def dedupe(findings: List[Finding]) -> List[Finding]:
    seen: Dict[tuple, Finding] = {}
    for fd in findings:
        key = (fd.path, fd.line, fd.rule_id)
        if key not in seen or fd.score > seen[key].score:
            seen[key] = fd
    # same line, same category: keep the strongest to avoid stacking
    best: Dict[tuple, Finding] = {}
    for fd in seen.values():
        key = (fd.path, fd.line, fd.category, fd.rule_id[:3] if fd.path != "." else fd.rule_id)
        if key not in best or SEV_POINTS[fd.severity] * fd.confidence > SEV_POINTS[best[key].severity] * best[key].confidence:
            best[key] = fd
    return list(best.values())


def scan(root: str, min_severity: Severity = Severity.INFO, min_confidence: float = 0.0,
         include_tests: bool = True, ignore: Iterable[str] = (), only: Optional[Set[str]] = None,
         skip_rules: Optional[Set[str]] = None) -> ScanResult:
    root = os.path.abspath(root)
    ignore_globs = list(ignore) + load_ignore_file(root if os.path.isdir(root) else os.path.dirname(root))
    paths = walk(root, ignore_globs)
    rules = [r for r in RULES if (not only or r.id in only or r.category in only)
             and not (skip_rules and r.id in skip_rules)]

    files: List[FileCtx] = []
    ignored_ctx: List[FileCtx] = []
    findings: List[Finding] = []
    for rel in paths:
        f = read_file(root, rel)
        if f is None:
            continue
        if f.is_test and not include_tests:
            continue
        if file_ignored(f):
            ignored_ctx.append(f)
            continue
        files.append(f)
        findings += apply_rules(f, rules)
        if not only or "slop" in only or "SLP012" in only:
            findings += detectors.commented_out_code(f)
        if not only or {"slop", "gap", "SLP001", "GAP003"} & only:
            findings += [x for x in detectors.multiline_patterns(f)
                         if not only or x.category in only or x.rule_id in only]
        if not only or "slop" in only or "SLP013" in only:
            findings += detectors.unused_python_imports(f) + detectors.unused_js_imports(f)
        if not only or "slop" in only or "SLP015" in only:
            findings += detectors.long_functions(f)
    if not only or "slop" in only or "SLP014" in only:
        findings += detectors.duplicate_blocks(files)
    if os.path.isdir(root) and (not only or "gap" in only or "security" in only):
        findings += [x for x in detectors.project_checks(root, files + ignored_ctx, paths)
                     if not only or x.category in only or x.rule_id in only]

    by_path = {f.path: f for f in files}
    kept, suppressed = [], 0
    for fd in findings:
        f = by_path.get(fd.path)
        if f and _suppressed(f, fd.line, fd.rule_id):
            suppressed += 1
            continue
        kept.append(fd)
    kept = dedupe(kept)
    rank(kept)
    kept = [fd for fd in kept if fd.severity >= min_severity and fd.confidence >= min_confidence]

    langs: Dict[str, int] = {}
    for f in files:
        langs[f.lang] = langs.get(f.lang, 0) + 1
    stats = {
        "files_scanned": len(files),
        "lines_scanned": sum(len(f.lines) for f in files),
        "languages": dict(sorted(langs.items(), key=lambda kv: -kv[1])),
    }
    return ScanResult(root, kept, stats, suppressed)


def health_score(result: ScanResult) -> int:
    """0-100, higher is healthier. Normalised by code size so big repos aren't punished."""
    kloc = max(result.stats["lines_scanned"] / 1000.0, 0.5)
    penalty = sum(fd.score for fd in result.findings if not fd.dismissed) / kloc
    return max(0, min(100, round(100 - penalty * 0.6)))
