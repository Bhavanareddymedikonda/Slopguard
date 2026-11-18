"""File-type knowledge: which files to scan, how their comments/strings look.

SlopGuard is language agnostic: it never needs a real parser. It only needs to
know how a language writes comments and strings so that rules can be applied to
"code only", "comments only" or "the whole line".
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass(frozen=True)
class Lang:
    """Lexical description of a language family."""

    line: Tuple[str, ...] = ()
    # (start, end, string_like). string_like blocks (Python triple quotes) are
    # treated as docstrings/comments only when they start a statement.
    blocks: Tuple[Tuple[str, str, bool], ...] = ()
    quotes: str = "\"'`"


_PY = Lang(("#",), (('"""', '"""', True), ("'''", "'''", True)))
_HASH = Lang(("#",))
_C = Lang(("//",), (("/*", "*/", False),))
_PHP = Lang(("//", "#"), (("/*", "*/", False),))
_SQL = Lang(("--",), (("/*", "*/", False),))
_HTML = Lang((), (("<!--", "-->", False),))
_WEB = Lang(("//",), (("/*", "*/", False), ("<!--", "-->", False)))
_CSS = Lang((), (("/*", "*/", False),), quotes="\"'")
_SCSS = Lang(("//",), (("/*", "*/", False),), quotes="\"'")
_LUA = Lang(("--",), (("--[[", "]]", False),))
_INI = Lang(("#", ";"))
_TF = Lang(("#", "//"), (("/*", "*/", False),))
_NONE = Lang()

# extension -> (language name, lexical description)
CODE_EXTS = {
    ".py": ("python", _PY), ".pyi": ("python", _PY), ".pyw": ("python", _PY),
    ".js": ("javascript", _C), ".jsx": ("javascript", _C),
    ".mjs": ("javascript", _C), ".cjs": ("javascript", _C),
    ".ts": ("typescript", _C), ".tsx": ("typescript", _C),
    ".java": ("java", _C), ".kt": ("kotlin", _C), ".kts": ("kotlin", _C),
    ".scala": ("scala", _C), ".groovy": ("groovy", _C), ".gradle": ("groovy", _C),
    ".c": ("c", _C), ".h": ("c", _C),
    ".cpp": ("cpp", _C), ".cc": ("cpp", _C), ".cxx": ("cpp", _C), ".hpp": ("cpp", _C),
    ".cs": ("csharp", _C), ".go": ("go", _C), ".rs": ("rust", _C),
    ".swift": ("swift", _C), ".dart": ("dart", _C), ".sol": ("solidity", _C),
    ".php": ("php", _PHP), ".rb": ("ruby", _HASH),
    ".sh": ("shell", _HASH), ".bash": ("shell", _HASH), ".zsh": ("shell", _HASH),
    ".ps1": ("powershell", _HASH), ".pl": ("perl", _HASH), ".r": ("r", _HASH),
    ".tf": ("terraform", _TF), ".sql": ("sql", _SQL), ".lua": ("lua", _LUA),
    ".html": ("html", _WEB), ".htm": ("html", _WEB), ".vue": ("vue", _WEB),
    ".svelte": ("svelte", _WEB), ".css": ("css", _CSS), ".scss": ("scss", _SCSS),
    ".less": ("scss", _SCSS), ".ipynb": ("notebook", _NONE),
}

CONFIG_EXTS = {
    ".json": ("json", _NONE), ".yml": ("yaml", _HASH), ".yaml": ("yaml", _HASH),
    ".toml": ("toml", _HASH), ".ini": ("ini", _INI), ".cfg": ("ini", _INI),
    ".conf": ("ini", _INI), ".properties": ("properties", _INI),
    ".env": ("dotenv", _HASH), ".tfvars": ("terraform", _TF),
    ".xml": ("xml", _HTML),
}

DOC_EXTS = {".md", ".markdown", ".rst", ".txt", ".adoc"}

SKIP_NAMES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock",
    "pipfile.lock", "cargo.lock", "composer.lock", "go.sum", "gemfile.lock",
    "uv.lock", "bun.lockb",
}
SKIP_SUFFIXES = (".min.js", ".min.css", ".map", ".svg", ".lock")

TEST_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "e2e", "fixtures", "fixture",
    "testdata", "mocks", "__mocks__", "examples", "example", "samples", "sample",
    "demo", "demos", "docs", "doc", "benchmarks", "testing",
}
TEST_FILE_RE = re.compile(
    r"(^test_|_test\.\w+$|\.test\.\w+$|\.spec\.\w+$|^conftest\.py$|tests?\.py$|Tests?\.java$|_spec\.rb$)"
)


def file_info(rel_path: str) -> Optional[Tuple[str, str, Lang]]:
    """Return (kind, language name, lexical description) or None to skip."""
    name = os.path.basename(rel_path)
    low = name.lower()
    if low in SKIP_NAMES or low.endswith(SKIP_SUFFIXES):
        return None
    if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
        return ("code", "dockerfile", _HASH)
    if low == "makefile" or low.endswith(".mk"):
        return ("code", "make", _HASH)
    if low.startswith(".env"):
        return ("config", "dotenv", _HASH)
    if low.startswith("requirements") and low.endswith(".txt"):
        return ("config", "requirements", _HASH)
    ext = os.path.splitext(low)[1]
    if ext in CODE_EXTS:
        lang, syn = CODE_EXTS[ext]
        return ("code", lang, syn)
    if ext in CONFIG_EXTS:
        lang, syn = CONFIG_EXTS[ext]
        return ("config", lang, syn)
    if ext in DOC_EXTS:
        return ("doc", "text", _NONE)
    return None


def is_test_path(rel_path: str) -> bool:
    parts = rel_path.replace("\\", "/").split("/")
    if any(p.lower() in TEST_DIRS for p in parts[:-1]):
        return True
    return bool(TEST_FILE_RE.search(parts[-1]))


def classify_lines(lines, lang: Lang):
    """Split every line into (code, comment) using a tiny lexer.

    Strings are kept in `code`, so a `#` inside a string is not a comment.
    Multi-line block comments and Python docstrings are tracked across lines.
    """
    out = []
    state = None  # None | (kind, end_marker); kind is "comment" | "string"
    for raw in lines:
        code, comment = [], []
        i, n = 0, len(raw)
        if state:
            kind, end = state
            j = raw.find(end)
            if j == -1:
                (comment if kind == "comment" else code).append(raw)
                out.append(("".join(code), "".join(comment)))
                continue
            seg = raw[: j + len(end)]
            (comment if kind == "comment" else code).append(seg)
            i, state = j + len(end), None
        quote = None
        while i < n:
            ch = raw[i]
            if quote:
                code.append(ch)
                if ch == "\\" and i + 1 < n:
                    code.append(raw[i + 1])
                    i += 2
                    continue
                if ch == quote:
                    quote = None
                i += 1
                continue
            hit = False
            for start, end, string_like in lang.blocks:
                if raw.startswith(start, i):
                    prefix = "".join(code).strip()
                    kind = "comment" if (not string_like or prefix == "") else "string"
                    j = raw.find(end, i + len(start))
                    if j == -1:
                        (comment if kind == "comment" else code).append(raw[i:])
                        state = (kind, end)
                        i = n
                    else:
                        (comment if kind == "comment" else code).append(raw[i : j + len(end)])
                        i = j + len(end)
                    hit = True
                    break
            if hit:
                continue
            if any(raw.startswith(tok, i) for tok in lang.line):
                comment.append(raw[i:])
                i = n
                break
            if ch in lang.quotes:
                quote = ch
            code.append(ch)
            i += 1
        out.append(("".join(code), "".join(comment)))
    return out
