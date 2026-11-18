"""Core data types shared by every part of SlopGuard."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Tuple

from .languages import Lang


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, text: str) -> "Severity":
        try:
            return cls[text.strip().upper()]
        except KeyError as exc:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {text!r} (choose from: {names})") from exc

    @property
    def label(self) -> str:
        return self.name.lower()

    def lowered(self) -> "Severity":
        return Severity(max(0, int(self) - 1))


CATEGORIES = ("security", "slop", "gap")
CATEGORY_TITLES = {
    "security": "Security",
    "slop": "Slop",
    "gap": "Gaps & loose ends",
}


@dataclass
class Finding:
    rule_id: str
    category: str
    severity: Severity
    title: str
    message: str
    path: str
    line: int
    snippet: str = ""
    confidence: float = 0.8
    fix: str = ""
    in_test: bool = False       # found in test/example code -> gets downgraded
    note: str = ""
    score: float = 0.0
    verdict: str = ""           # LLM triage: true_positive | false_positive | uncertain
    explanation: str = ""       # LLM triage: why
    ai_fix: str = ""            # LLM triage: suggested fix
    dismissed: bool = False     # LLM triage says it is a false positive

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "severity": self.severity.label,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "snippet": self.snippet,
            "confidence": round(self.confidence, 2),
            "score": round(self.score, 2),
            "fix": self.fix,
            "note": self.note,
            "verdict": self.verdict,
            "explanation": self.explanation,
            "ai_fix": self.ai_fix,
        }


@dataclass
class FileCtx:
    """A file that has been read and lexed, ready for rules and detectors."""

    path: str                      # posix path relative to the scan root
    abspath: str
    kind: str                      # code | config | doc
    lang: str                      # language name, e.g. "python"
    syntax: Lang
    lines: List[str]
    cls: List[Tuple[str, str]]     # per line: (code part, comment part)
    is_test: bool = False
    py_imports: List[Tuple[str, int]] = field(default_factory=list)


@dataclass
class ScanResult:
    root: str
    findings: List[Finding]
    stats: Dict[str, Any]
    suppressed: int = 0
    llm_info: Dict[str, Any] = field(default_factory=dict)
