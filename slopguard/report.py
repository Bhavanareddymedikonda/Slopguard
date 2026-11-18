"""Report renderers: markdown, json, text, sarif."""

from __future__ import annotations

import json
from collections import Counter
from typing import List

from . import __version__
from .models import CATEGORIES, CATEGORY_TITLES, Finding, ScanResult, Severity
from .scanner import health_score

ICON = {Severity.CRITICAL: "🔴", Severity.HIGH: "🟠", Severity.MEDIUM: "🟡", Severity.LOW: "🔵", Severity.INFO: "⚪"}


def summary_counts(result: ScanResult):
    live = [f for f in result.findings if not f.dismissed]
    by_sev = Counter(f.severity.label for f in live)
    by_cat = Counter(f.category for f in live)
    return live, by_sev, by_cat


def headline(result: ScanResult) -> str:
    live, by_sev, by_cat = summary_counts(result)
    if not live:
        return "No issues found. Clean scan."
    bits = []
    if by_sev["critical"] or by_sev["high"]:
        bits.append(f"{by_sev['critical'] + by_sev['high']} high-impact issue(s) need attention first")
    if by_cat["security"]:
        bits.append(f"{by_cat['security']} security")
    if by_cat["slop"]:
        bits.append(f"{by_cat['slop']} slop")
    if by_cat["gap"]:
        bits.append(f"{by_cat['gap']} gaps/loose ends")
    return "; ".join(bits[:1] + [", ".join(bits[1:])]) if len(bits) > 1 else bits[0]


def _display_root(root: str) -> str:
    import os
    rel = os.path.relpath(root)
    return rel if not rel.startswith("..") else root


def _loc(f: Finding) -> str:
    return f"{f.path}:{f.line}" if f.path != "." else "(repository)"


def to_json(result: ScanResult) -> str:
    live, by_sev, by_cat = summary_counts(result)
    doc = {
        "tool": "slopguard", "version": __version__, "target": result.root,
        "health_score": health_score(result), "summary": headline(result),
        "stats": result.stats, "counts": {"severity": dict(by_sev), "category": dict(by_cat)},
        "suppressed": result.suppressed, "llm": result.llm_info,
        "findings": [f.to_dict() | {"dismissed": f.dismissed} for f in result.findings],
    }
    return json.dumps(doc, indent=2)


def to_text(result: ScanResult, limit: int = 50) -> str:
    live, by_sev, _ = summary_counts(result)
    out = [f"SlopGuard {__version__} - {result.stats['files_scanned']} files, "
           f"{result.stats['lines_scanned']} lines - health {health_score(result)}/100",
           headline(result), ""]
    for f in live[:limit]:
        out.append(f"[{f.severity.label.upper():8}] {f.rule_id} {_loc(f)}  {f.title}")
        if f.snippet:
            out.append(f"           > {f.snippet[:110]}")
        if f.explanation:
            out.append(f"           AI: {f.explanation}")
    if len(live) > limit:
        out.append(f"... and {len(live) - limit} more (use --format markdown/json for all)")
    out.append("")
    out.append("Totals: " + ", ".join(f"{k}={v}" for k, v in sorted(by_sev.items())))
    return "\n".join(out)


def to_markdown(result: ScanResult, max_per_section: int = 40) -> str:
    live, by_sev, by_cat = summary_counts(result)
    dismissed = [f for f in result.findings if f.dismissed]
    score = health_score(result)
    L: List[str] = []
    L.append("# SlopGuard report")
    L.append("")
    L.append(f"**Target:** `{_display_root(result.root)}`  ")
    L.append(f"**Scanned:** {result.stats['files_scanned']} files · {result.stats['lines_scanned']:,} lines · "
             + ", ".join(f"{k} ({v})" for k, v in list(result.stats["languages"].items())[:6]))
    L.append("")
    L.append(f"## Health score: {score}/100")
    L.append("")
    L.append(f"> {headline(result)}")
    L.append("")
    L.append("| Severity | Count |")
    L.append("|---|---|")
    for sev in sorted(Severity, reverse=True):
        if by_sev[sev.label]:
            L.append(f"| {ICON[sev]} {sev.label} | {by_sev[sev.label]} |")
    L.append("")
    L.append("| Category | Count |")
    L.append("|---|---|")
    for c in CATEGORIES:
        L.append(f"| {CATEGORY_TITLES[c]} | {by_cat[c]} |")
    if result.suppressed:
        L.append("")
        L.append(f"_{result.suppressed} finding(s) suppressed with `slopguard: ignore`._")
    if result.llm_info.get("enabled"):
        li = result.llm_info
        L.append("")
        L.append(f"_LLM triage: {li['triaged']} findings reviewed by `{li['model']}`, "
                 f"{li['dismissed']} dismissed as false positives._")

    top = live[:10]
    if top:
        L += ["", "## Fix these first", ""]
        for i, f in enumerate(top, 1):
            L.append(f"{i}. {ICON[f.severity]} **{f.title}** - `{_loc(f)}` ({f.category})")
            fix = f.ai_fix or f.fix
            if fix:
                L.append(f"   - {fix}")

    for cat in CATEGORIES:
        items = [f for f in live if f.category == cat]
        if not items:
            continue
        L += ["", f"## {CATEGORY_TITLES[cat]} ({len(items)})", ""]
        for f in items[:max_per_section]:
            L.append(f"### {ICON[f.severity]} {f.title} · `{f.rule_id}` · {f.severity.label}"
                     + (f" · _{f.note}_" if f.note else ""))
            L.append(f"`{_loc(f)}` · confidence {f.confidence:.0%}")
            if f.snippet:
                L += ["", "```", f.snippet, "```"]
            L.append("")
            L.append(f"{f.explanation or f.message}")
            fix = f.ai_fix or f.fix
            if fix:
                L.append(f"")
                L.append(f"**Fix:** {fix}")
            L.append("")
        if len(items) > max_per_section:
            L.append(f"_...and {len(items) - max_per_section} more {cat} findings (see the JSON report)._")

    if dismissed:
        L += ["", f"## Dismissed by LLM triage ({len(dismissed)})", ""]
        for f in dismissed[:20]:
            L.append(f"- `{_loc(f)}` {f.title} - {f.explanation}")
    L += ["", "---", f"_Generated by SlopGuard {__version__}._", ""]
    return "\n".join(L)


def to_sarif(result: ScanResult) -> str:
    level = {Severity.CRITICAL: "error", Severity.HIGH: "error", Severity.MEDIUM: "warning",
             Severity.LOW: "note", Severity.INFO: "note"}
    seen = {f.rule_id: f for f in result.findings}
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SlopGuard", "version": __version__, "rules": [
                {"id": rid, "name": f.title, "shortDescription": {"text": f.title},
                 "fullDescription": {"text": f.message}} for rid, f in sorted(seen.items())]}},
            "results": [{
                "ruleId": f.rule_id, "level": level[f.severity],
                "message": {"text": f.explanation or f.message},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": f.path}, "region": {"startLine": max(1, f.line)}}}],
            } for f in result.findings if not f.dismissed]}],
    }
    return json.dumps(doc, indent=2)


RENDERERS = {"markdown": to_markdown, "md": to_markdown, "json": to_json, "text": to_text, "sarif": to_sarif}
