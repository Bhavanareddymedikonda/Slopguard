"""Optional LLM triage: confirms/dismisses findings and explains them.

Zero dependencies: talks to the Anthropic or any OpenAI-compatible chat API
using urllib. Without an API key SlopGuard still works fully (rule-based).
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Dict, List, Optional

from .models import Finding, ScanResult

SYSTEM = (
    "You are a senior application-security and code-quality reviewer triaging findings from a "
    "static scanner. For each finding decide if it is a real problem in context. Be skeptical of "
    "test code, examples and placeholders. Reply with ONLY a JSON array; one object per finding "
    'with keys: "id" (int), "verdict" ("true_positive" | "false_positive" | "uncertain"), '
    '"explanation" (<=25 words, concrete, why it matters or why it is fine), '
    '"fix" (<=25 words, concrete remediation or empty string).'
)


def detect_provider() -> Optional[str]:
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY") or os.environ.get("SLOPGUARD_API_KEY"):
        return "openai"
    return None


def _context(root: str, fd: Finding, radius: int = 3) -> str:
    path = root if os.path.isfile(root) else os.path.join(root, fd.path)
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return fd.snippet
    lo, hi = max(0, fd.line - 1 - radius), min(len(lines), fd.line + radius)
    return "\n".join(f"{i + 1}: {lines[i][:200]}" for i in range(lo, hi))


def _post(url: str, headers: Dict[str, str], body: Dict) -> Dict:
    req = urllib.request.Request(url, json.dumps(body).encode(), headers, method="POST")
    with urllib.request.urlopen(req, timeout=90) as resp:
        return json.loads(resp.read().decode())


def _call(provider: str, model: str, prompt: str) -> str:
    if provider == "anthropic":
        data = _post(
            os.environ.get("ANTHROPIC_BASE_URL", "https://api.anthropic.com") + "/v1/messages",
            {"x-api-key": os.environ["ANTHROPIC_API_KEY"], "anthropic-version": "2023-06-01",
             "content-type": "application/json"},
            {"model": model, "max_tokens": 4096, "system": SYSTEM,
             "messages": [{"role": "user", "content": prompt}]})
        return "".join(b.get("text", "") for b in data.get("content", []))
    key = os.environ.get("SLOPGUARD_API_KEY") or os.environ.get("OPENAI_API_KEY", "")
    base = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    data = _post(base + "/chat/completions",
                 {"Authorization": f"Bearer {key}", "content-type": "application/json"},
                 {"model": model, "messages": [{"role": "system", "content": SYSTEM},
                                               {"role": "user", "content": prompt}],
                  "temperature": 0})
    return data["choices"][0]["message"]["content"]


def _parse(text: str) -> List[Dict]:
    m = re.search(r"\[.*\]", text, re.S)
    if not m:
        return []
    try:
        arr = json.loads(m.group(0))
    except ValueError:
        return []
    return [a for a in arr if isinstance(a, dict) and "id" in a]


def llm_triage(result: ScanResult, limit: int = 40, batch: int = 10,
               model: Optional[str] = None) -> Dict:
    """Mutates findings in place; returns info about what happened."""
    provider = detect_provider()
    if not provider:
        return {"enabled": False, "reason": "no API key (set ANTHROPIC_API_KEY or OPENAI_API_KEY)"}
    model = model or os.environ.get("SLOPGUARD_MODEL") or (
        "claude-sonnet-5-5" if provider == "anthropic" else "gpt-4o-mini")
    top = result.findings[:limit]
    done = errors = 0
    for start in range(0, len(top), batch):
        chunk = top[start:start + batch]
        prompt = "Findings to triage:\n\n" + "\n\n".join(
            f"### id={start + i}\nrule={fd.rule_id} ({fd.title}) severity={fd.severity.label} "
            f"file={fd.path}:{fd.line}{' [test/example code]' if fd.in_test else ''}\n"
            f"```\n{_context(result.root, fd)}\n```" for i, fd in enumerate(chunk))
        try:
            answers = _parse(_call(provider, model, prompt))
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError, OSError) as exc:
            errors += 1
            last = str(exc)
            continue
        for a in answers:
            try:
                fd = top[int(a["id"])]
            except (ValueError, IndexError, TypeError):  # slopguard: ignore SLP001 - bad id from model
                continue
            fd.verdict = str(a.get("verdict", "uncertain"))
            fd.explanation = str(a.get("explanation", ""))[:300]
            fd.ai_fix = str(a.get("fix", ""))[:300]
            if fd.verdict == "false_positive":
                fd.dismissed = True
                fd.score *= 0.1
            elif fd.verdict == "true_positive":
                fd.score *= 1.2
            done += 1
    result.findings.sort(key=lambda x: (x.dismissed, -x.score, x.path, x.line))
    info = {"enabled": True, "provider": provider, "model": model, "triaged": done,
            "dismissed": sum(1 for f in result.findings if f.dismissed)}
    if errors:
        info["errors"] = errors
        info["last_error"] = last
    return info
