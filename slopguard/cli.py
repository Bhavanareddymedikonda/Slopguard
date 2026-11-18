"""Command line interface: `python -m slopguard <path-or-git-url>`."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

from . import __version__
from .models import Severity
from .report import RENDERERS
from .rules import RULES
from .scanner import scan
from .triage import detect_provider, llm_triage


def _is_git_url(t: str) -> bool:
    return t.startswith(("http://", "https://", "git@", "ssh://")) and (
        t.endswith(".git") or "github.com" in t or "gitlab.com" in t or "bitbucket.org" in t)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="slopguard",
        description="Language-agnostic agent that finds security issues, AI slop, coding gaps and loose ends.")
    p.add_argument("target", nargs="?", default=".", help="directory, file or git URL (default: .)")
    p.add_argument("-f", "--format", choices=sorted(RENDERERS), default="text")
    p.add_argument("-o", "--output", help="write the report to a file")
    p.add_argument("--min-severity", default="info", help="info|low|medium|high|critical (default: info)")
    p.add_argument("--min-confidence", type=float, default=0.0, help="0.0-1.0")
    p.add_argument("--only", help="comma list of categories (security,slop,gap) or rule ids")
    p.add_argument("--skip", help="comma list of rule ids to skip")
    p.add_argument("--ignore", action="append", default=[], help="glob to ignore (repeatable)")
    p.add_argument("--no-tests", action="store_true", help="do not scan test/example files")
    p.add_argument("--llm", action="store_true", help="LLM triage (needs ANTHROPIC_API_KEY or OPENAI_API_KEY)")
    p.add_argument("--model", help="override the LLM model name")
    p.add_argument("--llm-limit", type=int, default=40, help="max findings sent to the LLM")
    p.add_argument("--fail-on", default=None, help="exit 1 if a finding >= this severity exists")
    p.add_argument("--list-rules", action="store_true")
    p.add_argument("--version", action="version", version=f"slopguard {__version__}")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
        try:
            sys.stdout.reconfigure(encoding="utf-8")
        except (AttributeError, OSError):  # slopguard: ignore SLP001 - best effort only
            pass
    if args.list_rules:
        for r in RULES:
            print(f"{r.id}  {r.category:8} {r.severity.label:8} {r.title}")
        return 0
    try:
        min_sev = Severity.parse(args.min_severity)
        fail_on = Severity.parse(args.fail_on) if args.fail_on else None
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    target, tmp = args.target, None
    if _is_git_url(target):
        tmp = tempfile.mkdtemp(prefix="slopguard-")
        print(f"cloning {target} ...", file=sys.stderr)
        r = subprocess.run(["git", "clone", "--depth", "1", "--quiet", target, tmp],
                           capture_output=True, text=True)
        if r.returncode != 0:
            print(f"error: git clone failed: {r.stderr.strip()}", file=sys.stderr)
            shutil.rmtree(tmp, ignore_errors=True)
            return 2
        target = tmp
    if not os.path.exists(target):
        print(f"error: {target!r} does not exist", file=sys.stderr)
        return 2

    try:
        only = {x.strip() for x in args.only.split(",")} if args.only else None
        skip = {x.strip().upper() for x in args.skip.split(",")} if args.skip else None
        result = scan(target, min_sev, args.min_confidence, not args.no_tests, args.ignore, only, skip)
        if args.llm:
            if not detect_provider():
                print("warning: --llm given but no API key found; continuing rule-based.", file=sys.stderr)
            else:
                print("triaging findings with the LLM ...", file=sys.stderr)
            result.llm_info = llm_triage(result, limit=args.llm_limit, model=args.model)
            if result.llm_info.get("errors"):
                print(f"warning: LLM errors: {result.llm_info.get('last_error')}", file=sys.stderr)
        if tmp:
            result.root = args.target
        out = RENDERERS[args.format](result)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(out)
            print(f"report written to {args.output}", file=sys.stderr)
        else:
            print(out)
        if fail_on is not None and any(f.severity >= fail_on and not f.dismissed for f in result.findings):
            return 1
        return 0
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
