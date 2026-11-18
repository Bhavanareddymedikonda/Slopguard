# AI usage log

This file records how AI was used to build SlopGuard for the Mycrobo Hackathon (AntiSlop), in the interest of full transparency.

## Tools used

| Tool | Used for |
|---|---|
| **Claude** (Anthropic, via claude.ai / Claude Code) | Design discussion, writing the code, tests, example app, README and this log |

SlopGuard's optional `--llm` triage feature can also call an LLM at *runtime* (Anthropic or an OpenAI-compatible API). It is off by default and was only exercised in the tests with a mocked response; it was not run against a live API during development.

## How the work was split

**Human (Medikonda Bhavana)**
- Chose the project from the hackathon brief and decided to submit to the AI triage track.
- Directed the work: scope, deadline pressure, and "finish it fast" decisions.
- Ran the code locally, created the GitHub repository, pushed the code, fixed the push/CI problems and made the submission.

**AI (Claude)**
- Proposed the architecture: walk, lex, rules, detectors, rank, optional triage, report.
- Wrote the Python source (`slopguard/`), the 25 tests, the vulnerable demo app, the README, CI workflow and this log.
- Debugged its own output (see below).

## Verification that was done (not just trusted)

1. **Tests:** 25 automated tests, all passing, including regression tests for bugs found along the way.
2. **Dogfooding:** SlopGuard was run on its own source. This surfaced real problems (unused imports, an MD5 hash) and false positives (the rule definitions matching their own patterns, `print` in a CLI being flagged), all fixed.
3. **Real-world code:** SlopGuard was run on Python's standard library (`email`, `json`, `asyncio`). This exposed a real false positive (`token_type = 'encoded-word'` flagged as a credential), which was fixed and given a regression test.
4. **Bugs the AI introduced and then fixed:**
   - Several verbose-mode regexes treated `#` as a comment and failed to compile or matched wrongly.
   - A suppression comment on one line wrongly suppressed the next line.
   - Project-level findings (missing README / tests) were deduplicated into one by mistake.
   - The first CI run failed because the package was not importable under plain `pytest`; fixed with `pythonpath` and `python -m pytest`.

## Known limits of AI-generated code here

- Rules are pattern-based heuristics with no data-flow analysis, so false positives and negatives are expected. Each finding carries a confidence score for this reason.
- The sample secrets in `examples/vulnerable_app/` are fake and exist only to demonstrate detection.
- The LLM triage path has not been validated against a live model.

## Prompts

The work happened in one long conversation. The key human instructions were, in order: understand the hackathon brief from screenshots; help build the assignment; continue and complete it fast; package it for submission; write an impressive README; fix the failing CI run; and prepare the repo for Arena's requirements.