# 🛡️ SlopGuard

**A simple, language-agnostic agent that hunts security issues, AI "slop", coding gaps and loose ends in any codebase.**

Point it at a folder or a GitHub URL and it returns a ranked, actionable report. No dependencies, no setup, works on Python, JavaScript/TypeScript, Java, Go, Rust, C/C++, PHP, Ruby, shell, Dockerfiles, Terraform, SQL, notebooks and config files, because it uses a tiny lexer instead of per-language parsers.

```bash
python -m slopguard .                                   # scan current directory
python -m slopguard https://github.com/user/repo        # clone + scan
python -m slopguard . -f markdown -o report.md          # full report
python -m slopguard . --llm -f markdown -o report.md    # + LLM triage (optional)
```

## What it finds

| Category | Examples |
|---|---|
| 🔐 **Security** (25 rules) | hardcoded secrets, AWS/GitHub/Slack/Stripe/Anthropic tokens, private keys, credentials in URLs, `eval`/`exec`, command & SQL injection, `pickle`/unsafe YAML, weak hashes, disabled TLS verification, XSS sinks, wildcard CORS, debug mode, Docker as root, piped remote installers, committed `.env`/`.pem` files |
| 🧹 **Slop** | swallowed exceptions, AI-assistant leftovers (*"Here is the updated code"*, *"in a real application…"*), pointless narrating comments, blocks of commented-out code, **copy-pasted blocks across files**, unused imports, placeholder names (`doSomething`, `helper`), debug prints, stub return values, very long functions |
| 🕳️ **Gaps & loose ends** | TODO/FIXME/HACK, `NotImplementedError` stubs, empty functions, skipped/always-true tests, HTTP calls without timeouts, unpinned or `*` dependencies, missing README / LICENSE / tests / .gitignore |

Run `python -m slopguard --list-rules` for the full catalogue.

## How it works

```
 files ──► walk (skip node_modules, .git, locks, minified)
       ──► lex   (separate code / comments / strings, any language)
       ──► rules (regex, scoped to code | comment | line, with validators)
       ──► detectors (multi-line & cross-file: duplicates, dead code, unused imports)
       ──► rank  (severity × confidence × category weight; tests/examples downgraded)
       ──► triage (optional LLM confirms / dismisses and explains)
       ──► report (text · markdown · json · sarif) + health score
```

Design choices that keep the signal high:

* **Context-aware scoping.** `# TODO` inside a string is not a TODO; `password = os.environ[...]` is not a secret. A mini-lexer tracks comments, strings, block comments and docstrings across lines.
* **Validators, not just regex.** Secret rules reject placeholders (`your_api_key_here`), low-entropy values and env lookups, and use Shannon entropy for random-looking tokens.
* **Test/example awareness.** Findings in `tests/`, `examples/`, fixtures are downgraded one severity level.
* **Ranked output.** A `Fix these first` list is sorted by `severity × confidence`, plus a 0-100 size-normalised health score.
* **Optional LLM triage.** With `ANTHROPIC_API_KEY` (or any OpenAI-compatible `OPENAI_API_KEY`), `--llm` sends the top findings with code context to a model that labels each *true / false positive*, explains it and suggests a fix. False positives are dismissed. Without a key SlopGuard is fully functional and deterministic.
* **Zero dependencies**, single `pip install .`, Python ≥ 3.9.

## CLI

```
slopguard [target] [-f text|markdown|json|sarif] [-o FILE]
          [--min-severity low|medium|high|critical] [--min-confidence 0.5]
          [--only security,slop,gap|RULE_IDS] [--skip RULE_IDS]
          [--ignore GLOB] [--no-tests] [--llm] [--model NAME]
          [--fail-on high]      # CI gate: exit code 1
```

**Suppress** a finding with `# slopguard: ignore` (optionally `SEC007`) on the line or the line above, a whole file with `slopguard: ignore-file` in its first 5 lines, or paths via `.slopguardignore`.

**CI**: `--fail-on high` fails the build; `-f sarif` uploads to GitHub code scanning.

## Example

`examples/vulnerable_app/` is a deliberately bad multi-language app (Python, JS, Go, shell, Dockerfile). 

```bash
python -m slopguard examples/vulnerable_app -f markdown -o examples/sample_report.md
```

See [`examples/sample_report.md`](examples/sample_report.md) for the output: it flags the hardcoded AWS key, SQL injection, shell injection, pickle, `eval`, disabled TLS, committed `.env`, AI leftovers, commented-out code blocks, swallowed exceptions and more.

## Develop

```bash
pip install pytest && pytest -q        # 24 tests
python -m slopguard . --no-tests       # SlopGuard scans itself (dogfooding)
```

## Limitations (honest)

Pattern-based analysis has no data-flow tracking, so injection rules are heuristics, which is exactly why each finding carries a confidence score and why the optional LLM pass exists. 

MIT licensed.
