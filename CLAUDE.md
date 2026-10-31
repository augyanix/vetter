# vetter — project instructions

Static security scanner to run BEFORE installing any skill/plugin/MCP server/repo. Trust is the product: it must stay a single readable file, stdlib only, and must NEVER execute scanned code.

## Layout
- `vetter.py` — everything: `RULES` list (regex rules), `scan_file`, `scan`, `verdict`, `main`.
- `tests/fixtures/{evil,good}` — samples; `tests/test_vetter.py` runs the CLI against them.

## Commands
- Test: `pip install pytest && pytest -q`
- Use: `python3 vetter.py <path|git-url> [--json] [--ignore FILE]`  (exit 0 green / 1 yellow / 2 red / 3 usage error)
- Ignore files come only from `--ignore`; never auto-load one from the scanned target.

## Rules for changes
- No third-party dependencies. No network calls, no executing scanned files. Git clones must disable hooks.
- New rule = entry in `RULES` + fixture line + test. Prefer precise regexes; false positives erode trust.
- README stays short; detail in `<details>` blocks. Be honest in docs: green ≠ safe.

## Roadmap
1. Dependency CVE check (OSV) 2. Ignore/allowlist file 3. GitHub Action + SARIF 4. Multi-line exfil detection 5. Optional AI-assisted review
