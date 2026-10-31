# skillguard — project instructions

Static security scanner to run BEFORE installing any skill/plugin/MCP server/repo. Trust is the product: it must stay a single readable file, stdlib only, and must NEVER execute scanned code.

## Layout
- `skillguard.py` — everything: `RULES` list (regex rules), `scan_file`, `scan`, `verdict`, `main`.
- `tests/fixtures/{evil,good}` — samples; `tests/test_skillguard.py` runs the CLI against them.

## Commands
- Test: `pip install pytest && pytest -q`
- Use: `python3 skillguard.py <path|git-url> [--json]`  (exit 0 green / 1 yellow / 2 red)

## Rules for changes
- No third-party dependencies. No network calls, no executing scanned files. Git clones must disable hooks.
- New rule = entry in `RULES` + fixture line + test. Prefer precise regexes; false positives erode trust.
- README stays short; detail in `<details>` blocks. Be honest in docs: green ≠ safe.

## Roadmap
1. Dependency CVE check (OSV) 2. Ignore/allowlist file 3. GitHub Action + SARIF 4. Multi-line exfil detection 5. Optional AI-assisted review
