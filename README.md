# vetter

Scan any skill, plugin, connector, package, MCP server or open-source repo for security red flags **before you install it**.
One file, Python standard library only: read all of it in 5 minutes. It never runs the code it scans.

## Quick start

```bash
python3 vetter.py ./some-skill                         # local folder
python3 vetter.py https://github.com/user/repo         # GitHub repo (shallow clone, never executed)
```

You get a verdict, with the file and line behind every finding:

| Verdict | Exit code | Meaning |
|---|---|---|
| 🟢 GREEN | 0 | No known red flags. Still skim the code. |
| 🟡 YELLOW | 1 | Review the flagged items first. |
| 🔴 RED | 2 | Do **not** install until you've reviewed the high items. |

Add `--json` for machine-readable output (e.g. in CI), and `--ignore FILE` to accept findings you've already reviewed.

<details>
<summary><b>Ignore file</b></summary>

One `<rule-id> <path-glob>` per line; `*` matches any rule or path, `#` starts a comment.

```
# reviewed 2026-10-31: build script legitimately shells out
subprocess      scripts/build.py
network-call    *
```

- vetter reads an ignore file **only** when you pass `--ignore`. A `.vetterignore` (or any other file) shipped inside the scanned package is never used, so a package can't silence its own findings.
- Ignored findings still show up: as a count in the summary line, and in full under `"ignored"` in `--json` output.
- A typo in a rule id prints a warning, and a malformed line exits with code 3, so a broken ignore file never fails silently.

</details>

<details>
<summary><b>What it checks</b></summary>

- Pipe-to-shell (`curl … | bash`), base64/`eval` execution, reverse shells, destructive commands
- Access to credential files (`.ssh`, `.aws`, `.env`, tokens), env vars sent over the network, exfil/webhook endpoints
- Prompt-injection text aimed at the AI ("ignore previous instructions", "don't tell the user")
- Hidden / bidirectional unicode characters
- npm `postinstall` scripts, `setup.py`, auto-run **hooks**, MCP server commands
- Persistence (cron, shell rc files, authorized_keys), bundled binaries, symlinks, obfuscated or minified code, hardcoded secrets
- Permission bypass flags (`--dangerously-skip-permissions`, `chmod 777`, …)

</details>

<details>
<summary><b>Limits (read this)</b></summary>

A green result means "no known red flags", not "safe". It is rule-based static analysis: it can miss novel or split-up tricks, and it can flag harmless code. Treat it as a first filter, not a replacement for reading what you install.

</details>

<details>
<summary><b>Development</b></summary>

```bash
pip install pytest && pytest
```

Rules live in the `RULES` list at the top of `vetter.py`; add a rule + a fixture + a test.

</details>

## Roadmap
- [x] Static rule scan, local + GitHub URL, JSON output
- [ ] Dependency vulnerability check (OSV)
- [x] Allowlist / ignore file
- [ ] GitHub Action + SARIF output
- [ ] Optional AI-assisted review pass

Licensed under [MIT](LICENSE).
