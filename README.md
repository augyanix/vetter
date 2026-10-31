# skillguard

Scan any skill, plugin, MCP server or open-source repo for security red flags **before you install it**.
One file, Python standard library only: read all of it in 5 minutes. It never runs the code it scans.

## Quick start

```bash
python3 skillguard.py ./some-skill                         # local folder
python3 skillguard.py https://github.com/user/repo         # GitHub repo (shallow clone, never executed)
```

You get a verdict, with the file and line behind every finding:

| Verdict | Exit code | Meaning |
|---|---|---|
| 🟢 GREEN | 0 | No known red flags. Still skim the code. |
| 🟡 YELLOW | 1 | Review the flagged items first. |
| 🔴 RED | 2 | Do **not** install until you've reviewed the high items. |

Add `--json` for machine-readable output (e.g. in CI).

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

Rules live in the `RULES` list at the top of `skillguard.py`; add a rule + a fixture + a test.

</details>

## Roadmap
- [x] Static rule scan, local + GitHub URL, JSON output
- [ ] Dependency vulnerability check (OSV)
- [ ] Allowlist / ignore file
- [ ] GitHub Action + SARIF output
- [ ] Optional AI-assisted review pass

Licensed under [MIT](LICENSE).
