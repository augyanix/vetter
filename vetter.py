#!/usr/bin/env python3
"""vetter - scan a skill/plugin/repo for security red flags BEFORE you install it.

Static analysis only: it never executes the code it scans. Stdlib only, so there is
nothing to trust but this one file.

Usage:  vetter.py <path | git-url> [--json]
Exit codes: 0 = green, 1 = yellow (review), 2 = red (do not install)
"""
import json, os, re, shutil, subprocess, sys, tempfile, unicodedata

RULES = [  # (id, severity, description, regex)
 ("pipe-to-shell", "high", "Downloads and pipes to a shell", r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh"),
 ("eval-exec", "high", "Dynamic code execution (eval/exec of built strings)", r"\b(eval|exec)\s*\(\s*(base64|atob|decode|compile|[\"'])"),
 ("base64-decode-exec", "high", "Decodes base64 then executes", r"(base64\s+-d|b64decode|atob)\s*\(?.{0,80}(sh|exec|eval|bash)"),
 ("secret-file-access", "high", "Reads credential locations", r"(\.ssh/|\.aws/credentials|\.npmrc|\.env\b|\.netrc|id_rsa|\.config/gh|\.claude/\.credentials|keychain)"),
 ("env-exfil", "high", "Sends environment/secrets over network", r"(os\.environ|process\.env)[^\n]{0,120}(requests\.|fetch\(|http|curl|axios)"),
 ("webhook-exfil", "high", "Posts to known exfil/webhook endpoints", r"(discord(app)?\.com/api/webhooks|webhook\.site|pastebin\.com|transfer\.sh|ngrok\.io|requestbin|pipedream\.net|burpcollaborator)"),
 ("reverse-shell", "high", "Reverse shell pattern", r"(/dev/tcp/|nc\s+-e|bash\s+-i\s*>&|socat\s+.*exec|mkfifo\s+/tmp)"),
 ("destructive", "high", "Destructive filesystem command", r"(rm\s+-rf\s+(/|~|\$HOME)|mkfs\.|dd\s+if=.*of=/dev/)"),
 ("prompt-injection", "high", "Prompt-injection language aimed at the AI agent", r"(ignore (all |any )?(previous|prior|above) (instructions|rules)|do not (tell|inform|reveal to) the user|without (telling|informing|asking) the user|disregard (your|the) (system|safety))"),
 ("perm-bypass", "high", "Disables safety/permission checks", r"(--dangerously-skip-permissions|bypassPermissions|dangerouslyDisableSandbox|--no-verify|chmod\s+(-R\s+)?777)"),
 ("persistence", "medium", "Persistence mechanism (cron/shell rc/launch agents)", r"(crontab|\.bashrc|\.zshrc|\.profile|LaunchAgents|systemctl\s+enable|authorized_keys)"),
 ("subprocess", "medium", "Spawns shell commands", r"(subprocess\.(run|Popen|call)|os\.system|child_process|shell\s*=\s*True)"),
 ("network-call", "low", "Makes outbound network calls (check destinations)", r"(requests\.(get|post)|urllib|fetch\(|axios|http\.client|XMLHttpRequest)"),
 ("hardcoded-ip", "medium", "Hardcoded IP address", r"\b(?!127\.|0\.|10\.|192\.168\.)\d{1,3}(\.\d{1,3}){3}\b(?!\.\d)"),
 ("obfuscation", "medium", "Obfuscation (hex/charcode blobs)", r"(\\x[0-9a-f]{2}){12,}|String\.fromCharCode\((\s*\d+\s*,){8,}"),
 ("secret-leak", "medium", "Possible hardcoded secret", r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|-----BEGIN (RSA |OPENSSH )?PRIVATE KEY)"),
]
SEV = {"high": 3, "medium": 2, "low": 1}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
INVISIBLE = {"​", "‌", "‍", "⁠", "﻿", "‮", "‭", "⁦", "⁧", "⁨", "⁩"}
TEXT_EXT_LIMIT = 2_000_000

def scan_file(path, rel):
    out = []
    try:
        data = open(path, "rb").read(TEXT_EXT_LIMIT)
    except OSError:
        return out
    if b"\0" in data[:4096]:
        if os.access(path, os.X_OK) or rel.endswith((".exe", ".dll", ".so", ".dylib", ".bin")):
            out.append(("binary", "medium", "Bundled executable/binary - cannot be inspected", rel, 0, ""))
        return out
    text = data.decode("utf-8", "replace")
    inv = [c for c in text if c in INVISIBLE or unicodedata.category(c) == "Cf"]
    if inv:
        out.append(("hidden-unicode", "high", f"{len(inv)} invisible/bidi characters (can hide instructions)", rel, 0, ""))
    for i, line in enumerate(text.splitlines(), 1):
        if len(line) > 3000:
            out.append(("minified", "medium", "Very long line (minified/obfuscated?)", rel, i, line[:80])); continue
        for rid, sev, desc, rx in RULES:
            if re.search(rx, line, re.I):
                out.append((rid, sev, desc, rel, i, line.strip()[:120]))
    base = os.path.basename(path)
    if base == "package.json":
        try:
            scripts = json.loads(text).get("scripts", {})
            for k in ("preinstall", "install", "postinstall", "prepare"):
                if k in scripts:
                    out.append(("install-script", "high", f"npm '{k}' script runs on install: {scripts[k][:80]}", rel, 0, ""))
        except ValueError:
            pass
    if base == "setup.py":
        out.append(("setup-py", "medium", "setup.py executes code at install time", rel, 0, ""))
    if base in ("settings.json", "settings.local.json", "hooks.json") and '"hooks"' in text:
        out.append(("hooks", "high", "Defines hooks that auto-run commands on your machine", rel, 0, ""))
    if base in ("plugin.json", ".mcp.json") and re.search(r'"(command|mcpServers)"', text):
        out.append(("mcp-server", "medium", "Declares MCP server/command that will run locally", rel, 0, ""))
    return out

def scan(root):
    findings, nfiles = [], 0
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in SKIP_DIRS]
        for f in files:
            p = os.path.join(d, f)
            if os.path.islink(p):
                findings.append(("symlink", "medium", "Symlink (could point outside the package)", os.path.relpath(p, root), 0, "")); continue
            nfiles += 1
            findings += scan_file(p, os.path.relpath(p, root))
    return findings, nfiles

def verdict(findings):
    top = max((SEV[f[1]] for f in findings if f[0] != "network-call"), default=0)
    return {3: "RED", 2: "YELLOW", 1: "GREEN", 0: "GREEN"}[top]

def main(argv):
    if len(argv) < 2:
        print(__doc__); return 3
    target, as_json = argv[1], "--json" in argv
    tmp = None
    if re.match(r"^(https://|git@)", target):
        tmp = tempfile.mkdtemp(prefix="vetter-")
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
        subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "--depth", "1", "--no-recurse-submodules", target, tmp + "/repo"],
                       check=True, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        target = tmp + "/repo"
    try:
        findings, n = scan(target)
    finally:
        if tmp: shutil.rmtree(tmp, ignore_errors=True)
    v = verdict(findings)
    if as_json:
        print(json.dumps({"verdict": v, "files": n, "findings": [dict(zip(("rule", "severity", "desc", "file", "line", "snippet"), f)) for f in findings]}, indent=2))
    else:
        icon = {"RED": "🔴", "YELLOW": "🟡", "GREEN": "🟢"}[v]
        print(f"{icon} {v}  ({n} files scanned, {len(findings)} findings)\n")
        for f in sorted(findings, key=lambda f: -SEV[f[1]]):
            print(f"[{f[1].upper():6}] {f[0]}: {f[2]}\n         {f[3]}:{f[4]}  {f[5]}")
        print({"RED": "\nDo NOT install until you've manually reviewed the high items.",
               "YELLOW": "\nReview the flagged items; install only if they make sense for what the tool does.",
               "GREEN": "\nNo red flags found by static rules. This is not a guarantee - still skim the code."}[v])
    return {"RED": 2, "YELLOW": 1, "GREEN": 0}[v]

def main_cli():
    sys.exit(main(sys.argv))

if __name__ == "__main__":
    main_cli()
