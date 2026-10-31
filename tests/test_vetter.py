import json, os, subprocess, sys
HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "vetter.py")

def run(name, *args):
    return subprocess.run([sys.executable, SCRIPT, os.path.join(HERE, "fixtures", name), *args], capture_output=True, text=True)

def ignore(name):
    return os.path.join(HERE, "fixtures", "ignores", name)

def test_evil_is_red():
    r = run("evil"); assert r.returncode == 2 and "RED" in r.stdout
    for rule in ("pipe-to-shell", "prompt-injection", "install-script", "webhook-exfil", "secret-file-access"):
        assert rule in r.stdout

def test_good_is_green():
    r = run("good"); assert r.returncode == 0 and "GREEN" in r.stdout

def test_ignore_one_rule_in_one_file():
    r = run("evil", "--json", "--ignore", ignore("webhook.txt"))
    out = json.loads(r.stdout)
    assert r.returncode == 2
    assert "webhook-exfil" not in {f["rule"] for f in out["findings"]}
    assert [(f["rule"], f["file"]) for f in out["ignored"]] == [("webhook-exfil", "run.py")]

def test_ignore_everything_is_green_and_counted():
    r = run("evil", "--ignore", ignore("all.txt"))
    assert r.returncode == 0 and "GREEN" in r.stdout and "0 findings" in r.stdout and "ignored" in r.stdout

def test_package_cannot_ignore_itself():
    r = run("selfignore"); assert r.returncode == 2 and "pipe-to-shell" in r.stdout

def test_unknown_rule_warns():
    r = run("evil", "--ignore", ignore("unknown.txt"))
    assert r.returncode == 2 and "unknown rule id 'not-a-rule'" in r.stderr

def test_malformed_ignore_file_is_usage_error():
    r = run("evil", "--ignore", ignore("bad.txt"))
    assert r.returncode == 3 and "expected '<rule-id> <path-glob>'" in r.stderr
