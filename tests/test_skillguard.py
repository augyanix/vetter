import os, subprocess, sys
HERE = os.path.dirname(__file__)
SCRIPT = os.path.join(HERE, "..", "vetter.py")

def run(name):
    return subprocess.run([sys.executable, SCRIPT, os.path.join(HERE, "fixtures", name)], capture_output=True, text=True)

def test_evil_is_red():
    r = run("evil"); assert r.returncode == 2 and "RED" in r.stdout
    for rule in ("pipe-to-shell", "prompt-injection", "install-script", "webhook-exfil", "secret-file-access"):
        assert rule in r.stdout

def test_good_is_green():
    r = run("good"); assert r.returncode == 0 and "GREEN" in r.stdout
