"""End-to-end tests for The Pit. Runs against a throwaway PIT_HOME, never ~/.the-pit.

    pip install pexpect
    cargo build && python tests/e2e.py
    PIT_BIN=target/release/pit python tests/e2e.py
"""
import os, sys, json, re, subprocess, shutil, time, hmac, hashlib, struct, base64, stat
import pexpect

SP = os.environ.get("PIT_E2E_DIR") or __import__("tempfile").mkdtemp(prefix="pit-e2e-")
HOME = os.path.join(SP, "pit-home")
OUT = os.path.join(SP, "out")
PIT = os.environ.get("PIT_BIN", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "target", "debug", "pit"))
PW = "correct horse battery staple lantern"
PW2 = "violet orbit cascade marmalade tundra"
env = dict(os.environ, PIT_HOME=HOME, NO_COLOR="1")

def SOCK(home):
    p = os.path.join(home, "run", "agent.sock")
    if len(p) < 100: return p
    return "/tmp/the-pit-%d-%s/agent.sock" % (os.getuid(), hashlib.sha256(home.encode()).hexdigest()[:12])

def sh(args, stdin=None, ok=True):
    r = subprocess.run([PIT] + args, input=stdin, capture_output=True, env=env, text=True, timeout=120)
    if ok and r.returncode != 0:
        print("FAILED:", args, r.stdout, r.stderr); sys.exit(1)
    return r

def spawn(args):
    return pexpect.spawn(PIT, args, env=env, encoding="utf-8", timeout=60)

def check(cond, msg):
    print(("PASS " if cond else "FAIL ") + msg)
    if not cond: sys.exit(1)

def approved(args):
    """Run a command that needs approval, answering with the password if asked."""
    p = spawn(args)
    if p.expect(["Password: ", pexpect.EOF]) == 0:
        p.sendline(PW); p.expect(pexpect.EOF)
    p.close()
    if p.exitstatus != 0:
        print("FAILED:", args, p.before); sys.exit(1)
    return p.before

# fresh
subprocess.run([PIT, "lock"], env=env, capture_output=True)
try:
    subprocess.run([PIT, "service", "x"], env=env, capture_output=True)
except Exception: pass
if os.path.exists(SOCK(HOME)):
    import socket
    s = socket.socket(socket.AF_UNIX);
    try:
        s.connect(SOCK(HOME)); s.sendall(b'{"op":"shutdown","args":{}}\n'); s.recv(100)
    except Exception: pass
shutil.rmtree(HOME, ignore_errors=True); shutil.rmtree(OUT, ignore_errors=True)
os.makedirs(OUT)

# 1. init
p = spawn(["init", "--name", "tester", "--no-touch-id"])
p.expect("New password: "); p.sendline("short")
p.expect("at least 12"); p.expect("New password: "); p.sendline("password password")
p.expect("too weak"); p.expect("New password: "); p.sendline(PW)
p.expect("Repeat it: "); p.sendline(PW)
p.expect(r"(PIT-R-[0-9A-Z\-]+)")
code = p.match.group(1)
last = code.split("-")[-2]
p.expect("type the last group"); p.sendline("WRONG")
p.expect("does not match"); p.expect("type the last group"); p.sendline(last)
p.expect("vault created"); p.expect(pexpect.EOF)
check(code.startswith("PIT-R-"), "init shows recovery code; weak passwords rejected")
mode = stat.S_IMODE(os.stat(HOME).st_mode)
check(mode == 0o700, f"home is 0700 ({oct(mode)})")
hdr = open(os.path.join(HOME, "vault/header.json")).read()
check(PW not in hdr and "tester" not in hdr, "header holds no password or owner name")
lib = open(os.path.join(HOME, "vault/library.sealed")).read()
check("tester" not in lib, "library file is ciphertext")

# Approval windows are tested on their own in 21f; elsewhere every approval is asked for.
approved(["settings", "approval_window_secs", "0"])

# 2. projects/channels/secrets
sh(["project", "add", "demo", "-d", "Demo app", "--channels", "production,development"])
sh(["set", "demo/development", "API_KEY", "-d", "The API key"], stdin="dev-value-123\n")
sh(["set", "demo/production", "API_KEY"], stdin="prod-value-456\n", ok=False)  # needs approval, no tty
r = sh(["set", "demo/production", "API_KEY"], stdin="x\n", ok=False)
check(r.returncode != 0 and "approval" in (r.stderr + r.stdout), "setting a protected-channel secret without a terminal is refused pending approval")
r = sh(["set", "demo", "SHARED_URL", "-p", "plain"], stdin="x\n", ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "a project secret inherited by a protected channel needs approval")
p = spawn(["set", "demo", "SHARED_URL", "-p", "plain", "-d", "Inherited by channels"])
p.expect("Value for SHARED_URL"); p.sendline("https://example.test")
p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
sh(["declare", "demo/development", "TODO_TOKEN", "-d", "Needed later"])
sh(["set", "demo/development", "SESSION", "--generate", "32", "--charset", "hex"])
sh(["set", "demo/development", "ADMIN_PIN", "-p", "hashed"], stdin="4321\n")
with open(os.path.join(OUT, "key.p8"), "wb") as f: f.write(b"\x00\x01binary-key\xff")
sh(["set", "demo/development", "SIGNING_KEY", "--file", os.path.join(OUT, "key.p8")])
r = sh(["ls"])
check("API_KEY" in r.stdout and "dev-value-123" not in r.stdout and "empty" in r.stdout, "ls shows names, never values")
r = sh(["needs"])
check("TODO_TOKEN" in r.stdout, "needs lists empty secrets")

# 3. verify (hashed)
r = sh(["verify", "demo/development", "ADMIN_PIN"], stdin="4321\n")
check("match" in r.stderr, "one-way secret verifies")
r = sh(["verify", "demo/development", "ADMIN_PIN"], stdin="0000\n", ok=False)
check(r.returncode == 1, "one-way secret rejects wrong value")

# 4. dotenv destination + push
os.makedirs(os.path.join(OUT, "app"))
r = sh(["dest", "add", "demo/development", "local", "--kind", "dotenv", "--set", f"path={OUT}/app/.env"], ok=False)
check(r.returncode != 0 and "approval required" in r.stderr, "adding a destination needs approval, even on an unprotected channel")
out = approved(["dest", "add", "demo/development", "local", "--kind", "dotenv", "--set", f"path={OUT}/app/.env", "--select", "*", "--select", "!SIGNING_KEY"])
check("one-way secrets it can never receive: ADMIN_PIN" in out, "adding a destination warns about one-way secrets it selects")
approved(["dest", "add", "demo/development", "keys", "--kind", "files", "--set", f"dir={OUT}/app/keys", "--select", "SIGNING_KEY"])
r = sh(["push", "demo/development", "--dry-run"])
check(not os.path.exists(os.path.join(OUT, "app/.env")), "dry run writes nothing")
r = sh(["push", "demo/development", "-y"])
envtext = open(os.path.join(OUT, "app/.env")).read()
check("API_KEY=dev-value-123" in envtext and "SHARED_URL=https://example.test" in envtext, "dotenv push writes channel + inherited values")
check("ADMIN_PIN" not in envtext and "TODO_TOKEN" not in envtext, "one-way and empty secrets are not pushed")
check(stat.S_IMODE(os.stat(os.path.join(OUT, "app/.env")).st_mode) == 0o600, ".env written 0600")
check(open(os.path.join(OUT, "app/keys/key.p8"), "rb").read() == b"\x00\x01binary-key\xff", "binary file secret delivered byte-exact")

# 5. absorb: a tool writes a new value into the rendered file
open(os.path.join(OUT, "app/.env"), "a").write("EXTRA=1\n")
txt = open(os.path.join(OUT, "app/.env")).read().replace("dev-value-123", "rotated-by-tool")
open(os.path.join(OUT, "app/.env"), "w").write(txt)
r = sh(["push", "demo/development", "local", "-y"], ok=False)
check(r.returncode != 0 and "EXTRA" in (r.stderr + r.stdout), "push refuses to erase a value only the file holds")
r = sh(["absorb", "demo/development", "local"])
check("updated API_KEY" in r.stdout, "absorb pulls changed value back")

# 6. git guard
gitdir = os.path.join(OUT, "repo"); os.makedirs(gitdir); subprocess.run(["git", "init", "-q", gitdir])
approved(["dest", "add", "demo/development", "ingit", "--kind", "dotenv", "--set", f"path={gitdir}/.env"])
r = sh(["push", "demo/development", "ingit", "-y"], ok=False)
check("not ignored" in (r.stdout + r.stderr), "refuses to write an un-ignored file in a git repo")
open(os.path.join(gitdir, ".gitignore"), "w").write(".env\n")
r = sh(["push", "demo/development", "ingit", "-y"])
check(os.path.exists(os.path.join(gitdir, ".env")), "writes once git-ignored")
sh(["dest", "rm", "demo/development", "ingit"])

# 7. collision guard: dev may not push to production's address
sh(["dest", "add", "demo/production", "local", "--kind", "dotenv", "--set", f"path={OUT}/prod.env"], ok=False)
p = spawn(["dest", "add", "demo/production", "local", "--kind", "dotenv", "--set", f"path={OUT}/prod.env"])
p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
approved(["dest", "add", "demo/development", "sneaky", "--kind", "dotenv", "--set", f"path={OUT}/prod.env"])
r = sh(["push", "demo/development", "sneaky", "-y"], ok=False)
check("protected channel" in (r.stdout + r.stderr), "unprotected channel cannot push to a protected channel's address")
sh(["dest", "rm", "demo/development", "sneaky"])

# 8. protected push requires approval; wrong password denied
p = spawn(["push", "demo/production", "-y"])
p.expect("approval needed"); p.expect("Password: "); p.sendline("wrong wrong wrong")
p.expect("approval needed"); p.expect("Password: "); p.sendline(PW)
p.expect(pexpect.EOF)
r = sh(["log", "--event", "push", "-n", "5"])
check("prod.env" in r.stdout, "approved protected push happened and is logged")

# 9. reveal needs approval
p = spawn(["reveal", "demo/development", "API_KEY"])
p.expect("Password: "); p.sendline(PW); p.expect("rotated-by-tool"); p.expect(pexpect.EOF)
check(True, "reveal works with approval")
r = sh(["reveal", "demo/development", "API_KEY"], ok=False)
check(r.returncode != 0 and "rotated-by-tool" not in r.stdout, "reveal without a terminal is not answered")

# 10. elevate window
p = spawn(["elevate", "--for", "2m"]); p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
r = sh(["reveal", "demo/development", "API_KEY"])
check("rotated-by-tool" in r.stdout, "elevation window allows reveal without re-prompt")

# 10b. uninstalling and reinstalling the program keeps the vault: stop the agent, delete the
# binary, install a fresh copy somewhere else, and everything is still there.
import socket
def stop_agent():
    try:
        s = socket.socket(socket.AF_UNIX); s.connect(SOCK(HOME)); s.sendall(b'{"op":"shutdown","args":{},"client":"cli"}\n'); s.recv(200)
    except Exception: pass
    time.sleep(1)
def vault_files():
    out = {}
    for root, _, files in os.walk(os.path.join(HOME, "vault")):
        for f in files:
            fp = os.path.join(root, f); out[fp] = hashlib.sha256(open(fp, "rb").read()).hexdigest()
    return out
listing = sh(["ls"]).stdout
sh(["lock"]); stop_agent()
before = vault_files()
old_bin = os.path.join(SP, "bin-old", "pit"); os.makedirs(os.path.dirname(old_bin)); shutil.copy2(PIT, old_bin)
shutil.rmtree(os.path.dirname(old_bin))
check(before and vault_files() == before, "removing the program leaves every vault file untouched")
new_bin = os.path.join(SP, "bin-new", "pit"); os.makedirs(os.path.dirname(new_bin)); shutil.copy2(PIT, new_bin)
p = pexpect.spawn(new_bin, ["unlock"], env=env, encoding="utf-8", timeout=60); p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
r = subprocess.run([new_bin, "ls"], capture_output=True, env=env, text=True)
check(r.stdout == listing, "a fresh install lists the same projects, secrets and fingerprints")
p = pexpect.spawn(new_bin, ["elevate"], env=env, encoding="utf-8", timeout=60); p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
r = subprocess.run([new_bin, "reveal", "demo/development", "API_KEY"], capture_output=True, env=env, text=True)
check("rotated-by-tool" in r.stdout, "a fresh install opens the same values")
stop_agent(); shutil.rmtree(os.path.dirname(new_bin))
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)
p = spawn(["elevate"]); p.expect("Password: "); p.sendline(PW); p.expect(pexpect.EOF)

# 11. run injects env and files
r = subprocess.run([PIT, "run", "-c", "demo/development", "--", "sh", "-c", 'echo "$API_KEY|$SHARED_URL"; cat "$PIT_FILE_SIGNING_KEY" | wc -c'], capture_output=True, env=env, text=True)
check("rotated-by-tool|https://example.test" in r.stdout and "13" in r.stdout, "pit run injects env and file secrets")
leftover = [d for d in os.listdir(os.environ.get("TMPDIR", "/tmp")) if d.startswith("pit-run-")]
check(not leftover, "run cleans up its file folder")

# 11b. review regressions: path guards, templates, declare
os.symlink(HOME, os.path.join(OUT, "pitlink"))
for bad in [f"{OUT}/pitlink/vault/header.json", f"{OUT}/app/../../{os.path.basename(SP)}/pit-home/vault/x.env" if False else f"{HOME}/../{os.path.basename(HOME)}/vault/x.env"]:
    approved(["dest", "add", "demo/development", "bad", "--kind", "dotenv", "--set", f"path={bad}"])
    r = sh(["push", "demo/development", "bad", "-y", "--force"], ok=False)
    check(r.returncode != 0 and "own folder" in (r.stdout + r.stderr), "destination cannot reach the vault via symlink or .. (" + bad.split("/")[-3] + ")")
    sh(["dest", "rm", "demo/development", "bad"])
check(json.load(open(os.path.join(HOME, "vault/header.json")))["format"] == "the-pit/1", "vault header untouched")
approved(["dest", "add", "demo/development", "leak", "--kind", "dotenv", "--set", f"path={OUT}/x-{{API_KEY}}.env"])
r = sh(["push", "demo/development", "leak", "--dry-run"], ok=False)
check("plain secrets" in (r.stdout + r.stderr) and "rotated" not in (r.stdout + r.stderr), "destination settings refuse sealed secrets")
sh(["dest", "rm", "demo/development", "leak"])
r = sh(["declare", "demo/development", "API_KEY", "-p", "hashed"], ok=False)
check(r.returncode != 0 and "already exists" in r.stderr, "declare never changes an existing secret")

# 12. log integrity + tamper detection
r = sh(["log", "-n", "200"])
check("log intact" in r.stderr, "audit log chain verifies")
logp = os.path.join(HOME, "log/audit.log")
lines = open(logp).read().splitlines()
bak = list(lines)
del lines[3]
open(logp, "w").write("\n".join(lines) + "\n")
r = sh(["log"])
check("ALTERED" in r.stderr, "deleting a log line is detected")
open(logp, "w").write("\n".join(bak) + "\n")

# 13. backups: every change, list, diff
NAS = os.path.join(OUT, "nas")
r = sh(["backup", "target", "nas", "--kind", "dir", "--path", NAS])
snaps = sorted(os.listdir(NAS))
check(len(snaps) == 1 and snaps[0].endswith(".pitvault"), "adding a target sends it the current vault")
r = sh(["backup", "sync"])
check("nas: already up to date" in r.stderr, "sync sends nothing when every target is current")
snap = open(os.path.join(NAS, snaps[0])).read()
check("rotated-by-tool" not in snap and "dev-value" not in snap, "snapshot holds ciphertext only")
r = sh(["backup", "inspect", os.path.join(NAS, snaps[0])])
check("checksums verified" in r.stderr, "snapshot inspect verifies checksums")
sh(["set", "demo/development", "BACKUP_PROBE", "-d", "probe"], stdin="probe-value-1\n")
deadline = time.time() + 30
while len(os.listdir(NAS)) < 2 and time.time() < deadline: time.sleep(0.5)
check(len(os.listdir(NAS)) >= 2, "a change is backed up automatically within seconds")
r = sh(["backup", "list"])
check(re.search(r"^\s+1\s+\d{4}-", r.stdout, re.M) and "nas" in r.stdout, "backup list shows every backup and where it is")
r = sh(["backup", "diff", "nas:" + snaps[0]])
out = r.stdout + r.stderr
check("secret" in out and "demo/development BACKUP_PROBE" in out and "probe-value" not in out, "diff of a backup against now names what changed, never values")
r = sh(["backup", "diff", "2", "1"])
check("demo/development BACKUP_PROBE" in (r.stdout + r.stderr), "diff between two backups")
r = sh(["backup", "status"])
check("up to date" in r.stdout, "status shows each target holds the current vault")
r = sh(["backup", "target", "away", "--kind", "ssh", "--dest", "nobody@127.0.0.1:pit"], ok=False)
check(r.returncode != 0 and "will retry" in r.stderr, "an unreachable target is reported and kept for retry")
r = sh(["backup", "status"])
check(re.search(r"away[\s\S]*nothing sent yet[\s\S]*✗", r.stdout) is not None, "status shows the target is behind, and why")
sh(["backup", "untarget", "away"])

# 13b. ssh and rclone targets (stand-in tools that act on local folders)
FAKE_REMOTE = os.path.join(OUT, "remote-home"); FAKE_RCLONE = os.path.join(OUT, "rclone-store")
os.makedirs(FAKE_REMOTE); os.makedirs(FAKE_RCLONE)
real_path = env["PATH"]
env["PATH"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fakes") + ":" + real_path
env["FAKE_REMOTE"] = FAKE_REMOTE; env["FAKE_RCLONE"] = FAKE_RCLONE
sh(["backup", "target", "box", "--kind", "ssh", "--dest", "me@backup-box.invalid:~/the pit backups"])
remote_dir = os.path.join(FAKE_REMOTE, "the pit backups")
check(os.path.isdir(remote_dir) and stat.S_IMODE(os.stat(remote_dir).st_mode) == 0o700 and any(n.endswith(".pitvault") for n in os.listdir(remote_dir)), "ssh target: folder made private, backup sent (paths with spaces)")
sh(["backup", "target", "drive", "--kind", "rclone", "--remote", "gdrive:the-pit-backups"])
check(any(n.endswith(".pitvault") for n in os.listdir(os.path.join(FAKE_RCLONE, "the-pit-backups"))), "rclone target: backup sent")
r = sh(["backup", "list"])
check("box" in r.stdout and "drive" in r.stdout, "list covers ssh and rclone targets")
r = sh(["backup", "diff", "box:1"])
check("no differences" in r.stderr, "diff reads a backup back over ssh")
r = sh(["backup", "diff", "drive:latest"])
check("no differences" in r.stderr, "diff reads a backup back through rclone")
r = sh(["backup", "list", "--from", "ssh:me@backup-box.invalid:the pit backups"])
check(re.search(r"^\s+1\s", r.stdout, re.M) is not None, "a target written out on the command line can be listed (recovery on a new machine)")
sh(["backup", "untarget", "box"]); sh(["backup", "untarget", "drive"])
env["PATH"] = real_path
p = spawn(["backup", "bundle", "--project", "demo", "--out", os.path.join(OUT, "demo.pitbundle"), "--passphrase"])
p.expect("Bundle passphrase: "); p.sendline(PW2); p.expect("Repeat it: "); p.sendline(PW2); p.expect(pexpect.EOF)
b = open(os.path.join(OUT, "demo.pitbundle")).read()
check("rotated-by-tool" not in b, "bundle is encrypted")

# 14. lock / unlock
sh(["lock"])
r = sh(["ls"], ok=False)
check(r.returncode != 0 and "locked" in r.stderr, "locked pit refuses")
p = spawn(["unlock"]); p.expect("Password: "); p.sendline("nope nope nope nope"); p.expect("denied"); p.expect(pexpect.EOF)
p = spawn(["unlock", "--for", "10m"]); p.expect("Password: "); p.sendline(PW); p.expect("unlocked for"); p.expect(pexpect.EOF)
check(True, "unlock with password")
r = subprocess.run([PIT, "run", "-c", "demo/development", "--", "true"], capture_output=True, env=env, text=True, stdin=subprocess.DEVNULL)
check(r.returncode != 0 and "approval" in r.stderr, "pit run needs approval outside an elevation window")

# 15. TOTP
p = spawn(["mfa", "totp"])
p.expect(r"enter this key by hand: ([A-Z2-7]+)")
secret = p.match.group(1)
def totp(sec, t=None):
    key = base64.b32decode(sec + "=" * (-len(sec) % 8))
    c = int((t or time.time()) // 30)
    h = hmac.new(key, struct.pack(">Q", c), hashlib.sha1).digest()
    o = h[19] & 15
    return "%06d" % ((struct.unpack(">I", h[o:o+4])[0] & 0x7fffffff) % 1000000)
p.expect("Code shown in the app: "); p.sendline(totp(secret))
p.expect("Password: "); p.sendline(PW)
p.expect("authenticator enrolled"); p.expect(pexpect.EOF)
sh(["lock"])
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW); p.expect("Authenticator code: ")
time.sleep(31)
p.sendline(totp(secret)); p.expect("unlocked"); p.expect(pexpect.EOF)
check(True, "TOTP enrolled and required at unlock")

# 16. recovery: forgot password
sh(["lock"])
p = spawn(["recover"]); p.expect("Code: "); p.sendline(code)
p.expect("New password: "); p.sendline(PW2); p.expect("Repeat it: "); p.sendline(PW2)
p.expect("password replaced"); p.expect(pexpect.EOF)
sh(["lock"])
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW); p.expect("denied"); p.expect(pexpect.EOF)
time.sleep(1)
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW2); p.expect("Authenticator code: "); time.sleep(31); p.sendline(totp(secret)); p.expect("unlocked"); p.expect(pexpect.EOF)
check(True, "recovery code resets the password; old password stops working")

# 17. split recovery into shares, recover with 2 of 3
p = spawn(["recovery", "rotate", "--split", "2-of-3"])
p.expect("Authenticator code or password: "); p.sendline(PW2)
p.expect(r"share 1: (PIT-S-\S+)"); s1 = p.match.group(1)
p.expect(r"share 2: (PIT-S-\S+)")
p.expect(r"share 3: (PIT-S-\S+)"); s3 = p.match.group(1)
p.expect("Press Enter"); p.sendline(""); p.expect(pexpect.EOF)
sh(["lock"])
p = spawn(["recover"]); p.expect("Code: "); p.sendline(code); p.expect("denied"); p.expect(pexpect.EOF)
time.sleep(1)
p = spawn(["recover"]); p.expect("Code: "); p.sendline(s1 + "," + s3)
p.expect("New password: "); p.sendline(PW); p.expect("Repeat it: "); p.sendline(PW); p.expect("password replaced"); p.expect(pexpect.EOF)
check(True, "old recovery code revoked; 2-of-3 shares recover")

# 18. bundle import into a second vault
HOME2 = os.path.join(SP, "pit-home-2"); shutil.rmtree(HOME2, ignore_errors=True)
env2 = dict(env, PIT_HOME=HOME2)
p = pexpect.spawn(PIT, ["init", "--name", "other", "--no-touch-id"], env=env2, encoding="utf-8", timeout=60)
p.expect("New password: "); p.sendline(PW2); p.expect("Repeat it: "); p.sendline(PW2)
p.expect(r"(PIT-R-[0-9A-Z\-]+)"); c2 = p.match.group(1)
p.expect("type the last group"); p.sendline(c2.split("-")[-2]); p.expect(pexpect.EOF)
p = pexpect.spawn(PIT, ["backup", "import", os.path.join(OUT, "demo.pitbundle"), "--passphrase"], env=env2, encoding="utf-8", timeout=60)
p.expect("Bundle passphrase: "); p.sendline(PW2); p.expect("Password: "); p.sendline(PW2); p.expect(pexpect.EOF)
p = pexpect.spawn(PIT, ["elevate"], env=env2, encoding="utf-8", timeout=60); p.expect("Password: "); p.sendline(PW2); p.expect(pexpect.EOF)
r = subprocess.run([PIT, "reveal", "demo/development", "API_KEY"], env=env2, capture_output=True, text=True)
check("rotated-by-tool" in r.stdout, "passphrase bundle imports into another vault and values survive")
p = pexpect.spawn(PIT, ["emergency", "destroy"], env=env2, encoding="utf-8", timeout=60)
p.expect(r"Type (DESTROY [0-9a-f]+)"); p.sendline(p.match.group(1)); p.expect(pexpect.EOF)
import socket
def shutdown(home):
    try:
        s = socket.socket(socket.AF_UNIX); s.connect(SOCK(home)); s.sendall(b'{"op":"shutdown","args":{},"client":"cli"}\n'); s.recv(200)
    except Exception: pass
shutdown(HOME2); shutil.rmtree(HOME2, ignore_errors=True)

# 19. MCP
mcp = subprocess.Popen([PIT, "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, env=env, text=True)
def rpc(i, method, params=None):
    mcp.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params or {}}) + "\n"); mcp.stdin.flush()
    return json.loads(mcp.stdout.readline())
init = rpc(1, "initialize", {"protocolVersion": "2025-06-18"})
check(init["result"]["serverInfo"]["name"] == "the-pit", "MCP initialize")
tools = [t["name"] for t in rpc(2, "tools/list")["result"]["tools"]]
check("pit_push" in tools and not any("reveal" in t for t in tools), "MCP exposes no reveal tool")
lst = rpc(3, "tools/call", {"name": "pit_list", "arguments": {}})["result"]["content"][0]["text"]
check("API_KEY" in lst and "rotated-by-tool" not in lst, "MCP list shows names only")
gen = rpc(4, "tools/call", {"name": "pit_generate", "arguments": {"scope": "demo/development", "name": "API_KEY"}})["result"]
check(gen.get("isError") and "already has a value" in gen["content"][0]["text"], "MCP cannot overwrite a set secret")
push = rpc(5, "tools/call", {"name": "pit_push", "arguments": {"project": "demo", "channel": "development", "destinations": ["local"]}})["result"]
txt = push["content"][0]["text"]
m = re.search(r'ticket="([0-9a-f]+)"', txt)
check(push.get("isError") and m, "MCP push waits for approval with a ticket")
ticket = m.group(1)
p = spawn(["approve", ticket]); p.expect("assword: "); p.sendline(PW); p.expect("approved"); p.expect(pexpect.EOF)
push = rpc(6, "tools/call", {"name": "pit_push", "arguments": {"project": "demo", "channel": "development", "destinations": ["local"], "ticket": ticket}})["result"]
check(not push.get("isError"), "MCP push proceeds with the approved ticket")
again = rpc(7, "tools/call", {"name": "pit_push", "arguments": {"project": "demo", "channel": "development", "destinations": ["local"], "ticket": ticket}})["result"]
check(again.get("isError"), "an approval ticket is single-use")
mcp.stdin.close(); mcp.wait()
r = sh(["log", "--event", "push", "-n", "3"])
check("mcp (" in r.stdout, "log records the MCP client as the actor")

# 20. emergency export (plaintext tree)
p = spawn(["emergency", "export", "--out", os.path.join(OUT, "dump"), "--plaintext"])
p.expect(r"Continue\?"); p.sendline("y")
if p.expect(["assword: ", pexpect.EOF]) == 0:
    p.sendline(PW); p.expect(pexpect.EOF)
dump = open(os.path.join(OUT, "dump/demo/development/secrets.env")).read()
check("API_KEY=rotated-by-tool" in dump, "emergency export dumps every secret")

# 21. snapshot restore round trip
snapfile = os.path.join(NAS, snaps[0])
p = spawn(["backup", "restore", snapfile]); p.expect(r"Replace"); p.sendline("y"); p.expect("restored"); p.expect(pexpect.EOF)
p = spawn(["unlock"]); p.expect("assword: "); p.sendline(PW); p.expect("unlocked"); p.expect(pexpect.EOF)
r = sh(["ls", "demo"])
check("API_KEY" in r.stdout, "snapshot restores and opens with the password current at the time")

# 21b. review regressions: log truncation, library rollback, factor guessing
logp = os.path.join(HOME, "log/audit.log")
full = open(logp).read().splitlines()
open(logp, "w").write("\n".join(full[:2]) + "\n")
r = sh(["log"])
check("ALTERED" in r.stderr, "cutting the end of the log is detected")
open(logp, "w").write("\n".join(full) + "\n")
sh(["set", "demo/development", "BUMP"], stdin="1\n")
hist = sorted(os.listdir(os.path.join(HOME, "vault/history")))
libp = os.path.join(HOME, "vault/library.sealed")
cur = open(libp, "rb").read()
open(libp, "wb").write(open(os.path.join(HOME, "vault/history", hist[0]), "rb").read())
sh(["lock"])
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW); p.expect("older than"); p.expect(pexpect.EOF)
check(True, "an older library swapped in is refused")
open(libp, "wb").write(cur)
p = spawn(["unlock"]); p.expect("Password: "); p.sendline(PW); p.expect("unlocked"); p.expect(pexpect.EOF)
import socket as _s
def raw(op, args, auth=None, client="cli"):
    c = _s.socket(_s.AF_UNIX); c.connect(SOCK(HOME))
    c.sendall((json.dumps({"op": op, "args": args, "auth": auth, "client": client}) + "\n").encode())
    data = b""
    while not data.endswith(b"\n"):
        chunk = c.recv(65536)
        if not chunk: break
        data += chunk
    return json.loads(data)
codes = []
for i in range(8):
    codes.append(raw("secret.reveal", {"scope": "demo/development", "name": "API_KEY"}, {"totp": "%06d" % i})["error"]["code"])
check(codes[:3] == ["denied"] * 3 and all(c in ("throttled", "locked") for c in codes[3:]), f"guessing codes at the gate is throttled after 3 tries ({codes})")

# 21c. one-way secrets in a channel that pushes them
r = sh(["set", "demo/development", "NEW_PIN", "-p", "hashed"], stdin="9999\n", ok=False)
check(r.returncode != 0 and "pushed to" in r.stderr and "local (dotenv)" in r.stderr, "storing a pushed secret one-way needs confirmation")
r = sh(["ls", "demo"])
check("NEW_PIN" not in r.stdout, "an unconfirmed one-way secret is not created")
p = spawn(["set", "demo/development", "NEW_PIN", "-p", "hashed"]); p.expect("Value for"); p.sendline("9999")
p.expect("anyway"); p.sendline("y"); p.expect("set"); p.expect(pexpect.EOF)
r = sh(["ls", "demo"])
check("one-way but pushed to 1 destination" in r.stdout, "listing flags one-way secrets a destination expects")
r = raw("secret.edit", {"scope": "demo/development", "name": "API_KEY", "protection": "hashed"})
check(r.get("error", {}).get("code") == "confirm" and "pushed to" in r["error"]["message"], "switching a pushed secret to one-way needs confirmation")
r = sh(["ls", "demo"])
check(re.search(r"API_KEY\s.*sealed", r.stdout) is not None, "a refused switch leaves the secret sealed")
r = sh(["push", "demo/development", "local", "--dry-run", "--force"])
check("ADMIN_PIN NOT sent" in r.stderr, "push says loudly which one-way secrets were not sent")
r = raw("secret.declare", {"scope": "demo/development", "name": "AI_PIN", "protection": "hashed", "confirmed": True}, client="mcp")
check(r.get("error", {}).get("code") == "confirm", "an AI client cannot confirm a one-way secret that would be pushed")

# 21d. import a .env file
envf = os.path.join(OUT, "import.env")
open(envf, "w").write("# Mail service key.\nMAIL_KEY=mk-111-zzz\nexport QUOTED=\"a b\"\nAPI_KEY=something-else\nNEW_EMPTY=\n")
r = sh(["import", "env", envf, "--to", "demo/development", "--dry-run"])
check("MAIL_KEY" in r.stderr and "DIFFERENT value: API_KEY" in r.stderr and "nothing changed" in r.stderr, "import dry run shows new and differing keys")
r = sh(["import", "env", envf, "--to", "demo/development"])
out = r.stdout + r.stderr
check("2 added" in out and "kept the pit's values for: API_KEY" in out and "mk-111" not in out, "import adds new keys, keeps differing ones unless confirmed, never echoes values")
r = sh(["import", "env", envf, "--to", "demo/development"])
check("same value: MAIL_KEY QUOTED" in r.stderr, "re-importing the same file changes nothing")
r = sh(["ls", "demo"])
check("Mail service key." in r.stdout, "comments above a key become its description")
jf = os.path.join(OUT, "conf.json")
open(jf, "w").write(json.dumps({"stripe": {"secret": "sj-1"}, "PORT": 8080}))
r = sh(["import", "env", jf, "--to", "demo/development"])
check("stripe_secret" in r.stderr and "PORT" in r.stderr, "JSON files import, nested keys flattened")

# 21e. scan a project and pull findings in, leaving it untouched
proj = os.path.join(OUT, "proj"); os.makedirs(os.path.join(proj, "src"))
open(os.path.join(proj, ".env"), "w").write("STRIPE_SECRET_KEY=sk_" "test_FAKEFAKEFAKE1234567890abcd\nPORT=3000\n")
open(os.path.join(proj, "src/a.js"), "w").write('const clientSecret = "Qw8eRt5yUi2oPa9sDf";\nconst k = process.env.KEY;\n')
def tree_hash(d):
    h = hashlib.sha256()
    for root, _, files in sorted(os.walk(d)):
        for f in sorted(files):
            fp = os.path.join(root, f); h.update(fp.encode()); h.update(open(fp, "rb").read())
    return h.hexdigest()
before = tree_hash(proj)
r = sh(["scan", proj, "--report"])
check("STRIPE_SECRET_KEY" in r.stdout and "CLIENT_SECRET" in r.stdout and "PORT" not in r.stdout and "sk_test" not in r.stdout and "Qw8e" not in r.stdout, "scan names likely secrets without showing values")
p = spawn(["scan", proj, "--to", "scanned/development"])
p.expect("Copy which"); p.sendline("1")
p.expect("Rename"); p.sendline("1=STRIPE_KEY")
p.expect("Rename"); p.sendline("")
p.expect("create it"); p.sendline("y")
p.expect("create it"); p.sendline("y")
p.expect("1 added"); p.expect("was not changed"); p.expect(pexpect.EOF)
r = sh(["ls", "scanned"])
check("STRIPE_KEY" in r.stdout and "CLIENT_SECRET" not in r.stdout, "scan imports only what was picked, under the chosen name")
check(tree_hash(proj) == before, "scan leaves the project's files exactly as they were")

# 21b. console: hints for a mistyped command, Tab completion (names only)
p = spawn([]); p.expect("console")
p.sendline("veiw"); p.expect("Did you mean"); p.expect("reveal PROJECT/CHANNEL NAME")
check(True, "console explains a mistyped command and how to view a secret")
p.send("rev\t"); p.expect("reveal "); p.sendcontrol("u")
p.send("reveal demo/devel\t"); p.expect("demo/development "); p.send("API_\t"); p.expect("API_KEY "); p.sendcontrol("u")
check(True, "console Tab completes commands, scopes and secret names")
p.sendline("exit"); p.expect(pexpect.EOF)

# 21f. one approval covers a run of changes to the same channel from the same terminal
approved(["settings", "approval_window_secs", "300"])
r = sh(["set", "demo/production", "WIN_A", "--generate", "16"], ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "with no approval yet, a protected change asks")
approved(["set", "demo/production", "WIN_A", "--generate", "16"])
for n in ("WIN_B", "WIN_C", "WIN_D"):
    sh(["set", "demo/production", n, "--generate", "16"])
check(True, "after one approval, more changes to the same channel go ahead without asking again")
r = sh(["push", "demo/production", "--dry-run"])
check("WIN_D" in r.stdout, "a push preview never asks")
r = sh(["set", "demo", "WIN_E", "--generate", "16"], ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "the approval does not cover another scope")
r = sh(["reveal", "demo/production", "WIN_A"], ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "reveals are asked about every time")
r = raw("secret.generate", {"scope": "demo/production", "name": "WIN_AI", "length": 16}, client="mcp")
check(r.get("error", {}).get("code") == "approval_required", "AI clients are asked every time")
r = sh(["log", "--event", "approval.window"])
check("demo/production" in r.stdout, "the approval window is in the audit log")
approved(["settings", "approval_window_secs", "0"])
r = sh(["set", "demo/production", "WIN_F", "--generate", "16"], ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "approval_window_secs 0 asks every time again")

# 21g. sharing one secret with another vault
HOME3 = os.path.join(SP, "pit-home-3"); shutil.rmtree(HOME3, ignore_errors=True)
env3 = dict(env, PIT_HOME=HOME3)
def sh3(args, stdin=None, ok=True):
    r = subprocess.run([PIT] + args, input=stdin, capture_output=True, env=env3, text=True, timeout=120)
    if ok and r.returncode != 0:
        print("FAILED:", args, r.stdout, r.stderr); sys.exit(1)
    return r
p = pexpect.spawn(PIT, ["init", "--name", "sam", "--no-touch-id"], env=env3, encoding="utf-8", timeout=60)
p.expect("New password: "); p.sendline(PW2); p.expect("Repeat it: "); p.sendline(PW2)
p.expect(r"(PIT-R-[0-9A-Z\-]+)"); c3 = p.match.group(1)
p.expect("type the last group"); p.sendline(c3.split("-")[-2]); p.expect(pexpect.EOF)
sh3(["project", "add", "app", "--channels", "dev"])
sh(["set", "demo/development", "SHARE_ME"], stdin="shared-value-42\n")
def receive_request():
    r = sh3(["receive", "--for", "10m"])
    return re.search(r"PIT-RQ-[0-9A-Z\-]+", r.stdout).group(0)
def send(req, name="SHARE_ME"):
    out = approved(["share", "demo/development", name, "--to", req, "--trust"])
    return re.search(r"PIT-SH-[0-9A-Z\-]+", out).group(0)
req = receive_request()
r = sh(["share", "demo/development", "SHARE_ME", "--to", req], ok=False)
check(r.returncode != 0 and "--trust" in r.stderr and "PIT-ID-" in r.stderr, "sharing with an identity never confirmed asks to compare it first")
r = sh(["share", "demo/development", "SHARE_ME", "--to", req, "--trust"], ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "sharing a secret always needs approval")
r = raw("share.send", {"scope": "demo/development", "name": "SHARE_ME", "request": req, "trust": True}, client="mcp")
check(r.get("error", {}).get("code") == "refused", "AI clients cannot share secrets")
share = send(req)
check("shared-value-42" not in share, "the share is ciphertext")
r = sh(["contacts"])
check("sam" in r.stdout and "PIT-ID-" in r.stdout, "the confirmed recipient becomes a contact")
r = sh(["receive", share, "--into", "demo/development", "--trust"], ok=False)
check(r.returncode != 0 and "not made for this vault" in r.stderr, "a share opens only in the recipient's vault")
r = sh3(["receive", share, "--into", "app/dev"], ok=False)
check(r.returncode != 0 and "--trust" in r.stderr, "receiving from an unconfirmed sender asks to compare their identity")
r = sh3(["receive", share, "--into", "app/dev", "--trust"])
check("saved" in r.stderr and "window is closed" in r.stderr and "shared-value-42" not in r.stdout + r.stderr, "the recipient saves the share without seeing it")
p = pexpect.spawn(PIT, ["reveal", "app/dev", "SHARE_ME"], env=env3, encoding="utf-8", timeout=60)
p.expect("Password: "); p.sendline(PW2); p.expect(pexpect.EOF)
check("shared-value-42" in p.before, "the shared value arrives intact")
r = sh3(["receive", share, "--into", "app/dev", "--as", "AGAIN"], ok=False)
check(r.returncode != 0 and "window for this share is closed" in r.stderr, "a share opens once: its window closes when it is saved")
req = receive_request()
share = send(req)
sh3(["receive", "--cancel"])
r = sh3(["receive", share, "--into", "app/dev", "--as", "CANCELLED"], ok=False)
check(r.returncode != 0 and "closed" in r.stderr, "a cancelled window can no longer open its share")
req = receive_request()
share = send(req)
sh3(["lock"])
p = pexpect.spawn(PIT, ["unlock"], env=env3, encoding="utf-8", timeout=60); p.expect("Password: "); p.sendline(PW2); p.expect(pexpect.EOF)
r = sh3(["receive", share, "--into", "app/dev", "--as", "AFTER_LOCK"], ok=False)
check(r.returncode != 0 and "closed" in r.stderr, "locking the pit closes every receive window for good")
req = receive_request()
share = send(req)
r = sh3(["receive", share, "--into", "app/dev"], ok=False)
check(r.returncode != 0 and "already has a value" in r.stderr, "receiving never silently replaces a value")
r = sh3(["receive", share, "--into", "app/dev", "--as", "SECOND"])
check("saved" in r.stderr, "a known sender needs no identity check, and the window stayed open after the refusal")
r = sh3(["receive", "--list"])
check("no receive windows" in r.stderr, "no window is left open")
r = sh(["log", "--event", "share.send"])
check("SHARE_ME" in r.stdout and "sam" in r.stdout, "every share is in the sender's audit log")
shutdown(HOME3); shutil.rmtree(HOME3, ignore_errors=True)

# 21h. channels inside channels
r = sh(["channel", "add", "demo/staging/eu/fra"])
check("also created demo/staging, demo/staging/eu" in r.stderr, "adding a deep channel creates the channels above it")
r = sh(["channel", "add", "demo/a/..", ], ok=False)
check(r.returncode != 0, "a channel cannot be named ..")
sh(["set", "demo/staging", "STAGE_KEY"], stdin="from-staging\n")
sh(["set", "demo/staging", "OVR"], stdin="outer\n")
sh(["set", "demo/staging/eu", "OVR"], stdin="inner\n")
sh(["set", "demo/staging/eu/fra", "FRA_KEY"], stdin="from-fra\n")
r = sh(["ls", "demo/staging"])
check(re.search(r"\n\s+/eu\b", r.stdout) and re.search(r"\n\s+/fra\b", r.stdout) and "development" not in r.stdout, "ls shows nested channels as a tree, and filters by subtree")
out = approved(["run", "-c", "demo/staging/eu/fra", "--", "sh", "-c", "echo seen:$STAGE_KEY:$OVR:$FRA_KEY:$API_KEY"])
check("seen:from-staging:inner:from-fra:" in out, "a nested channel sees every channel above it, the nearest value winning")
sh(["channel", "edit", "demo/staging/eu", "--inherit", "false"])
out = approved(["run", "-c", "demo/staging/eu/fra", "--", "sh", "-c", "echo seen:$STAGE_KEY:$OVR:$FRA_KEY"])
check("seen::inner:from-fra" in out, "inheritance stops at a channel that does not inherit")
r = sh(["channel", "add", "demo/production/eu"])
check("(protected)" in r.stderr, "a channel inside a protected channel is protected")
p = spawn(["channel", "edit", "demo/production/eu", "--unprotected"])
p.expect("Password: "); p.sendline(PW); p.expect("inside a protected channel"); p.expect(pexpect.EOF)
check(True, "it cannot be unprotected while its parent is protected")
r = sh(["set", "demo/production/eu", "EU_PROD"], stdin="x\n", ok=False)
check(r.returncode != 0 and "approval" in r.stderr, "changing a nested protected channel needs approval")
sh(["channel", "edit", "demo/staging", "--rename", "stage"])
r = sh(["ls", "demo/stage/eu/fra"])
check("FRA_KEY" in r.stdout, "renaming a channel moves the channels inside it")
r = sh(["channel", "rm", "demo/stage"], ok=False)
check(r.returncode != 0 and "--recursive" in r.stderr, "removing a channel with channels inside asks for --recursive")
p = spawn(["channel", "rm", "demo/stage", "--recursive"])
p.expect(r"\[y/N\]"); p.sendline("y"); p.expect("Password: "); p.sendline(PW); p.expect("deleted, with 2 channel"); p.expect(pexpect.EOF)
r = sh(["ls", "demo"])
check("stage" not in r.stdout and "FRA_KEY" not in r.stdout, "--recursive removes the whole subtree")

# 21i. completion: shells, console hints, names only
sh(["channel", "add", "demo/development/feature-x"])
r = sh(["__complete", "reveal", "demo/dev"])
check("demo/development\t" in r.stdout and "demo/development/\t" in r.stdout, "shell completion offers a channel and the way deeper")
r = sh(["__complete", "reveal", "demo/development", ""])
check("API_KEY\t" in r.stdout and "rotated-by-tool" not in r.stdout, "shell completion lists secret names with hints, never values")
r = sh(["__complete", "set", "demo/development", "X", "--protection", ""])
check(r.stdout.startswith("hashed\t") and "sealed\t" in r.stdout, "flag values complete with descriptions")
r = sh(["__complete", "share", "demo/development", "API_KEY", "--to", ""])
check(r.stdout.strip() == "::files", "file arguments hand over to the shell's file completion")
r = raw("secret.reveal", {"scope": "demo/development", "name": "API_KEY"}, client="complete")
check(r.get("error", {}).get("code") == "refused", "the completion client can only read listings")
for shell in ("zsh", "bash", "fish"):
    check(len(sh(["completions", shell]).stdout) > 100, f"pit completions {shell}")
benv = dict(env, PATH=os.path.dirname(os.path.abspath(PIT)) + ":" + os.environ["PATH"])
r = subprocess.run(["bash", "-c", 'eval "$(pit completions bash)"; COMP_WORDS=(pit reveal demo/development/); COMP_CWORD=2; _pit; printf "%s\\n" "${COMPREPLY[@]}"'], env=benv, capture_output=True, text=True)
check("demo/development/feature-x" in r.stdout, "bash completion works end to end")
if shutil.which("zsh"):
    r = subprocess.run(["zsh", "-n", "-c", sh(["completions", "zsh"]).stdout], capture_output=True, text=True)
    check(r.returncode == 0, "the zsh script parses")
p = spawn([]); p.expect("console")
p.send("reve"); p.expect("Show a secret"); p.sendcontrol("u")
p.send("share "); p.expect("--to"); p.sendcontrol("u")
p.send("reveal demo/development/\t"); p.expect("feature-x"); p.sendcontrol("u")
p.sendline("exit"); p.expect(pexpect.EOF)
check(True, "the console shows hints as you type and completes nested channels")

# 22. destroy
p = spawn(["emergency", "destroy"]); p.expect(r"Type (DESTROY [0-9a-f]+)"); phrase = p.match.group(1); p.sendline(phrase); p.expect("vault is gone"); p.expect(pexpect.EOF)
check(not os.path.exists(os.path.join(HOME, "vault/header.json")), "destroy removes the vault")
shutdown(HOME)
if not os.environ.get("PIT_E2E_DIR"):
    shutil.rmtree(SP, ignore_errors=True)
print("\nALL E2E CHECKS PASSED")
