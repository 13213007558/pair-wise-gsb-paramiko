"""
Evidence harness: trace what paramiko's SSHConfig pipeline actually does.

The configs only reference sentinel paths/commands (probe-exec, proxy-sentinel).
Every side-effecting API is replaced by a recording stub, so no config-supplied
external command is ever executed and no real network/file access occurs.

Recorded channels:
  SPAWN : subprocess.Popen            (ProxyCommand construction)
  EXEC  : invoke.run                  (Match exec evaluation, inside lookup)
  DNS   : socket.gethostbyname/getaddrinfo/getfqdn
  OPEN  : builtins.open / os.path.expanduser (path reads / home resolution)
"""
import builtins
import io
import os
import shlex
import socket
import sys
from contextlib import contextmanager

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from paramiko.config import SSHConfig, LazyFqdn
import paramiko.config as cfg
import paramiko.proxy as pxy
from paramiko.proxy import ProxyCommand

HERE = os.path.dirname(os.path.abspath(__file__))
CONF_DIR = os.path.join(HERE, "configs")
EVENTS = []


def log(channel, detail):
    EVENTS.append((channel, detail))


class FakePopen:
    def __init__(self, cmd, stdin=None, stdout=None, stderr=None,
                 bufsize=0, **kwargs):
        self.cmd = cmd
        self.pid = 0
        self.returncode = None
        self.stdin = io.BytesIO()
        self.stdout = io.BytesIO(b"")
        self.stderr = io.BytesIO(b"")
        log("SPAWN", " ".join(cmd))

    def poll(self):
        return self.returncode


def fake_run(command, *args, **kwargs):
    log("EXEC", command)

    class R:
        ok = not command.startswith("probe-exec --fail")
        exited = 0 if ok else 1

    return R()


class GAIError(Exception):
    pass


def make_dns_stubs(fail_names=()):
    def gethostbyname(name):
        log("DNS", "gethostbyname(%r)" % name)
        if name in fail_names:
            raise socket.gaierror("stub: no record for %s" % name)
        return "203.0.113.7"

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        log("DNS", "getaddrinfo(%r, family=%s)" % (host, family))
        if host in fail_names:
            raise socket.gaierror("stub: no record for %s" % host)
        return [(socket.AF_INET, socket.SOCK_DGRAM, proto, "stub-fqdn.test",
                 ("203.0.113.7", 0))]

    def getfqdn(name=""):
        log("DNS", "getfqdn(%r)" % name)
        return "stub-host.lab.test"

    return gethostbyname, getaddrinfo, getfqdn


real_open = builtins.open
real_expanduser = os.path.expanduser
REAL_POPEN = pxy.subprocess.Popen
REAL_RUN = cfg.invoke.run
REAL_SOCKET = cfg.socket


def fake_open(path, *args, **kwargs):
    log("OPEN", "open(%r)" % str(path))
    return real_open(path, *args, **kwargs)


def fake_expanduser(path):
    result = real_expanduser(path)
    if "~" in str(path):
        log("OPEN", "expanduser(%r) -> %r" % (path, result))
    return result


@contextmanager
def instrumented(fail_dns=()):
    EVENTS.clear()
    ghbn, gai, gfqdn = make_dns_stubs(fail_dns)
    builtins.open = fake_open
    os.path.expanduser = fake_expanduser
    cfg.socket.gethostbyname = ghbn
    cfg.socket.getaddrinfo = gai
    cfg.socket.getfqdn = gfqdn
    pxy.subprocess.Popen = FakePopen
    cfg.invoke.run = fake_run
    try:
        yield EVENTS
    finally:
        builtins.open = real_open
        os.path.expanduser = real_expanduser
        cfg.socket = REAL_SOCKET
        pxy.subprocess.Popen = REAL_POPEN
        cfg.invoke.run = REAL_RUN


def report(title):
    print("\n=== %s ===" % title)


def dump(events):
    if not events:
        print("  (no side effects recorded)")
    for channel, detail in events:
        print("  [%-5s] %s" % (channel, detail))


def load(name):
    return SSHConfig.from_path(os.path.join(CONF_DIR, name))


print("# Evidence run: all side effects below are stubs; nothing really runs")
print("# python:", sys.version.split()[0], "| paramiko baseline 5.1.0")

# --- Case 1: parse alone -----------------------------------------------------
report("CASE 1  parse() only, no lookup (config 01, Match exec present)")
with instrumented() as ev:
    cfg_obj = load("01-match-exec.conf")
dump(ev)

# --- Case 2: lookup, Match exec condition true -------------------------------
report("CASE 2  lookup() normal match, exec succeeds (config 01)")
with instrumented() as ev:
    result = cfg_obj.lookup("plain-anything")
print("  result.user      =", result.get("user"))
print("  result.hostname  =", result.get("hostname"))
dump(ev)

# --- Case 3: lookup, Match exec condition false ------------------------------
report("CASE 3  lookup() with exec returning non-zero (condition false)")
with instrumented() as ev:
    cfg3 = SSHConfig.from_text(
        'Match exec "probe-exec --fail"\n    User should-not-appear\n'
    )
    ev.clear()
    result = cfg3.lookup("some-host")
print("  result.user      =", result.get("user"), "(absent => stanza skipped)")
dump(ev)

# --- Case 4: same config queried twice ---------------------------------------
report("CASE 4  lookup() called twice on one parsed config (config 01)")
with instrumented() as ev:
    r1 = cfg_obj.lookup("plain-anything")
    r2 = cfg_obj.lookup("plain-anything")
print("  user values:", r1.get("user"), "/", r2.get("user"))
dump(ev)

# --- Case 5: canonicalization, DNS + double exec -----------------------------
report("CASE 5  canonicalized re-match: DNS queries and both exec passes (02)")
with instrumented(fail_dns=("www.lab.test",)) as ev:
    canon_cfg = load("02-canon-exec.conf")
    ev.clear()
    result = canon_cfg.lookup("www")
print("  result.hostname  =", result.get("hostname"))
print("  result.user      =", result.get("user"))
dump(ev)

# --- Case 5b: all DNS fails, fallback local keeps original name --------------
report("CASE 5b canonicalization fails DNS, fallback local (config 02)")
with instrumented(fail_dns=("www.lab.test", "www.corp.test")) as ev:
    result = canon_cfg.lookup("www")
print("  result.hostname  =", result.get("hostname"))
dump(ev)

# --- Case 6: token expansion + ProxyCommand stages ---------------------------
report("CASE 6  placeholder expansion at lookup; ProxyCommand only at Popen (03)")
with instrumented() as ev:
    tok_cfg = load("03-proxy-tokens.conf")
    ev.clear()
    result = tok_cfg.lookup("gateway")
    print("  result.hostname      =", result.get("hostname"))
    print("  result.proxycommand  =", result.get("proxycommand"))
    print("  result.identityfile  =", result.get("identityfile"))
    print("  -- after lookup, before ProxyCommand():")
    dump(ev)
    proxy = ProxyCommand(result["proxycommand"])
    print("  -- after ProxyCommand() construction:")
    dump(ev)

# --- Case 7: ProxyCommand none must never spawn ------------------------------
report("CASE 7  ProxyCommand none is None, construction skipped (config 04)")
with instrumented() as ev:
    none_cfg = load("04-proxy-none.conf")
    result_no = none_cfg.lookup("no-proxy")
    result_yes = none_cfg.lookup("with-proxy")
    print("  proxycommand(no-proxy)    =", result_no.get("proxycommand"))
    print("  proxycommand(with-proxy)  =", result_yes.get("proxycommand"))
    if result_yes.get("proxycommand"):
        ProxyCommand(result_yes["proxycommand"])
    if result_no.get("proxycommand") is None:
        print("  skipping ProxyCommand(None): no process requested")
    dump(ev)

# --- Case 8: %l triggers local FQDN resolution during lookup ----------------
report("CASE 8  %%l token causes local FQDN DNS lookups during lookup (05)")
with instrumented() as ev:
    fqdn_cfg = load("05-fqdn-token.conf")
    ev.clear()
    result = fqdn_cfg.lookup("fqdn-host")
    print("  result.user =", result.get("user"))
    dump(ev)
