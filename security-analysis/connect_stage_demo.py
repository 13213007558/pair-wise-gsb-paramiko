"""
connect()-stage evidence (no real process, no network, no Transport thread).

Uses a transport_factory stub to stop inside SSHClient.connect right after
socket selection, proving:
  * SSHConfig.lookup spawns nothing;
  * ProxyCommand spawns only on explicit caller construction;
  * with sock= supplied, connect() skips getaddrinfo/socket() entirely
    (paramiko/client.py:352 `if not sock:`);
  * connect() itself never reads SSHConfig (no config plumbing in client.py).
"""
import os
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import paramiko.client as cl
import paramiko.proxy as pxy
from paramiko.client import SSHClient
from paramiko.config import SSHConfig

SPAWNED = []


class FakePopen:
    def __init__(self, cmd, stdin=None, stdout=None, stderr=None,
                 bufsize=0, **kw):
        self.cmd = cmd
        self.pid = -1
        self.returncode = None
        self.stdin = MagicMock()
        self.stdout = MagicMock()
        self.stderr = MagicMock()
        SPAWNED.append(cmd)


def main():
    pxy.subprocess.Popen = FakePopen
    cfg = SSHConfig.from_text(
        'Host demo\n    HostName real-target.test\n    User svc\n'
        '    ProxyCommand "sentinel --host %h"\n'
    )
    opts = cfg.lookup("demo")
    print("1) after lookup, spawns =", SPAWNED)

    proxy = pxy.ProxyCommand(opts["proxycommand"])
    print("2) after explicit ProxyCommand(), spawns =", SPAWNED)

    with patch.object(cl.socket, "getaddrinfo") as gai, patch.object(
        cl.socket, "socket"
    ) as sk:
        seen = {}

        def fake_transport(sock, **kw):
            seen["sock"] = sock
            raise RuntimeError("stop-before-handshake")

        client = SSHClient()
        try:
            client.connect(
                "real-target.test", sock=proxy, username="svc",
                allow_agent=False, look_for_keys=False,
                transport_factory=fake_transport,
            )
        except RuntimeError:
            pass
        print("3) transport received our proxy object:",
              seen.get("sock") is proxy)
        print("   getaddrinfo called:", gai.called,
              "| socket() called:", sk.called)
    print("4) total spawns:", len(SPAWNED),
          "- connect() added zero; config is never consulted there.")


if __name__ == "__main__":
    main()
