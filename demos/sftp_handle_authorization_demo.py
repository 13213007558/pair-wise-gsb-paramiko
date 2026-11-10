#!/usr/bin/env python3
"""
Demo: trusted-server, handle-scoped SFTP authorization.

An in-memory (loopback) SFTP server hands out capability-limited handles and
keeps a log of every backend callback it actually performs.  A client then
attempts both allowed and forbidden operations; the printed log makes it
possible to confirm that each rejection happens *before* any backend
callback, so no file is ever modified by a denied request.

Run from the repository root:

    python demos/sftp_handle_authorization_demo.py
"""

import os
import sys
import threading
import tempfile

# make the repository root importable when run as a plain script
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from paramiko import (
    AUTH_SUCCESSFUL,
    OPEN_SUCCEEDED,
    RSAKey,
    SFTP,
    SFTPAttributes,
    SFTPHandle,
    SFTPServer,
    SFTPServerInterface,
    Transport,
    HANDLE_FSTAT,
    HANDLE_READ,
    HANDLE_READDIR,
    SFTP_BAD_MESSAGE,
    SFTP_OK,
    SFTP_OP_UNSUPPORTED,
    SFTP_PERMISSION_DENIED,
    ServerInterface,
)
from paramiko.sftp import (
    CMD_ATTRS,
    CMD_CLOSE,
    CMD_DATA,
    CMD_EXTENDED,
    CMD_FSTAT,
    CMD_FSETSTAT,
    CMD_HANDLE,
    CMD_OPEN,
    CMD_OPENDIR,
    CMD_READ,
    CMD_READDIR,
    CMD_WRITE,
    int64,
)
from paramiko.sftp_attr import SFTPAttributes as Attrs

from tests._loop import LoopSocket
from tests._util import _support


# ---------------------------------------------------------------------------
# Server side
# ---------------------------------------------------------------------------


class PasswordServer(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


class LoggingFileHandle(SFTPHandle):
    """File handle backed by a real on-disk file, logging every callback."""

    def __init__(self, backend, label, events):
        super().__init__()
        self.readfile = backend
        self.writefile = backend
        self._label = label
        self._events = events

    def read(self, offset, length):
        self._events.append(("read", self._label))
        return super().read(offset, length)

    def write(self, offset, data):
        self._events.append(("write", self._label))
        return super().write(offset, data)

    def stat(self):
        self._events.append(("fstat", self._label))
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    def chattr(self, attr):
        self._events.append(("fsetstat", self._label))
        return SFTP_OP_UNSUPPORTED


class LoggingFolderHandle(SFTPHandle):
    def __init__(self, entries, events):
        super().__init__()
        self._set_files(entries)
        self._events = events

    def _get_next_files(self):
        self._events.append(("readdir", "folder"))
        return super()._get_next_files()


class TrustedSFTPServer(SFTPServerInterface):
    """
    Trusted server policy:

    * ``/readonly.txt`` is opened read-only no matter what flags the client
      requests (READ + FSTAT only).
    * ``/folder`` is a directory handle limited to READDIR.
    * ``/legacy.txt`` opts out of the mechanism (no limit), so every
      operation remains available, exactly as in older paramiko versions.
    """

    def __init__(self, server, root, events, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self._root = root
        self._events = events

    def _realpath(self, path):
        return os.path.join(self._root, path.lstrip("/"))

    def open(self, path, flags, attr):
        self._events.append(("open", path))
        backend = open(self._realpath(path), "r+b")
        handle = LoggingFileHandle(backend, path, self._events)
        if path == "/readonly.txt":
            # client flags cannot widen this server-approved scope
            handle.allow(HANDLE_READ | HANDLE_FSTAT)
        # /legacy.txt intentionally gets no limit -> mechanism disabled
        return handle

    def list_folder(self, path):
        self._events.append(("list_folder", path))
        entries = []
        for name in sorted(os.listdir(self._realpath(path))):
            attr = SFTPAttributes.from_stat(
                os.stat(os.path.join(self._realpath(path), name))
            )
            attr.filename = name
            entries.append(attr)
        handle = LoggingFolderHandle(entries, self._events)
        handle.allow(HANDLE_READDIR)
        return handle


# ---------------------------------------------------------------------------
# Client-side helpers (raw protocol requests so status codes stay visible)
# ---------------------------------------------------------------------------


def raw_status(sftp, *args):
    """
    Send a request and return the raw SFTP status code, bypassing the
    client's conversion of status codes into exceptions.

    Successful non-status replies (for example a readdir NAME packet) are
    reported as SFTP_OK.
    """
    captured = {}

    def capture(msg):
        captured["code"] = msg.get_int()

    original = sftp._convert_status
    sftp._convert_status = capture
    try:
        t, _ = sftp._request(*args)
    finally:
        sftp._convert_status = original
    return captured.get("code", SFTP_OK)


def open_raw(sftp, path, pflags):
    t, msg = sftp._request(CMD_OPEN, path, pflags, Attrs())
    assert t == CMD_HANDLE
    return msg.get_string()


def opendir_raw(sftp, path):
    t, msg = sftp._request(CMD_OPENDIR, path)
    assert t == CMD_HANDLE
    return msg.get_string()


STATUS_NAME = {
    SFTP_OK: "OK",
    SFTP_PERMISSION_DENIED: "PERMISSION_DENIED",
    SFTP_BAD_MESSAGE: "BAD_MESSAGE",
    SFTP_OP_UNSUPPORTED: "OP_UNSUPPORTED",
}


def report(title, code, expected):
    verdict = "PASS" if code == expected else "FAIL"
    print(
        "  [{verdict}] {title}: {actual} (expected {want})".format(
            verdict=verdict,
            title=title,
            actual=STATUS_NAME.get(code, code),
            want=STATUS_NAME.get(expected, expected),
        )
    )


def main():
    root = tempfile.mkdtemp(prefix="sftp-handle-authz-")
    readonly = os.path.join(root, "readonly.txt")
    legacy = os.path.join(root, "legacy.txt")
    os.mkdir(os.path.join(root, "folder"))
    with open(os.path.join(root, "folder", "entry.txt"), "wb") as f:
        f.write(b"listed")
    with open(readonly, "wb") as f:
        f.write(b"do-not-touch")
    with open(legacy, "wb") as f:
        f.write(b"legacy")

    events = []

    server_sock = LoopSocket()
    client_sock = LoopSocket()
    client_sock.link(server_sock)

    server_transport = Transport(server_sock)
    server_transport.add_server_key(
        RSAKey.from_private_key_file(_support("rsa.key"))
    )
    server_transport.set_subsystem_handler(
        "sftp", SFTPServer, TrustedSFTPServer, root, events
    )
    ready = threading.Event()
    server_transport.start_server(ready, PasswordServer())
    ready.wait(1.0)

    client_transport = Transport(client_sock)
    client_transport.connect(username="user", password="pass")
    sftp = SFTP.from_transport(client_transport)

    # the client asks for read+write, but the server grants read-only
    pflags = 0x1 | 0x2  # SFTP_FLAG_READ | SFTP_FLAG_WRITE
    ro_handle = open_raw(sftp, "/readonly.txt", pflags)
    folder_handle = opendir_raw(sftp, "/folder")
    legacy_handle = open_raw(sftp, "/legacy.txt", pflags)

    print("== Forbidden operations on a read-only file handle ==")
    report(
        "write denied",
        raw_status(sftp, CMD_WRITE, ro_handle, int64(0), b"hack"),
        SFTP_PERMISSION_DENIED,
    )
    setstat = Attrs()
    setstat.st_size = 0
    report(
        "fsetstat denied",
        raw_status(sftp, CMD_FSETSTAT, ro_handle, setstat),
        SFTP_PERMISSION_DENIED,
    )

    print("== Directory handle cannot be used as a file ==")
    report(
        "write to folder handle",
        raw_status(sftp, CMD_WRITE, folder_handle, int64(0), b"x"),
        SFTP_BAD_MESSAGE,
    )
    report(
        "readdir as file read",
        raw_status(sftp, CMD_READ, folder_handle, int64(0), 4),
        SFTP_BAD_MESSAGE,
    )
    report(
        "file handle used for readdir",
        raw_status(sftp, CMD_READDIR, ro_handle),
        SFTP_BAD_MESSAGE,
    )

    print("== Unknown extensions never gain implicit write access ==")
    report(
        "unknown extended request",
        raw_status(
            sftp, CMD_EXTENDED, "vendor-escalate", ro_handle
        ),
        SFTP_OP_UNSUPPORTED,
    )

    print("== Allowed operations still work ==")
    t, msg = sftp._request(CMD_READ, ro_handle, int64(0), 12)
    assert t == CMD_DATA and msg.get_binary() == b"do-not-touch"
    print("  [PASS] read returned the original bytes")
    t, _ = sftp._request(CMD_FSTAT, ro_handle)
    assert t == CMD_ATTRS
    print("  [PASS] fstat succeeded")
    report(
        "readdir on the folder handle",
        raw_status(sftp, CMD_READDIR, folder_handle),
        SFTP_OK,
    )
    report(
        "write on an unconstrained legacy handle",
        raw_status(sftp, CMD_WRITE, legacy_handle, int64(0), b"ok"),
        SFTP_OK,
    )

    print("== A closed handle cannot be reused ==")
    assert raw_status(sftp, CMD_CLOSE, ro_handle) == SFTP_OK
    report(
        "write after close",
        raw_status(sftp, CMD_WRITE, ro_handle, int64(0), b"x"),
        SFTP_BAD_MESSAGE,
    )

    sftp.close()
    client_transport.close()
    server_transport.close()

    print("\n== Backend callbacks actually triggered ==")
    for name, label in events:
        print("  - {}({})".format(name, label))

    wrote_to_readonly = any(
        name == "write" and label == "/readonly.txt" for name, label in events
    )
    fsetstat_readonly = any(
        name == "fsetstat" and label == "/readonly.txt"
        for name, label in events
    )
    untouched = open(readonly, "rb").read() == b"do-not-touch"

    print("\n== Security assertions ==")
    print(
        "  [{}] no write callback on the read-only file".format(
            "PASS" if not wrote_to_readonly else "FAIL"
        )
    )
    print(
        "  [{}] no fsetstat callback on the read-only file".format(
            "PASS" if not fsetstat_readonly else "FAIL"
        )
    )
    print(
        "  [{}] read-only file bytes are unchanged on disk".format(
            "PASS" if untouched else "FAIL"
        )
    )

    assert not wrote_to_readonly and not fsetstat_readonly and untouched
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
