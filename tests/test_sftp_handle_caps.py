# Copyright (C) 2026  Paramiko developers
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the
# Free Software Foundation; either version 2.1 of the License, or (at your
# option) any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License
# for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Protocol-level tests for the optional, handle-scoped SFTP authorization
mechanism.

A trusted server returns capability-limited `.SFTPHandle` objects and
records every backend callback it actually runs, so each test can prove a
rejected request never reached a callback (and therefore never modified a
file).
"""

import os
import threading

import pytest

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
    HANDLE_ALL,
    HANDLE_CHECK_FILE,
    HANDLE_FSTAT,
    HANDLE_FSETSTAT,
    HANDLE_READ,
    HANDLE_READDIR,
    HANDLE_WRITE,
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
    SFTP_FLAG_READ,
    SFTP_FLAG_WRITE,
    int64,
)

from ._loop import LoopSocket
from ._util import _support


class RecordingServer(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


class RecordingHandle(SFTPHandle):
    """
    Handle that records each business callback the server actually runs.
    """

    def __init__(self, owner, label, flags=0):
        super().__init__(flags)
        self._owner = owner
        self._label = label
        self.readfile = None
        self.writefile = None

    def read(self, offset, length):
        self._owner.record("read", self._label)
        return b"allowed-data"

    def write(self, offset, data):
        self._owner.record("write", self._label)
        return SFTP_OK

    def stat(self):
        self._owner.record("fstat", self._label)
        attr = SFTPAttributes()
        attr.st_size = 11
        return attr

    def chattr(self, attr):
        self._owner.record("fsetstat", self._label)
        return SFTP_OK


class FolderHandle(SFTPHandle):
    """
    Directory handle whose readdir callback records invocations.
    """

    def __init__(self, owner, entries):
        super().__init__()
        self._owner = owner
        self._set_files(entries)

    def _get_next_files(self):
        self._owner.record("readdir", "folder")
        return super()._get_next_files()


class RecordingSFTPServer(SFTPServerInterface):
    # policy: path -> capability bitmask.  Paths missing from the map get an
    # unconstrained handle (the historical, mechanism-disabled behavior).
    policy = {}

    def __init__(self, server, events, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.events = events

    def record(self, name, label):
        self.events.append((name, label))

    def open(self, path, flags, attr):
        self.record("open", path)
        handle = RecordingHandle(self, path, flags)
        if path in self.policy:
            # the server decides the scope; the client's flags are irrelevant
            handle.allow(self.policy[path])
        return handle

    def list_folder(self, path):
        self.record("list_folder", path)
        attr = SFTPAttributes()
        attr.filename = "entry"
        handle = FolderHandle(self, [attr])
        if path in self.policy:
            handle.allow(self.policy[path])
        return handle

    def rename(self, oldpath, newpath):
        self.record("rename", (oldpath, newpath))
        return SFTP_OK


def make_transport(events, policy, sftp_si=None):
    """Spin up paired client/server transports over in-memory sockets."""
    server_sock = LoopSocket()
    client_sock = LoopSocket()
    client_sock.link(server_sock)

    server_transport = Transport(server_sock)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    server_transport.add_server_key(host_key)

    if sftp_si is None:
        bound_policy = dict(policy)

        class sftp_si(RecordingSFTPServer):
            policy = bound_policy

    def factory(channel, name, server, *args, **kwargs):
        return SFTPServer(
            channel, name, server, sftp_si, events, *args, **kwargs
        )

    server_transport.set_subsystem_handler("sftp", factory)
    ready = threading.Event()
    server_transport.start_server(ready, RecordingServer())
    ready.wait(1.0)

    client_transport = Transport(client_sock)
    client_transport.connect(username="user", password="pass")
    return client_transport, server_transport


@pytest.fixture
def harness():
    events = []
    policy = {
        "/ro": HANDLE_READ | HANDLE_FSTAT,
        "/dir": HANDLE_READDIR,
        "/locked-dir": 0,
    }
    client_transport, server_transport = make_transport(events, policy)
    client = SFTP.from_transport(client_transport)
    yield client, events
    client.close()
    client_transport.close()
    server_transport.close()


def raw_request(client, *args):
    """
    Send a request and return the raw SFTP status code, bypassing the
    client's conversion of status codes into exceptions.
    """
    original = client._convert_status

    def capture(msg):
        capture.code = msg.get_int()

    client._convert_status = capture
    try:
        client._request(*args)
    finally:
        client._convert_status = original
    return capture.code


def open_handle(client, path, pflags=None):
    """Open via the wire and return the raw server handle bytes."""
    if pflags is None:
        # client asks for read+write; the server may still grant read-only
        pflags = SFTP_FLAG_READ | SFTP_FLAG_WRITE
    t, msg = client._request(
        CMD_OPEN, path, pflags, SFTPAttributes()
    )
    assert t == CMD_HANDLE
    return msg.get_string()


def open_dir_handle(client, path):
    t, msg = client._request(CMD_OPENDIR, path)
    assert t == CMD_HANDLE
    return msg.get_string()


def setstat_attr():
    attr = SFTPAttributes()
    attr.st_size = 42
    return attr


def test_unit_handle_allows_everything_when_unconstrained():
    handle = SFTPHandle()
    for cap in (
        HANDLE_READ,
        HANDLE_WRITE,
        HANDLE_FSTAT,
        HANDLE_FSETSTAT,
        HANDLE_READDIR,
        HANDLE_CHECK_FILE,
    ):
        assert handle.allows(cap)


def test_unit_allow_limits_scope():
    handle = SFTPHandle().allow(HANDLE_READ | HANDLE_FSTAT)
    assert handle.allows(HANDLE_READ)
    assert handle.allows(HANDLE_FSTAT)
    assert not handle.allows(HANDLE_WRITE)
    assert not handle.allows(HANDLE_FSETSTAT)
    assert not handle.allows(HANDLE_READDIR)


def test_unit_allow_replaces_previous_scope():
    handle = SFTPHandle().allow(HANDLE_ALL).allow(HANDLE_READ)
    assert handle.allows(HANDLE_READ)
    assert not handle.allows(HANDLE_WRITE)


def test_unit_deny_without_limit_starts_from_all():
    handle = SFTPHandle().deny(HANDLE_WRITE | HANDLE_FSETSTAT)
    assert handle.allows(HANDLE_READ)
    assert handle.allows(HANDLE_FSTAT)
    assert not handle.allows(HANDLE_WRITE)
    assert not handle.allows(HANDLE_FSETSTAT)


def test_unit_client_flags_cannot_widen_scope(harness):
    # the bitmask is set by the server; flags live on a separate attribute
    client, events = harness
    handle = SFTPHandle(flags=os.O_RDWR)
    handle.allow(HANDLE_READ)
    assert not handle.allows(HANDLE_WRITE)


def test_read_only_handle_rejects_write_before_callback(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    code = raw_request(client, CMD_WRITE, handle, int64(0), b"payload")

    assert code == SFTP_PERMISSION_DENIED
    assert events == []


def test_read_only_handle_rejects_fsetstat_before_callback(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    code = raw_request(
        client, CMD_FSETSTAT, handle, setstat_attr()
    )

    assert code == SFTP_PERMISSION_DENIED
    assert events == []


def test_read_only_handle_allows_read_and_fstat(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    t, msg = client._request(CMD_READ, handle, int64(0), 8)
    assert t == CMD_DATA
    assert msg.get_binary() == b"allowed-data"

    t, msg = client._request(CMD_FSTAT, handle)
    assert t == CMD_ATTRS
    assert ("read", "/ro") in events
    assert ("fstat", "/ro") in events
    assert not any(name == "write" for name, _ in events)


def test_folder_handle_rejects_file_write(harness):
    client, events = harness
    handle = open_dir_handle(client, "/dir")
    events.clear()

    code = raw_request(client, CMD_WRITE, handle, int64(0), b"x")

    assert code == SFTP_BAD_MESSAGE
    assert events == []


def test_folder_handle_rejects_file_fsetstat(harness):
    client, events = harness
    handle = open_dir_handle(client, "/dir")
    events.clear()

    code = raw_request(client, CMD_FSETSTAT, handle, setstat_attr())

    assert code == SFTP_BAD_MESSAGE
    assert events == []


def test_folder_handle_rejects_file_read(harness):
    client, events = harness
    handle = open_dir_handle(client, "/dir")
    events.clear()

    code = raw_request(client, CMD_READ, handle, int64(0), 4)

    assert code == SFTP_BAD_MESSAGE
    assert events == []


def test_file_handle_rejects_readdir(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    code = raw_request(client, CMD_READDIR, handle)

    assert code == SFTP_BAD_MESSAGE
    assert events == []


def test_readdir_capability_gates_folder_listing(harness):
    client, events = harness
    handle = open_dir_handle(client, "/locked-dir")
    events.clear()

    code = raw_request(client, CMD_READDIR, handle)

    assert code == SFTP_PERMISSION_DENIED
    assert events == []


def test_closed_handle_cannot_be_reused(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    assert raw_request(client, CMD_CLOSE, handle) == SFTP_OK
    events.clear()

    for command, args in (
        (CMD_READ, (int64(0), 4)),
        (CMD_WRITE, (int64(0), b"x")),
        (CMD_FSTAT, ()),
        (CMD_FSETSTAT, (setstat_attr(),)),
    ):
        assert raw_request(client, command, handle, *args) == SFTP_BAD_MESSAGE

    assert events == []


def test_same_bytes_on_new_connection_have_no_authorization(harness):
    client, events = harness
    first = open_handle(client, "/ro")
    assert raw_request(client, CMD_CLOSE, first) == SFTP_OK

    # the server numbers handles from 1 per session, so a fresh session
    # hands out the same bytes, but they must not carry the old scope
    other_events = []
    other_transport, other_server = make_transport(
        other_events, {"/ro": HANDLE_READ}
    )
    try:
        other_client = SFTP.from_transport(other_transport)
        second = open_handle(other_client, "/ro")
        assert second == first
        # valid in the new session with its own fresh authorization
        t, _ = other_client._request(CMD_READ, second, int64(0), 4)
        assert t == CMD_DATA
        # the original closed bytes are still invalid in the first session
        assert raw_request(
            client, CMD_WRITE, first, int64(0), b"x"
        ) == SFTP_BAD_MESSAGE
    finally:
        other_client.close()
        other_transport.close()
        other_server.close()


def test_rename_does_not_change_handle_authorization(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    assert client.rename("/ro", "/renamed") is None

    code = raw_request(client, CMD_WRITE, handle, int64(0), b"x")
    assert code == SFTP_PERMISSION_DENIED
    # rename happened, but no write callback ever ran
    assert ("rename", ("/ro", "/renamed")) in events
    assert not any(name == "write" for name, _ in events)


def test_unknown_extension_is_unsupported_not_writable(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    code = raw_request(
        client, CMD_EXTENDED, "vendor-make-me-write", handle
    )

    assert code == SFTP_OP_UNSUPPORTED
    assert events == []


def test_check_file_respects_handle_scope(harness):
    client, events = harness
    handle = open_handle(client, "/ro")
    events.clear()

    # check-file reads file contents; a read-only handle without the
    # CHECK_FILE capability must be rejected without any read callback
    code = raw_request(
        client,
        CMD_EXTENDED,
        "check-file",
        handle,
        "md5,sha1",
        int64(0),
        int64(0),
        int(0),
    )

    assert code == SFTP_PERMISSION_DENIED
    assert events == []


def test_unconstrained_handle_keeps_legacy_behavior(harness):
    client, events = harness
    handle = open_handle(client, "/legacy")
    events.clear()

    assert raw_request(
        client, CMD_WRITE, handle, int64(0), b"x"
    ) == SFTP_OK
    assert ("write", "/legacy") in events

    assert raw_request(client, CMD_FSETSTAT, handle, setstat_attr()) == (
        SFTP_OK
    )
    assert ("fsetstat", "/legacy") in events


def test_rejection_does_not_modify_file_backend(harness, tmp_path):
    # end-to-end proof using a real file: a denied write leaves the bytes
    # untouched and no write callback is recorded.
    target = tmp_path / "guarded.txt"
    target.write_bytes(b"original")

    events = []

    class FileHandle(SFTPHandle):
        def __init__(self, f):
            super().__init__()
            self.readfile = f
            self.writefile = f

        def chattr(self, attr):
            events.append(("fsetstat",))
            return SFTP_OK

    class FileServer(SFTPServerInterface):
        def open(self, path, flags, attr):
            f = open(str(target), "r+b")
            handle = FileHandle(f)
            handle.allow(HANDLE_READ | HANDLE_FSTAT)
            return handle

        def close(self):
            pass

    server_sock = LoopSocket()
    client_sock = LoopSocket()
    client_sock.link(server_sock)
    server_transport = Transport(server_sock)
    server_transport.add_server_key(
        RSAKey.from_private_key_file(_support("rsa.key"))
    )
    server_transport.set_subsystem_handler("sftp", SFTPServer, FileServer)
    ready = threading.Event()
    server_transport.start_server(ready, RecordingServer())
    ready.wait(1.0)
    client_transport = Transport(client_sock)
    client_transport.connect(username="user", password="pass")
    sftp = SFTP.from_transport(client_transport)
    try:
        handle = open_handle(sftp, "/guarded")
        assert (
            raw_request(sftp, CMD_WRITE, handle, int64(0), b"changed")
            == SFTP_PERMISSION_DENIED
        )
        assert (
            raw_request(sftp, CMD_FSETSTAT, handle, setstat_attr())
            == SFTP_PERMISSION_DENIED
        )
        assert events == []
        assert target.read_bytes() == b"original"
    finally:
        sftp.close()
        client_transport.close()
        server_transport.close()



def test_failing_close_still_removes_handle():
    # a backend close() that raises must not leave the handle registered,
    # or its bytes could regain authorization on a later request
    close_events = []

    class ExplodingHandle(RecordingHandle):
        def close(self):
            close_events.append("closed")
            raise RuntimeError("backend close exploded")

    class ExplodingServer(RecordingSFTPServer):
        def open(self, path, flags, attr):
            self.record("open", path)
            return ExplodingHandle(self, path, flags)

    events = []
    client_transport, server_transport = make_transport(
        events, {}, sftp_si=ExplodingServer
    )
    sftp = SFTP.from_transport(client_transport)
    try:
        t, msg = sftp._request(
            CMD_OPEN, "/boom", SFTP_FLAG_READ, SFTPAttributes()
        )
        wire_handle = msg.get_string()
        assert t == CMD_HANDLE

        # CMD_CLOSE still reports success and detaches the handle even
        # though the underlying close() raised
        assert raw_request(sftp, CMD_CLOSE, wire_handle) == SFTP_OK
        assert (
            raw_request(sftp, CMD_WRITE, wire_handle, int64(0), b"x")
            == SFTP_BAD_MESSAGE
        )
        assert close_events == ["closed"]
    finally:
        sftp.close()
        client_transport.close()
        server_transport.close()


def test_finish_subsystem_closes_all_handles_despite_errors():
    # unit-level: one broken close() must not prevent the others from
    # releasing their underlying objects during session teardown
    import logging

    from paramiko.sftp_server import SFTPServer as _SFTPServer

    closed = []

    class GoodHandle(SFTPHandle):
        def close(self):
            closed.append("good")

    class BadHandle(SFTPHandle):
        def close(self):
            closed.append("bad")
            raise RuntimeError("boom")

    server = _SFTPServer.__new__(_SFTPServer)
    server.file_table = {b"a": BadHandle(), b"b": GoodHandle()}
    server.folder_table = {b"c": GoodHandle()}

    class DummyInner:
        def finish_subsystem(self):
            pass

        def session_ended(self):
            pass

        def close(self):
            pass

        def get_name(self):
            return "test"

    server.server = DummyInner()
    server.logger = logging.getLogger("test-sftp")
    # error logging and SubsystemHandler teardown touch these attributes
    server.sock = DummyInner()
    # SubsystemHandler.finish_subsystem closes the channel via name mangling
    server._SubsystemHandler__channel = DummyInner()

    # must not raise, and every handle must have had close() invoked
    server.finish_subsystem()

    assert sorted(closed) == ["bad", "good", "good"]
    assert server.file_table == {}
    assert server.folder_table == {}
