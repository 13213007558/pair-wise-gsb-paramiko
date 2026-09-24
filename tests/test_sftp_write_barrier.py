"""
Tests for the explicit write-confirmation barrier
(``SFTPFile.wait_for_writes``) used with pipelined writes.

These tests run a local SFTP server that controls the order and outcome
of write responses, so out-of-order responses and mid-stream disk errors
can be exercised deterministically.
"""

import threading

import pytest

from paramiko import (
    RSAKey,
    SFTPClient,
    SFTPServer,
    SSHException,
    Transport,
)
from paramiko.sftp import (
    CMD_WRITE,
    SFTP_BAD_MESSAGE,
    SFTP_FAILURE,
    SFTP_OK,
)
from paramiko.sftp_file import SFTPWriteError

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support


CHUNK = 100


class ControlledSFTPServer(SFTPServer):
    """
    An SFTP server that lets the test control how write requests for one
    target file are answered.

    ``control`` is a dict supporting:

    - ``target_name``: only writes to a file whose name ends with this
      string are intercepted; everything else is handled normally.
    - ``fail_offsets``: offsets whose write is rejected with a
      (simulated) disk error; the data is not written.
    - ``expected_writes``: held responses are released once this many
      writes to the target file have arrived.
    - ``blackhole``: if true, never respond to target writes and drop
      the channel once ``expected_writes`` have arrived.
    - ``sent_order``: list the server appends request numbers to, in the
      order responses were actually sent.
    """

    def __init__(self, channel, name, server, control, *args, **kwargs):
        self.control = control
        self._held = []
        super().__init__(channel, name, server, *args, **kwargs)

    def _is_target(self, handle):
        target = self.control.get("target_name")
        if target is None or handle not in self.file_table:
            return False
        return self.file_table[handle].filename.endswith(target)

    def _process(self, t, request_number, msg):
        if t != CMD_WRITE:
            super()._process(t, request_number, msg)
            return
        handle = msg.get_binary()
        offset = msg.get_int64()
        data = msg.get_binary()
        if handle not in self.file_table:
            self._send_status(
                request_number, SFTP_BAD_MESSAGE, "Invalid handle"
            )
            return
        if not self._is_target(handle):
            self._send_status(
                request_number, self.file_table[handle].write(offset, data)
            )
            return
        if offset in self.control.get("fail_offsets", ()):
            # simulated disk error: the data is not written
            status = SFTP_FAILURE
        else:
            status = self.file_table[handle].write(offset, data)
        self._held.append((request_number, status))
        if len(self._held) < self.control["expected_writes"]:
            return
        held, self._held = self._held, []
        if self.control.get("blackhole"):
            # drop the channel without responding to the held writes
            self.sock.close()
            return
        # respond out of order: successes in reverse request order,
        # failures last of all
        successes = [h for h in held if h[1] == SFTP_OK]
        failures = [h for h in held if h[1] != SFTP_OK]
        ordered = list(reversed(successes)) + failures
        for num, code in ordered:
            self.control.setdefault("sent_order", []).append(num)
            if code == SFTP_OK:
                self._send_status(num, code)
            else:
                self._send_status(num, code, "simulated disk error")


def make_sftp_pair(tmp_path, control):
    """Build a client SFTP connection to a ControlledSFTPServer."""
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)

    class RootedStubSFTPServer(StubSFTPServer):
        ROOT = str(tmp_path)

    event = threading.Event()
    ts.set_subsystem_handler(
        "sftp", ControlledSFTPServer, control, RootedStubSFTPServer
    )
    ts.start_server(event, StubServer())
    # give the server thread a moment to start (as in tests/conftest.py);
    # the event is only set once the client below has negotiated
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    assert event.is_set()
    return tc, ts, SFTPClient.from_transport(tc)


def write_chunks(f, count, size=CHUNK):
    # chunk i is filled with the byte (i + 1), so unwritten gaps (zeros)
    # are distinguishable from written data
    for i in range(count):
        f.write(bytes([i + 1]) * size)


def test_barrier_reports_failed_extents_and_consumes_them(tmp_path):
    control = {
        "target_name": "data.bin",
        "fail_offsets": {2 * CHUNK},
        "expected_writes": 5,
    }
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        f = sftp.open("data.bin", "w")
        f.set_pipelined(True)
        write_chunks(f, 5)
        result = f.wait_for_writes()
        # the middle write was rejected; the rest were confirmed, even
        # though responses arrived out of order
        assert not result.ok
        assert list(result.confirmed) == [
            (0, CHUNK),
            (CHUNK, CHUNK),
            (3 * CHUNK, CHUNK),
            (4 * CHUNK, CHUNK),
        ]
        assert len(result.failed) == 1
        failure = result.failed[0]
        assert failure.offset == 2 * CHUNK
        assert failure.length == CHUNK
        assert isinstance(failure.error, IOError)
        # the server really did respond out of order
        assert control["sent_order"] != sorted(control["sent_order"])
        # asking again: the failure was reported exactly once, and no
        # writes are pending anymore
        again = f.wait_for_writes()
        assert again.ok
        assert again.confirmed == ()
        assert again.failed == ()
        # close must not re-report the already-consumed failure
        f.close()
    finally:
        tc.close()
        ts.close()
    # final file content: every chunk except the failed one landed
    content = (tmp_path / "data.bin").read_bytes()
    assert len(content) == 5 * CHUNK
    for i in (0, 1, 3, 4):
        assert content[i * CHUNK : (i + 1) * CHUNK] == bytes([i + 1]) * CHUNK
    assert content[2 * CHUNK : 3 * CHUNK] == bytes(CHUNK)


def test_barrier_ignores_other_files_and_reads(tmp_path):
    control = {
        "target_name": "a.bin",
        "fail_offsets": {CHUNK},
        "expected_writes": 3,
    }
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        fa = sftp.open("a.bin", "w")
        fa.set_pipelined(True)
        write_chunks(fa, 3)
        # a second file and plain reads on the same connection must keep
        # working while fa has unconfirmed writes in flight
        fb = sftp.open("b.bin", "w")
        fb.write(b"hello")
        fb.close()
        assert sftp.open("b.bin").read() == b"hello"
        assert sftp.stat("a.bin").st_size >= 0
        # fa's barrier still reports exactly fa's own writes
        result = fa.wait_for_writes()
        assert not result.ok
        assert list(result.confirmed) == [(0, CHUNK), (2 * CHUNK, CHUNK)]
        assert [(x.offset, x.length) for x in result.failed] == [
            (CHUNK, CHUNK)
        ]
        fa.close()
    finally:
        tc.close()
        ts.close()
    assert (tmp_path / "b.bin").read_bytes() == b"hello"
    content = (tmp_path / "a.bin").read_bytes()
    assert content[:CHUNK] == bytes([1]) * CHUNK
    assert content[CHUNK : 2 * CHUNK] == bytes(CHUNK)
    assert content[2 * CHUNK :] == bytes([3]) * CHUNK


def test_close_raises_unreported_write_failures(tmp_path):
    control = {
        "target_name": "c.bin",
        "fail_offsets": {CHUNK},
        "expected_writes": 3,
    }
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        f = sftp.open("c.bin", "w")
        f.set_pipelined(True)
        write_chunks(f, 3)
        # without an explicit barrier, close() surfaces the failure,
        # mapped to the original offset and length
        with pytest.raises(SFTPWriteError) as excinfo:
            f.close()
        failures = excinfo.value.failures
        assert [(x.offset, x.length) for x in failures] == [(CHUNK, CHUNK)]
        assert isinstance(failures[0].error, IOError)
        # the failure was reported once; closing again does not raise
        f.close()
    finally:
        tc.close()
        ts.close()


def test_dropped_connection_leaves_unconfirmed_writes_unknown(tmp_path):
    control = {
        "target_name": "d.bin",
        "expected_writes": 3,
        "blackhole": True,
    }
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        f = sftp.open("d.bin", "w")
        f.set_pipelined(True)
        write_chunks(f, 3)
        # the server drops the channel without responding; the barrier
        # cannot know the fate of the writes
        with pytest.raises(SSHException):
            f.wait_for_writes()
        # the unconfirmed writes are neither reported as confirmed nor
        # as failed: their result stays unknown
        assert len(f._pending_writes) == 3
        assert f._write_errors == {}
        # clean up without waiting on the dead channel
        f.pipelined = False
        f._close(async_=True)
    finally:
        tc.close()
        ts.close()


def test_barrier_without_pipelining_is_a_noop(tmp_path):
    control = {"target_name": "e.bin", "expected_writes": 1}
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        f = sftp.open("e.bin", "w")
        f.write(b"xy")
        # non-pipelined writes are confirmed synchronously, so the
        # barrier has nothing left to wait for or report
        result = f.wait_for_writes()
        assert result.ok
        assert result.confirmed == ()
        assert result.failed == ()
        f.close()
    finally:
        tc.close()
        ts.close()
    assert (tmp_path / "e.bin").read_bytes() == b"xy"


def test_barrier_on_closed_file_raises(tmp_path):
    control = {"target_name": "f.bin", "expected_writes": 1}
    tc, ts, sftp = make_sftp_pair(tmp_path, control)
    try:
        f = sftp.open("f.bin", "w")
        f.write(b"xy")
        f.close()
        with pytest.raises(ValueError):
            f.wait_for_writes()
    finally:
        tc.close()
        ts.close()
