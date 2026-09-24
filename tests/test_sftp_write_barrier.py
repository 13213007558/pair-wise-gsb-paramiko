"""
Tests for `.SFTPFile.confirm_writes`, the explicit confirmation barrier
for pipelined writes.

These tests use a loopback SFTP server that applies writes immediately but
holds back the write *responses*, so a test can release them in any order
and inject error statuses for chosen requests.
"""

import os
import shutil
import threading
import time

import pytest

from paramiko import (
    RSAKey,
    SFTP,
    SFTP_FAILURE,
    SFTPServer,
    Transport,
)
from paramiko.sftp import CMD_WRITE, SFTP_BAD_MESSAGE
from paramiko.ssh_exception import SSHException

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer
from ._util import _support


class HeldWrites:
    """
    Shared state between the test thread and the SFTP server thread.

    The server calls `hold` for every write request instead of responding
    right away; the test then releases the held responses in any order.
    """

    def __init__(self):
        self._cond = threading.Condition()
        self.held = []  # list of (request_number, status)
        self.server = None

    def hold(self, server, request_number, status):
        with self._cond:
            self.server = server
            self.held.append((request_number, status))
            self._cond.notify_all()

    def wait_for(self, count, timeout=10.0):
        deadline = time.time() + timeout
        with self._cond:
            while len(self.held) < count:
                remaining = deadline - time.time()
                assert remaining > 0, "server did not receive writes"
                self._cond.wait(remaining)

    def release(self, index, code=None, text=None):
        with self._cond:
            request_number, status = self.held.pop(index)
            server = self.server
        if code is None:
            server._send_status(request_number, status)
        else:
            server._send_status(request_number, code, text)


class ReorderingSFTPServer(SFTPServer):
    """
    An SFTP server that applies writes to disk immediately but does not
    answer them until the test explicitly releases the response.
    """

    def _process(self, t, request_number, msg):
        if t == CMD_WRITE:
            handle = msg.get_binary()
            offset = msg.get_int64()
            data = msg.get_binary()
            if handle not in self.file_table:
                self._send_status(
                    request_number, SFTP_BAD_MESSAGE, "Invalid handle"
                )
                return
            status = self.file_table[handle].write(offset, data)
            self.server.control.hold(self, request_number, status)
            return
        super()._process(t, request_number, msg)


class ControlledSFTPServer(StubSFTPServer):
    def __init__(self, server, control, *args, **kwargs):
        super().__init__(server, *args, **kwargs)
        self.control = control


@pytest.fixture
def barrier_sftp():
    """
    Yield an (SFTP client, HeldWrites control, server Transport) tuple
    connected to a ReorderingSFTPServer over a loopback socket.
    """
    control = HeldWrites()
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler(
        "sftp", ReorderingSFTPServer, ControlledSFTPServer, control
    )
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    client = SFTP.from_transport(tc)
    folder = "barrier-test-target"
    shutil.rmtree(folder, ignore_errors=True)
    os.mkdir(folder)
    client.FOLDER = folder
    yield client, control, ts
    client.close()
    tc.close()
    ts.close()
    shutil.rmtree(folder, ignore_errors=True)


def test_confirm_writes_reports_failed_ranges(barrier_sftp):
    sftp, control, ts = barrier_sftp
    path = sftp.FOLDER + "/barrier.bin"
    f = sftp.open(path, "w")
    f.set_pipelined(True)
    chunks = [b"A" * 100, b"B" * 100, b"C" * 100]
    for chunk in chunks:
        f.write(chunk)
        f.flush()
    control.wait_for(3)

    # other requests on the same connection are not blocked by the
    # unconfirmed writes
    sftp.stat(sftp.FOLDER)

    # a second file on the same connection, whose response will arrive in
    # the middle of the first file's barrier
    f2 = sftp.open(sftp.FOLDER + "/other.bin", "w")
    f2.set_pipelined(True)
    f2.write(b"X" * 10)
    f2.flush()
    control.wait_for(4)

    # release the held responses out of order; the middle write of the
    # first file fails with a (scripted) disk error
    control.release(2)  # third chunk -> OK
    control.release(2)  # second file's write -> OK
    control.release(0)  # first chunk -> OK
    control.release(0, SFTP_FAILURE, "simulated disk error")  # middle

    failures = f.confirm_writes()
    assert len(failures) == 1
    offset, length, error = failures[0]
    assert (offset, length) == (100, 100)
    assert isinstance(error, IOError)
    assert "simulated disk error" in str(error)

    # the second file's response was dispatched to it, not consumed by
    # the first file's barrier
    assert f2.confirm_writes() == []

    # the server applied every chunk, so the final content is complete
    with sftp.open(path) as readback:
        assert readback.read() == b"".join(chunks)

    # failures are reported exactly once
    assert f.confirm_writes() == []

    f.close()
    f2.close()


def test_confirm_writes_all_ok(barrier_sftp):
    sftp, control, ts = barrier_sftp
    f = sftp.open(sftp.FOLDER + "/ok.bin", "w")
    f.set_pipelined(True)
    f.write(b"hello")
    f.write(b"world")
    control.wait_for(2)  # confirm_writes() flushes the buffer itself
    control.release(1)
    control.release(0)
    assert f.confirm_writes() == []
    f.close()
    with sftp.open(sftp.FOLDER + "/ok.bin") as readback:
        assert readback.read() == b"helloworld"


def test_confirm_writes_connection_drop_leaves_result_unknown(barrier_sftp):
    sftp, control, ts = barrier_sftp
    f = sftp.open(sftp.FOLDER + "/drop.bin", "w")
    f.set_pipelined(True)
    f.write(b"Z" * 50)
    f.flush()
    control.wait_for(1)

    # sever the connection without answering the write
    ts.close()

    # the barrier neither reports success nor claims the server rejected
    # the write: it raises, and the write stays unconfirmed
    with pytest.raises(SSHException):
        f.confirm_writes()
    assert len(f._pending_writes) == 1

    # closing the file afterwards must not blow up either
    f.close()
    assert f._closed
