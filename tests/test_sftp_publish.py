"""
Tests for SFTPClient.putfo_atomic (upload-and-publish) semantics.

These tests run against an in-memory loopback SFTP server with hooks for
injecting failures at each stage of a publish (write, fsync, close,
rename), while a second connection continuously reads the publish target
to verify that readers only ever observe the complete old or the complete
new contents of the file.
"""

import os
import shutil
import threading
import time
from io import BytesIO
from types import SimpleNamespace

import pytest

from paramiko import RSAKey, SFTP, SFTPServer, Transport
from paramiko.sftp import SFTPError, SFTP_FAILURE
from paramiko.sftp_client import PublishStateUnknownError

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPHandle, StubSFTPServer
from ._util import _support, slow


OLD_CONTENT = b"# old config\noption = 1\n" * 64
NEW_CONTENT = b"# new config\noption = 2\nextra = 3\n" * 64

# notable server-side events, in order, for ordering assertions
EVENTS = []


class FaultyStubSFTPHandle(StubSFTPHandle):
    """
    Stub handle with class-level fault-injection switches for the write,
    fsync and close stages of a publish.
    """

    fail_writes = False
    fail_close = False
    fail_fsync = False
    fsyncs = 0

    @classmethod
    def reset(cls):
        cls.fail_writes = False
        cls.fail_close = False
        cls.fail_fsync = False
        cls.fsyncs = 0

    def write(self, offset, data):
        if type(self).fail_writes:
            return SFTP_FAILURE
        return super().write(offset, data)

    def close(self):
        if type(self).fail_close:
            return SFTP_FAILURE
        return super().close()

    def fsync(self):
        type(self).fsyncs += 1
        EVENTS.append("fsync")
        if type(self).fail_fsync:
            return SFTP_FAILURE
        return super().fsync()


class FaultyStubSFTPServer(StubSFTPServer):
    """
    Stub server with fault-injection hooks for the rename (publish) stage.
    """

    HANDLE_CLASS = FaultyStubSFTPHandle
    fail_posix_rename = False
    posix_renames = 0
    # optional callable(server, oldpath, newpath) -> sftp status, used to
    # simulate e.g. a server crash after the rename request arrives
    on_posix_rename = None

    @classmethod
    def reset(cls):
        cls.fail_posix_rename = False
        cls.posix_renames = 0
        cls.on_posix_rename = None

    def posix_rename(self, oldpath, newpath):
        type(self).posix_renames += 1
        EVENTS.append("rename")
        hook = type(self).on_posix_rename
        if hook is not None:
            return hook(self, oldpath, newpath)
        if type(self).fail_posix_rename:
            return SFTP_FAILURE
        return super().posix_rename(oldpath, newpath)


class NonReplayableStream:
    """
    A minimal read-only stream (no seek/tell) that tracks how much of it
    was consumed, to prove that publishes work with unknown sizes and that
    capability failures do not consume the input.
    """

    def __init__(self, data):
        self._bio = BytesIO(data)
        self.bytes_read = 0

    def read(self, size=-1):
        data = self._bio.read(size)
        self.bytes_read += len(data)
        return data


class ContinuousReader:
    """
    Read the publish target in a loop over a second SFTP connection,
    recording every read whose content is not in the allowed set.
    """

    def __init__(self, transport, path, allowed):
        self.sftp = SFTP.from_transport(transport)
        self.path = path
        self.allowed = allowed
        self.bad_reads = []
        self.reads = 0
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def __enter__(self):
        # one synchronous read so 'reads' is guaranteed nonzero
        self._read_once()
        self._thread.start()
        return self

    def __exit__(self, *exc_info):
        self._stop.set()
        self._thread.join(5)
        self.sftp.close()

    def _read_once(self):
        try:
            with self.sftp.open(self.path, "r") as f:
                data = f.read()
        except Exception:
            # e.g. the connection going away during teardown
            return
        self.reads += 1
        if data not in self.allowed:
            self.bad_reads.append(data)

    def _run(self):
        while not self._stop.is_set():
            self._read_once()
            time.sleep(0.001)


@pytest.fixture
def publish_loop():
    """
    An in-memory SFTP server with fault-injection hooks, plus a connected
    client Transport.  Yields a namespace with both transports.
    """
    FaultyStubSFTPHandle.reset()
    FaultyStubSFTPServer.reset()
    del EVENTS[:]
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    host_key = RSAKey.from_private_key_file(_support("rsa.key"))
    ts.add_server_key(host_key)
    event = threading.Event()
    ts.set_subsystem_handler("sftp", SFTPServer, FaultyStubSFTPServer)
    ts.start_server(event, StubServer())
    event.wait(1.0)
    tc.connect(username="slowdive", password="pygmalion")
    yield SimpleNamespace(client_transport=tc, server_transport=ts)
    tc.close()
    ts.close()


@pytest.fixture
def sftp(publish_loop):
    client = SFTP.from_transport(publish_loop.client_transport)
    client.FOLDER = "paramiko-publish-test-target"
    shutil.rmtree(client.FOLDER, ignore_errors=True)
    os.mkdir(client.FOLDER)
    yield client
    shutil.rmtree(client.FOLDER, ignore_errors=True)


def target_path(sftp, name="config.txt"):
    return sftp.FOLDER + "/" + name


def write_target(sftp, content=OLD_CONTENT):
    with sftp.open(target_path(sftp), "w") as f:
        f.write(content)


def read_target(sftp):
    with sftp.open(target_path(sftp), "r") as f:
        return f.read()


def temp_files(sftp):
    return [
        f
        for f in os.listdir(sftp.FOLDER)
        if f.startswith(".") and f.endswith(".tmp")
    ]


@slow
class TestPutfoAtomic:
    def test_server_extensions_are_recorded(self, sftp):
        assert sftp.server_extensions["posix-rename@openssh.com"] == b"1"
        assert sftp.server_extensions["fsync@openssh.com"] == b"1"

    @pytest.mark.parametrize("fsync", [False, True], ids=["plain", "fsync"])
    def test_publish_replaces_target_atomically(
        self, sftp, publish_loop, fsync
    ):
        write_target(sftp)
        with ContinuousReader(
            publish_loop.client_transport,
            target_path(sftp),
            {OLD_CONTENT, NEW_CONTENT},
        ) as reader:
            size = sftp.putfo_atomic(
                NonReplayableStream(NEW_CONTENT),
                target_path(sftp),
                fsync=fsync,
            )
        assert size == len(NEW_CONTENT)
        assert read_target(sftp) == NEW_CONTENT
        # readers only ever saw the complete old or new contents
        assert reader.reads > 0
        assert reader.bad_reads == []
        # the temp file was renamed, not left behind
        assert temp_files(sftp) == []
        if fsync:
            assert FaultyStubSFTPHandle.fsyncs == 1
            # the fsync happened before the rename
            assert EVENTS == ["fsync", "rename"]
        else:
            assert FaultyStubSFTPHandle.fsyncs == 0

    def test_publish_into_subdirectory(self, sftp):
        sftp.mkdir(sftp.FOLDER + "/sub")
        target = sftp.FOLDER + "/sub/config.txt"
        size = sftp.putfo_atomic(NonReplayableStream(NEW_CONTENT), target)
        assert size == len(NEW_CONTENT)
        with sftp.open(target, "r") as f:
            assert f.read() == NEW_CONTENT
        # the temp file lived (and was cleaned up) next to the target
        assert os.listdir(sftp.FOLDER + "/sub") == ["config.txt"]

    def test_callback_reports_progress_with_zero_total(self, sftp):
        calls = []
        sftp.putfo_atomic(
            NonReplayableStream(NEW_CONTENT),
            target_path(sftp),
            callback=lambda sofar, total: calls.append((sofar, total)),
        )
        assert len(calls) > 0
        # the size of a stream is unknown, so the total is always 0
        assert all(total == 0 for _, total in calls)
        assert calls[-1][0] == len(NEW_CONTENT)

    def test_callback_exception_aborts_like_upload_failure(
        self, sftp, publish_loop
    ):
        write_target(sftp)

        def boom(sofar, total):
            raise RuntimeError("callback exploded")

        with ContinuousReader(
            publish_loop.client_transport, target_path(sftp), {OLD_CONTENT}
        ) as reader:
            with pytest.raises(RuntimeError, match="callback exploded"):
                sftp.putfo_atomic(
                    NonReplayableStream(NEW_CONTENT),
                    target_path(sftp),
                    callback=boom,
                )
        # treated as an upload-phase failure: old target intact, temp removed
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []
        assert FaultyStubSFTPServer.posix_renames == 0
        assert reader.bad_reads == []

    def test_missing_posix_rename_extension_rejected_before_consuming_stream(
        self, sftp
    ):
        write_target(sftp)
        del sftp.server_extensions["posix-rename@openssh.com"]
        stream = NonReplayableStream(NEW_CONTENT)
        with pytest.raises(SFTPError, match="posix-rename"):
            sftp.putfo_atomic(stream, target_path(sftp))
        # the non-replayable input stream was not consumed
        assert stream.bytes_read == 0
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []

    def test_missing_fsync_extension_rejected_before_consuming_stream(
        self, sftp
    ):
        write_target(sftp)
        del sftp.server_extensions["fsync@openssh.com"]
        stream = NonReplayableStream(NEW_CONTENT)
        with pytest.raises(SFTPError, match="fsync"):
            sftp.putfo_atomic(stream, target_path(sftp), fsync=True)
        assert stream.bytes_read == 0
        assert read_target(sftp) == OLD_CONTENT
        # the plain mode does not need the fsync extension
        size = sftp.putfo_atomic(
            NonReplayableStream(NEW_CONTENT), target_path(sftp)
        )
        assert size == len(NEW_CONTENT)
        assert read_target(sftp) == NEW_CONTENT

    def test_write_failure_keeps_old_target(self, sftp, publish_loop):
        write_target(sftp)
        FaultyStubSFTPHandle.fail_writes = True
        with ContinuousReader(
            publish_loop.client_transport, target_path(sftp), {OLD_CONTENT}
        ) as reader:
            with pytest.raises(IOError):
                sftp.putfo_atomic(
                    NonReplayableStream(NEW_CONTENT), target_path(sftp)
                )
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []
        assert FaultyStubSFTPServer.posix_renames == 0
        assert reader.bad_reads == []

    def test_close_failure_keeps_old_target(self, sftp, publish_loop):
        write_target(sftp)
        FaultyStubSFTPHandle.fail_close = True
        with ContinuousReader(
            publish_loop.client_transport, target_path(sftp), {OLD_CONTENT}
        ) as reader:
            with pytest.raises(IOError):
                sftp.putfo_atomic(
                    NonReplayableStream(NEW_CONTENT), target_path(sftp)
                )
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []
        assert FaultyStubSFTPServer.posix_renames == 0
        assert reader.bad_reads == []

    def test_fsync_failure_keeps_old_target(self, sftp, publish_loop):
        write_target(sftp)
        FaultyStubSFTPHandle.fail_fsync = True
        with ContinuousReader(
            publish_loop.client_transport, target_path(sftp), {OLD_CONTENT}
        ) as reader:
            with pytest.raises(IOError):
                sftp.putfo_atomic(
                    NonReplayableStream(NEW_CONTENT),
                    target_path(sftp),
                    fsync=True,
                )
        # the fsync was attempted, but the publish never happened
        assert FaultyStubSFTPHandle.fsyncs == 1
        assert EVENTS == ["fsync"]
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []
        assert FaultyStubSFTPServer.posix_renames == 0
        assert reader.bad_reads == []

    def test_rename_failure_keeps_old_target(self, sftp, publish_loop):
        write_target(sftp)
        FaultyStubSFTPServer.fail_posix_rename = True
        with ContinuousReader(
            publish_loop.client_transport, target_path(sftp), {OLD_CONTENT}
        ) as reader:
            with pytest.raises(IOError):
                sftp.putfo_atomic(
                    NonReplayableStream(NEW_CONTENT), target_path(sftp)
                )
        # the rename was attempted exactly once and definitively refused
        assert FaultyStubSFTPServer.posix_renames == 1
        assert read_target(sftp) == OLD_CONTENT
        assert temp_files(sftp) == []
        assert reader.bad_reads == []

    def test_connection_drop_after_rename_is_unknown_state(
        self, sftp, publish_loop
    ):
        write_target(sftp)

        def crash_after_rename(server, oldpath, newpath):
            status = StubSFTPServer.posix_rename(server, oldpath, newpath)
            # simulate a server crash before the response could be sent
            publish_loop.server_transport.close()
            return status

        FaultyStubSFTPServer.on_posix_rename = crash_after_rename
        with pytest.raises(PublishStateUnknownError):
            sftp.putfo_atomic(
                NonReplayableStream(NEW_CONTENT), target_path(sftp)
            )
        # the publish was not retried
        assert FaultyStubSFTPServer.posix_renames == 1
        # the target was not deleted; here the rename did happen, but the
        # client could not know that (read the file locally, as the
        # connection is gone)
        with open(target_path(sftp), "rb") as f:
            assert f.read() == NEW_CONTENT

    def test_connection_drop_before_rename_effect_is_unknown_state(
        self, sftp, publish_loop
    ):
        write_target(sftp)

        def crash_before_rename(server, oldpath, newpath):
            # simulate a server crash before performing the rename
            publish_loop.server_transport.close()
            return SFTP_FAILURE  # never delivered

        FaultyStubSFTPServer.on_posix_rename = crash_before_rename
        with pytest.raises(PublishStateUnknownError):
            sftp.putfo_atomic(
                NonReplayableStream(NEW_CONTENT), target_path(sftp)
            )
        assert FaultyStubSFTPServer.posix_renames == 1
        # the old target is still intact (read locally; connection is gone)
        with open(target_path(sftp), "rb") as f:
            assert f.read() == OLD_CONTENT
        # and the client did not try to clean up or delete anything over
        # the dead connection
        assert len(temp_files(sftp)) == 1
