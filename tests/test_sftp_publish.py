"""
Tests for .SFTPClient.putfo_atomic (upload-and-publish with atomic replace).

A real loopback SFTP server is used, with knobs to advertise or withhold
the posix-rename@openssh.com / fsync@openssh.com extensions and to inject
failures at the write, fsync, close and rename stages.  While a publish is
underway, a second connection continuously reads the target and must only
ever observe the complete old or the complete new contents.
"""

import os
import threading
from unittest import mock

import pytest

from paramiko import (
    RSAKey,
    SFTP,
    SFTPServer,
    SFTPError,
    Transport,
    PublishStateUnknownError,
)
from paramiko.sftp import SFTP_FAILURE, SFTP_OK
from paramiko.sftp_client import SFTPClient
from paramiko.sftp_si import SFTPServerInterface

from ._loop import LoopSocket
from ._stub_sftp import StubServer, StubSFTPServer, StubSFTPHandle
from ._util import _support


OLD_CONTENT = b"old config, completely valid\n" * 4000
NEW_CONTENT = b"new config, also completely valid\n" * 5000
TARGET = "/config.txt"


def _chunks(data, size=32768):
    return [data[i : i + size] for i in range(0, len(data), size)]


class OneShotStream:
    """A non-seekable, non-replayable byte stream of unknown size."""

    def __init__(self, data):
        self._chunks = _chunks(data)
        self.reads = 0

    def read(self, size=-1):
        self.reads += 1
        if not self._chunks:
            return b""
        return self._chunks.pop(0)


class PublishControl:
    """Shared knobs and recorded state for the stub SFTP server."""

    def __init__(self, root):
        self.root = root
        self.advertise_fsync = True
        self.fail_write_after = None
        self.fail_fsync = False
        self.fail_close = False
        self.rename_mode = "ok"  # or fail / drop_before / drop_after
        self.server_transport = None
        self.events = []


class PublishStubHandle(StubSFTPHandle):
    def write(self, offset, data):
        control = self.control
        if control.fail_write_after is not None:
            self._written = getattr(self, "_written", 0) + len(data)
            if self._written > control.fail_write_after:
                return SFTP_FAILURE
        return super().write(offset, data)

    def fsync(self):
        self.control.events.append("fsync")
        if self.control.fail_fsync:
            return SFTP_FAILURE
        try:
            os.fsync(self.writefile.fileno())
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK

    def close(self):
        self.control.events.append("close")
        if self.control.fail_close:
            raise OSError("injected close failure")
        return super().close()


class PublishStubServer(StubSFTPServer):
    handle_class = PublishStubHandle

    def __init__(self, server, control, *args, **kwargs):
        super().__init__(server)
        self.control = control
        self.ROOT = control.root

    def open(self, path, flags, attr):
        self.control.events.append(("open", path))
        handle = super().open(path, flags, attr)
        if not isinstance(handle, int):
            handle.control = self.control
        return handle

    def posix_rename(self, oldpath, newpath):
        self.control.events.append("rename")
        mode = self.control.rename_mode
        if mode == "fail":
            return SFTP_FAILURE
        if mode == "drop_before":
            # connection dies after the rename request arrived, but before
            # it was carried out
            self.control.server_transport.close()
            return SFTP_OK
        result = super().posix_rename(oldpath, newpath)
        if mode == "drop_after":
            # connection dies after the rename was carried out, but before
            # the client could be told
            self.control.server_transport.close()
        return result


class NoPosixRenameStubServer(PublishStubServer):
    # an interface which does not implement posix-rename, so the server
    # does not advertise the extension
    posix_rename = SFTPServerInterface.posix_rename


class PublishSFTPServer(SFTPServer):
    def _extension_pairs(self):
        pairs = super()._extension_pairs()
        control = getattr(self.server, "control", None)
        if control is not None and control.advertise_fsync:
            pairs += ["fsync@openssh.com", "1"]
        return pairs


class PublishEnv:
    def __init__(
        self, tmp_path, interface=PublishStubServer, advertise_fsync=True
    ):
        self.control = PublishControl(str(tmp_path))
        self.control.advertise_fsync = advertise_fsync
        socks = LoopSocket()
        sockc = LoopSocket()
        sockc.link(socks)
        self.client_transport = Transport(sockc)
        self.server_transport = Transport(socks)
        self.control.server_transport = self.server_transport
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        self.server_transport.add_server_key(host_key)
        event = threading.Event()
        self.server_transport.set_subsystem_handler(
            "sftp", PublishSFTPServer, interface, self.control
        )
        self.server_transport.start_server(event, StubServer())
        event.wait(1.0)
        self.client_transport.connect(
            username="slowdive", password="pygmalion"
        )

    def client(self):
        return SFTP.from_transport(self.client_transport)

    def close(self):
        self.client_transport.close()
        self.server_transport.close()


@pytest.fixture
def make_env(tmp_path):
    envs = []

    def factory(interface=PublishStubServer, advertise_fsync=True):
        env = PublishEnv(tmp_path, interface, advertise_fsync)
        envs.append(env)
        return env

    yield factory
    for env in envs:
        env.close()


@pytest.fixture
def env(make_env):
    return make_env()


@pytest.fixture
def target(tmp_path):
    (tmp_path / "config.txt").write_bytes(OLD_CONTENT)
    return TARGET


class ContinuousReader:
    """
    Reads the publish target over a second connection in a loop, recording
    every complete contents observed along the way.
    """

    def __init__(self, sftp, path):
        self.sftp = sftp
        self.path = path
        self.reads = []
        self.errors = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run)

    def read_once(self):
        with self.sftp.open(self.path, "r") as f:
            return f.read()

    def __enter__(self):
        # synchronously observe the pre-publish contents first
        self.reads.append(self.read_once())
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        self._thread.join()
        return False

    def _run(self):
        while not self._stop.is_set():
            try:
                self.reads.append(self.read_once())
            except Exception as e:
                self.errors.append(e)
                return


def tempfiles(tmp_path):
    return [p for p in tmp_path.iterdir() if ".tmp-" in p.name]


class TestPutfoAtomic:
    def test_atomic_replace(self, env, target, tmp_path):
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            size = writer.putfo_atomic(OneShotStream(NEW_CONTENT), target)
            assert size == len(NEW_CONTENT)
        assert reader.errors == []
        # readers only ever saw the complete old or complete new contents
        assert set(reader.reads) <= {OLD_CONTENT, NEW_CONTENT}
        assert reader.read_once() == NEW_CONTENT
        assert tempfiles(tmp_path) == []
        # the default mode does not fsync
        assert "fsync" not in env.control.events
        # the staged tempfile lived in the target's own folder
        staged = [
            event[1]
            for event in env.control.events
            if isinstance(event, tuple)
            and event[0] == "open"
            and event[1] != target
        ]
        assert len(staged) == 1
        assert staged[0].startswith("/.config.txt.tmp-")

    def test_fsync_then_replace(self, env, target, tmp_path):
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            writer.putfo_atomic(OneShotStream(NEW_CONTENT), target, fsync=True)
        assert reader.errors == []
        assert set(reader.reads) <= {OLD_CONTENT, NEW_CONTENT}
        assert reader.read_once() == NEW_CONTENT
        assert tempfiles(tmp_path) == []
        events = env.control.events
        # contents were persisted before the replace happened
        assert "fsync" in events
        assert events.index("fsync") < events.index("rename")

    def test_missing_posix_rename_extension(
        self, make_env, target, tmp_path
    ):
        env = make_env(interface=NoPosixRenameStubServer)
        stream = OneShotStream(NEW_CONTENT)
        with pytest.raises(SFTPError):
            env.client().putfo_atomic(stream, target)
        # the non-replayable stream was never consumed...
        assert stream.reads == 0
        # ...and no non-atomic delete+rename fallback was attempted
        assert (tmp_path / "config.txt").read_bytes() == OLD_CONTENT
        assert tempfiles(tmp_path) == []

    def test_missing_fsync_extension(self, make_env, target, tmp_path):
        env = make_env(advertise_fsync=False)
        stream = OneShotStream(NEW_CONTENT)
        with pytest.raises(SFTPError):
            env.client().putfo_atomic(stream, target, fsync=True)
        assert stream.reads == 0
        assert (tmp_path / "config.txt").read_bytes() == OLD_CONTENT
        assert tempfiles(tmp_path) == []

    def test_write_failure(self, env, target, tmp_path):
        env.control.fail_write_after = 10000
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            with pytest.raises(IOError):
                writer.putfo_atomic(OneShotStream(NEW_CONTENT), target)
        assert reader.errors == []
        assert set(reader.reads) == {OLD_CONTENT}
        assert reader.read_once() == OLD_CONTENT
        assert tempfiles(tmp_path) == []

    def test_close_failure(self, env, target, tmp_path):
        env.control.fail_close = True
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            with pytest.raises(IOError):
                writer.putfo_atomic(OneShotStream(NEW_CONTENT), target)
        assert reader.errors == []
        assert set(reader.reads) == {OLD_CONTENT}
        assert reader.read_once() == OLD_CONTENT
        assert tempfiles(tmp_path) == []

    def test_fsync_failure(self, env, target, tmp_path):
        env.control.fail_fsync = True
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            with pytest.raises(IOError):
                writer.putfo_atomic(
                    OneShotStream(NEW_CONTENT), target, fsync=True
                )
        assert reader.errors == []
        assert set(reader.reads) == {OLD_CONTENT}
        assert reader.read_once() == OLD_CONTENT
        assert tempfiles(tmp_path) == []
        events = env.control.events
        assert "fsync" in events
        assert "rename" not in events

    def test_rename_failure(self, env, target, tmp_path):
        env.control.rename_mode = "fail"
        writer = env.client()
        with ContinuousReader(env.client(), target) as reader:
            with pytest.raises(IOError):
                writer.putfo_atomic(OneShotStream(NEW_CONTENT), target)
        assert reader.errors == []
        assert set(reader.reads) == {OLD_CONTENT}
        assert reader.read_once() == OLD_CONTENT
        assert tempfiles(tmp_path) == []
        assert "rename" in env.control.events

    def test_drop_after_rename_publish_unknown(self, env, target, tmp_path):
        env.control.rename_mode = "drop_after"
        with pytest.raises(PublishStateUnknownError):
            env.client().putfo_atomic(OneShotStream(NEW_CONTENT), target)
        # the rename actually happened server-side...
        assert (tmp_path / "config.txt").read_bytes() == NEW_CONTENT
        # ...and the client neither retried it nor deleted anything
        assert env.control.events.count("rename") == 1
        assert tempfiles(tmp_path) == []

    def test_drop_before_rename_publish_unknown(self, env, target, tmp_path):
        env.control.rename_mode = "drop_before"
        with pytest.raises(PublishStateUnknownError):
            env.client().putfo_atomic(OneShotStream(NEW_CONTENT), target)
        # the rename never happened, and the client must not have touched
        # anything after the drop: target intact, staged tempfile left
        # behind for the caller to sort out
        assert (tmp_path / "config.txt").read_bytes() == OLD_CONTENT
        assert env.control.events.count("rename") == 1
        left_behind = tempfiles(tmp_path)
        assert len(left_behind) == 1
        assert left_behind[0].read_bytes() == NEW_CONTENT

    def test_callback_exception_aborts_upload(self, env, target, tmp_path):
        calls = []

        def callback(done, total):
            calls.append((done, total))
            if len(calls) == 2:
                raise RuntimeError("boom")

        with pytest.raises(RuntimeError, match="boom"):
            env.client().putfo_atomic(
                OneShotStream(NEW_CONTENT), target, callback=callback
            )
        # a callback exception is an upload-stage failure: old target
        # intact, staged tempfile cleaned up
        assert (tmp_path / "config.txt").read_bytes() == OLD_CONTENT
        assert tempfiles(tmp_path) == []
        # the total size is reported as unknown (0)
        assert all(total == 0 for _, total in calls)

    def test_tempfile_collision_uses_exclusive_create(
        self, env, target, tmp_path
    ):
        decoy = tmp_path / ".config.txt.tmp-aaaaaaaa"
        decoy.write_bytes(b"decoy")
        names = ["/.config.txt.tmp-aaaaaaaa", "/.config.txt.tmp-bbbbbbbb"]
        with mock.patch.object(
            SFTPClient, "_staging_tempname", side_effect=names
        ):
            env.client().putfo_atomic(OneShotStream(NEW_CONTENT), target)
        # the decoy was not clobbered (exclusive create), the publish
        # retried with a fresh name and went through
        assert decoy.read_bytes() == b"decoy"
        assert (tmp_path / "config.txt").read_bytes() == NEW_CONTENT
        # only the pre-existing decoy remains; our own tempfile is gone
        assert tempfiles(tmp_path) == [decoy]
