"""
Tests for the client side of OpenSSH's host key rotation extensions
(hostkeys-00@openssh.com / hostkeys-prove-00@openssh.com).
"""

import threading
import time

from paramiko import (
    ECDSAKey,
    Ed25519Key,
    Message,
    RSAKey,
    SSHClient,
    Transport,
)
from paramiko.common import (
    cMSG_GLOBAL_REQUEST,
    cMSG_REQUEST_FAILURE,
    cMSG_REQUEST_SUCCESS,
)

from ._loop import LoopSocket
from ._util import TestServer, _support, server


def _load_rotated_keys():
    return [
        Ed25519Key.from_private_key_file(_support("ed25519.key")),
        ECDSAKey.from_private_key_file(_support("ecdsa-256.key")),
        # NOTE: generated, as the fixture RSA keys on disk are all copies of
        # the server's current host key.
        RSAKey.generate(1024),
    ]


class RotatingHostKeyServer(Transport):
    """
    Scripted server-mode peer speaking the host key rotation protocol.

    Offers are triggered manually via `send_host_key_offer`; proof requests
    are recorded in ``prove_requests`` and answered per the ``bad_session``
    and ``unproven`` blob sets (simulating misbehaving peers).
    """

    def __init__(
        self, sock, signing_keys, bad_session=(), unproven=(), **kwargs
    ):
        super().__init__(sock, **kwargs)
        self._signing_keys = {key.asbytes(): key for key in signing_keys}
        self._bad_session = set(bad_session)
        self._unproven = set(unproven)
        self.prove_requests = []

    def send_host_key_offer(self, blobs):
        m = Message()
        m.add_byte(cMSG_GLOBAL_REQUEST)
        m.add_string("hostkeys-00@openssh.com")
        m.add_boolean(False)
        for blob in blobs:
            m.add_string(blob)
        self._send_user_message(m)

    def _parse_global_request(self, m):
        kind = m.get_text()
        want_reply = m.get_boolean()
        if kind == "hostkeys-prove-00@openssh.com":
            blobs = []
            while m.get_remainder():
                blobs.append(m.get_string())
            self.prove_requests.append(blobs)
            response = Message()
            response.add_byte(cMSG_REQUEST_SUCCESS)
            for blob in blobs:
                if blob in self._unproven:
                    # Peer "forgets" to prove this key.
                    continue
                session_id = self.session_id
                if blob in self._bad_session:
                    # Peer signs with the wrong session identifier.
                    session_id = b"some-other-session-id"
                data = Message()
                data.add_string("hostkeys-prove-00@openssh.com")
                data.add_string(session_id)
                data.add_string(blob)
                key = self._signing_keys[blob]
                algorithm = (
                    "rsa-sha2-512" if isinstance(key, RSAKey) else None
                )
                sig = key.sign_ssh_data(
                    data.asbytes(), algorithm=algorithm
                )
                response.add_string(sig.asbytes())
            self._send_message(response)
        elif want_reply:
            response = Message()
            response.add_byte(cMSG_REQUEST_FAILURE)
            self._send_message(response)


def _server_factory(signing_keys, **kwargs):
    def factory(sock, **init):
        return RotatingHostKeyServer(
            sock, signing_keys, **dict(kwargs, **init)
        )

    return factory


class UpdateRecorder:
    def __init__(self):
        self.updates = []
        self.event = threading.Event()

    def __call__(self, keys):
        self.updates.append(keys)
        self.event.set()


class TestHostKeyUpdate:
    def setup_method(self):
        self._contexts = []

    def teardown_method(self):
        for context in self._contexts:
            context.__exit__(None, None, None)

    def _connect(self, recorder, **server_kwargs):
        rotated = _load_rotated_keys()
        context = server(
            client_init=dict(update_host_keys=True),
            server_transport_factory=_server_factory(
                rotated, **server_kwargs
            ),
        )
        tc, ts = context.__enter__()
        self._contexts.append(context)
        tc.mark_host_key_trusted()
        tc.set_host_key_update_handler(recorder)
        return tc, ts, rotated

    def test_advertises_support_in_ext_info(self):
        recorder = UpdateRecorder()
        tc, ts, _ = self._connect(recorder)
        assert ts.server_extensions == {"hostkeys-00@openssh.com": b""}

    def test_no_advertisement_when_disabled(self):
        rotated = _load_rotated_keys()
        with server(
            server_transport_factory=_server_factory(rotated)
        ) as (tc, ts):
            assert "hostkeys-00@openssh.com" not in ts.server_extensions

    def test_verified_update_set_filters_dupes_current_and_garbage(self):
        recorder = UpdateRecorder()
        tc, ts, rotated = self._connect(recorder)
        ed25519, ecdsa, lonely = [key.asbytes() for key in rotated]
        current = tc.get_remote_server_key().asbytes()
        garbage = Message().add_string("ssh-bogus").asbytes()
        # Out-of-order offer containing a duplicate, the current host key,
        # and an unparsable blob.
        ts.send_host_key_offer(
            [ecdsa, ed25519, current, ecdsa, garbage, lonely]
        )
        assert recorder.event.wait(5)
        expected = [ecdsa, ed25519, lonely]
        # The entire candidate set is proved in one request, in offer order,
        # with duplicates/current-key/garbage filtered out.
        assert ts.prove_requests == [expected]
        # Handler notified exactly once with the fully verified set.
        assert len(recorder.updates) == 1
        assert [key.asbytes() for key in recorder.updates[0]] == expected
        assert [
            key.asbytes() for key in tc.get_host_keys_update()
        ] == expected

    def test_wrong_session_signature_is_rejected(self):
        recorder = UpdateRecorder()
        rotated = _load_rotated_keys()
        bad = rotated[1].asbytes()
        tc, ts, rotated = self._connect(recorder, bad_session={bad})
        good = rotated[0].asbytes()
        ts.send_host_key_offer([good, bad])
        assert recorder.event.wait(5)
        # Both keys were asked about, but only the correctly-bound proof
        # makes it into the update set.
        assert ts.prove_requests == [[good, bad]]
        assert [key.asbytes() for key in recorder.updates[0]] == [good]

    def test_missing_proof_is_rejected(self):
        recorder = UpdateRecorder()
        rotated = _load_rotated_keys()
        skipped = rotated[1].asbytes()
        tc, ts, rotated = self._connect(recorder, unproven={skipped})
        proven = rotated[0].asbytes()
        ts.send_host_key_offer([proven, skipped])
        assert recorder.event.wait(5)
        assert [key.asbytes() for key in recorder.updates[0]] == [proven]

    def test_offer_ignored_until_host_key_trusted(self):
        recorder = UpdateRecorder()
        rotated = _load_rotated_keys()
        with server(
            client_init=dict(update_host_keys=True),
            server_transport_factory=_server_factory(rotated),
        ) as (tc, ts):
            tc.set_host_key_update_handler(recorder)
            ts.send_host_key_offer([key.asbytes() for key in rotated])
            # Give the client a moment to (not) process the offer.
            assert not recorder.event.wait(0.5)
            assert ts.prove_requests == []
            assert tc.get_host_keys_update() is None

    def test_offer_ignored_when_update_host_keys_disabled(self):
        recorder = UpdateRecorder()
        rotated = _load_rotated_keys()
        with server(
            server_transport_factory=_server_factory(rotated)
        ) as (tc, ts):
            tc.mark_host_key_trusted()
            tc.set_host_key_update_handler(recorder)
            ts.send_host_key_offer([key.asbytes() for key in rotated])
            assert not recorder.event.wait(0.5)
            assert ts.prove_requests == []
            assert tc.get_host_keys_update() is None

    def test_only_one_offer_processed_per_connection(self):
        recorder = UpdateRecorder()
        tc, ts, rotated = self._connect(recorder)
        first, second = [key.asbytes() for key in rotated[:2]]
        ts.send_host_key_offer([first])
        assert recorder.event.wait(5)
        ts.send_host_key_offer([second])
        # Give the second offer a chance to (not) be processed.
        time.sleep(0.5)
        assert len(recorder.updates) == 1
        assert ts.prove_requests == [[first]]
        assert [key.asbytes() for key in recorder.updates[0]] == [first]

    def test_reconnect_requires_fresh_proof(self):
        # First connection learns the key.
        recorder = UpdateRecorder()
        tc, ts, rotated = self._connect(recorder)
        blob = rotated[0].asbytes()
        ts.send_host_key_offer([blob])
        assert recorder.event.wait(5)
        assert ts.prove_requests == [[blob]]
        # A brand new connection must prove the same key all over again;
        # the previous connection's proof result cannot be reused.
        recorder2 = UpdateRecorder()
        tc2, ts2, _ = self._connect(recorder2)
        ts2.send_host_key_offer([blob])
        assert recorder2.event.wait(5)
        assert ts2.prove_requests == [[blob]]
        assert [key.asbytes() for key in recorder2.updates[0]] == [blob]


class TestSSHClientHostKeyUpdate:
    def test_verified_keys_persisted_without_pruning(self, tmp_path):
        host_key = RSAKey.from_private_key_file(_support("rsa.key"))
        rotated = _load_rotated_keys()
        # known_hosts: the server's current key plus an unrelated host.
        known_hosts = tmp_path / "known_hosts"
        known_hosts.write_text(
            "rotated.example.com ssh-rsa {}\n".format(host_key.get_base64())
            + "other.example.com ssh-rsa {}\n".format(
                rotated[2].get_base64()
            )
        )
        socks, sockc = LoopSocket(), LoopSocket()
        sockc.link(socks)
        ts = RotatingHostKeyServer(socks, rotated)
        ts.add_server_key(host_key)
        event = threading.Event()
        ts.start_server(event, TestServer())
        client = SSHClient()
        client.load_host_keys(str(known_hosts))
        try:
            client.connect(
                "rotated.example.com",
                username="slowdive",
                password="pygmalion",
                sock=sockc,
                update_host_keys=True,
            )
            assert event.wait(1.0)
            # Server only advertises one of its rotated keys.
            ts.send_host_key_offer([rotated[0].asbytes()])
            for _ in range(100):
                host_keys = client.get_host_keys()
                if "ssh-ed25519" in host_keys.get(
                    "rotated.example.com", {}
                ):
                    break
                time.sleep(0.05)
            host_keys = client.get_host_keys()["rotated.example.com"]
            # New key learned, original key untouched.
            assert host_keys["ssh-ed25519"] == rotated[0]
            assert host_keys["ssh-rsa"] == host_key
            # Persisted back to the known_hosts file...
            saved = known_hosts.read_text()
            assert "rotated.example.com ssh-ed25519" in saved
            assert "rotated.example.com ssh-rsa" in saved
            # ...and the unmentioned host's record was not deleted.
            assert "other.example.com ssh-rsa" in saved
        finally:
            client.close()
            ts.close()
            socks.close()
            sockc.close()
