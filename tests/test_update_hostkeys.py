"""
Tests for the opt-in OpenSSH host key rotation learning flow
(hostkeys-00@openssh.com / hostkeys-prove-00@openssh.com).
"""

import threading
import time
from contextlib import contextmanager

from paramiko import (
    AUTH_SUCCESSFUL,
    AutoAddPolicy,
    ECDSAKey,
    Ed25519Key,
    RSAKey,
    ServerInterface,
    SSHClient,
    Transport,
)
from paramiko.common import cMSG_GLOBAL_REQUEST
from paramiko.message import Message

from ._loop import LoopSocket
from ._util import _support


HOST_KEY = RSAKey.from_private_key_file(_support("rsa.key"))
HOST_KEY_PUB = RSAKey(data=HOST_KEY.asbytes())
ECDSA_KEY = ECDSAKey.from_private_key_file(_support("ecdsa-256.key"))
ED25519_KEY = Ed25519Key.from_private_key_file(_support("ed25519.key"))
LONELY_KEY = RSAKey.from_private_key_file(_support("rsa-lonely.key"))

HOSTNAME = "update-hostkeys.example.com"
PROVE_REQUEST = "hostkeys-prove-00@openssh.com"


class ScriptedServer(ServerInterface):
    """
    A scripted peer advertising host keys after authentication and answering
    hostkeys-prove-00@openssh.com requests, with knobs for misbehavior.
    """

    def __init__(
        self,
        candidates,
        session_id=None,
        drop_last_proof=False,
        bad_session_blobs=(),
    ):
        # Candidate public key blobs, in the exact (possibly duplicate-laden
        # or unsorted) order they should be advertised in.
        self.candidates = candidates
        # When set, proofs are signed against this session id instead of the
        # current connection's, simulating stale/replayed proofs.
        self.session_id_override = session_id
        # Blobs whose proofs are deliberately signed against a bogus session
        # id, simulating proofs that do not belong to this connection.
        self.bad_session_blobs = bad_session_blobs
        # When true, the last requested proof is withheld from the response.
        self.drop_last_proof = drop_last_proof
        self.prove_count = 0
        self.offers_sent = 0
        self.transport = None
        self._private_keys = {
            key.asbytes(): key for key in (ECDSA_KEY, ED25519_KEY, LONELY_KEY)
        }

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_global_request(self, kind, msg):
        if kind != PROVE_REQUEST:
            return False
        self.prove_count += 1
        blobs = []
        while msg.get_remainder():
            blobs.append(msg.get_string())
        signatures = []
        for blob in blobs:
            session_id = self.session_id_override
            if session_id is None:
                session_id = self.transport.session_id
            if blob in self.bad_session_blobs:
                session_id = b"\xde\xad\xbe\xef" * 8
            proof = Message()
            proof.add_string(b"hostkeys-prove-00@openssh.com")
            proof.add_string(session_id)
            proof.add_string(blob)
            signatures.append(
                bytes(self._private_keys[blob].sign_ssh_data(bytes(proof)))
            )
        if self.drop_last_proof:
            signatures = signatures[:-1]
        return tuple(signatures)

    def send_hostkeys_offer(self):
        m = Message()
        m.add_byte(cMSG_GLOBAL_REQUEST)
        m.add_string("hostkeys-00@openssh.com")
        m.add_boolean(False)
        for blob in self.candidates:
            m.add_string(blob)
        self.transport._send_user_message(m)
        self.offers_sent += 1


def _serve(sock, server, offers):
    ts = Transport(sock)
    ts.add_server_key(HOST_KEY)
    server.transport = ts
    ts.start_server(threading.Event(), server)
    while ts.is_active() and not ts.is_authenticated():
        time.sleep(0.01)
    for _ in range(offers):
        server.send_hostkeys_offer()
        time.sleep(0.05)


@contextmanager
def update_server(
    candidates,
    trusted=True,
    enable=True,
    offers=1,
    extra_known_keys=(),
    **server_kwargs
):
    """
    Run a scripted server and connect an SSHClient to it.

    Yields (client, server, notifications) once connect() has returned,
    i.e. after any host key learning has completed.
    """
    sockc, socks = LoopSocket(), LoopSocket()
    sockc.link(socks)
    server = ScriptedServer(candidates, **server_kwargs)
    thread = threading.Thread(
        target=_serve, args=(socks, server, offers), daemon=True
    )
    thread.start()
    notifications = []
    client = SSHClient()
    if trusted:
        client.get_host_keys().add(HOSTNAME, "ssh-rsa", HOST_KEY_PUB)
        for key in extra_known_keys:
            client.get_host_keys().add(HOSTNAME, key.get_name(), key)
    else:
        client.set_missing_host_key_policy(AutoAddPolicy())
    if enable:
        client.enable_update_hostkeys(
            callback=lambda h, keys: notifications.append((h, keys)),
            timeout=2.0,
        )
    try:
        client.connect(
            HOSTNAME,
            sock=sockc,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
        )
        yield client, server, notifications
    finally:
        client.close()
        if server.transport is not None:
            server.transport.close()
        thread.join(5)
        sockc.close()
        socks.close()


def known_keytypes(client):
    return set(client.get_host_keys()[HOSTNAME].keys())


class TestUpdateHostKeys:
    def test_learns_verified_keys_from_unordered_duplicate_offer(self):
        # Server advertises its new keys out of order and with duplicates.
        candidates = [
            ED25519_KEY.asbytes(),
            ECDSA_KEY.asbytes(),
            ED25519_KEY.asbytes(),
            ECDSA_KEY.asbytes(),
        ]
        with update_server(candidates) as (client, server, notifications):
            keytypes = known_keytypes(client)
            assert "ssh-ed25519" in keytypes
            assert "ecdsa-sha2-nistp256" in keytypes
            # Duplicates collapsed: exactly one notification, with each new
            # key appearing exactly once, after the whole set was verified.
            assert len(notifications) == 1
            hostname, keys = notifications[0]
            assert hostname == HOSTNAME
            assert sorted(key.asbytes() for key in keys) == sorted(
                [ED25519_KEY.asbytes(), ECDSA_KEY.asbytes()]
            )
            assert server.prove_count == 1

    def test_wrong_session_signature_is_rejected(self):
        # Only the ed25519 proof is bound to the real session id; the ecdsa
        # proof is signed against a bogus one and must not be learned.
        candidates = [ED25519_KEY.asbytes(), ECDSA_KEY.asbytes()]
        with update_server(
            candidates, bad_session_blobs=(ECDSA_KEY.asbytes(),)
        ) as (client, server, notifications):
            keytypes = known_keytypes(client)
            assert "ssh-ed25519" in keytypes
            assert "ecdsa-sha2-nistp256" not in keytypes
            assert len(notifications) == 1
            assert [k.get_name() for k in notifications[0][1]] == [
                "ssh-ed25519"
            ]

    def test_missing_proof_is_rejected(self):
        # Server withholds the proof for the last requested key.
        candidates = [ED25519_KEY.asbytes(), ECDSA_KEY.asbytes()]
        with update_server(candidates, drop_last_proof=True) as (
            client,
            server,
            notifications,
        ):
            keytypes = known_keytypes(client)
            assert "ssh-ed25519" in keytypes
            assert "ecdsa-sha2-nistp256" not in keytypes

    def test_disabled_by_default(self):
        candidates = [ED25519_KEY.asbytes()]
        with update_server(candidates, enable=False) as (
            client,
            server,
            notifications,
        ):
            time.sleep(0.2)
            assert server.offers_sent == 1
            assert server.prove_count == 0
            assert "ssh-ed25519" not in known_keytypes(client)
            assert notifications == []

    def test_untrusted_host_key_skips_learning(self):
        # Connection authenticated via AutoAddPolicy (no pre-existing trusted
        # host key) must not process candidates.
        candidates = [ED25519_KEY.asbytes()]
        with update_server(candidates, trusted=False) as (
            client,
            server,
            notifications,
        ):
            time.sleep(0.2)
            assert server.prove_count == 0
            assert "ssh-ed25519" not in known_keytypes(client)
            assert notifications == []

    def test_reconnect_requires_fresh_proof(self):
        candidates = [ED25519_KEY.asbytes()]
        with update_server(candidates) as (client, server, notifications):
            assert "ssh-ed25519" in known_keytypes(client)
            first_session_id = server.transport.session_id
            assert server.prove_count == 1
        # A new connection gets a new session id, and the client must ask for
        # proofs again; a proof bound to the previous connection's session id
        # (replayed here by the server) is rejected.
        with update_server(candidates, session_id=first_session_id) as (
            client,
            server,
            notifications,
        ):
            assert server.transport.session_id != first_session_id
            assert server.prove_count == 1
            assert "ssh-ed25519" not in known_keytypes(client)
            assert notifications == []

    def test_existing_connection_notified_only_once(self):
        candidates = [ED25519_KEY.asbytes()]
        with update_server(candidates, offers=2) as (
            client,
            server,
            notifications,
        ):
            time.sleep(0.2)
            assert server.offers_sent == 2
            assert server.prove_count == 1
            assert len(notifications) == 1
            assert "ssh-ed25519" in known_keytypes(client)

    def test_unadvertised_local_keys_are_never_removed(self):
        # A pre-existing local record the server no longer advertises must
        # survive the update untouched.
        candidates = [ECDSA_KEY.asbytes()]
        with update_server(candidates, extra_known_keys=(LONELY_KEY,)) as (
            client,
            server,
            notifications,
        ):
            host_keys = client.get_host_keys()
            assert host_keys.check(HOSTNAME, LONELY_KEY)
            assert host_keys.check(HOSTNAME, ECDSA_KEY)
            assert host_keys.check(HOSTNAME, HOST_KEY_PUB)
