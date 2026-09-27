# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Tests for client-side OpenSSH Ed25519 host certificate support.

Test CA and host keys are generated locally; certificates are built (and
signed) in-process following OpenSSH's PROTOCOL.certkeys, and exercised both
against the verifier directly and through real client/server handshakes.
"""

import socket
import threading
import time
import unittest

import nacl.signing

import paramiko
from paramiko import (
    AutoAddPolicy,
    Ed25519Key,
    HostCertificateVerifier,
    Message,
    OpenSSHCertificate,
    RSAKey,
    SSHClient,
    SSHException,
    Transport,
)
from paramiko.hostcerts import (
    CERT_TYPE_HOST,
    CERT_TYPE_USER,
    ED25519_CERT_TYPE,
    CertificateValidationError,
)

from ._util import _support

NOW = int(time.time())
DAY = 24 * 60 * 60


def generate_ed25519_key():
    """A sign-capable Ed25519Key generated locally."""
    signing_key = nacl.signing.SigningKey.generate()
    msg = Message()
    msg.add_string("ssh-ed25519")
    msg.add_string(signing_key.verify_key.encode())
    key = Ed25519Key(data=msg.asbytes())
    key._signing_key = signing_key
    return key


def public_half(key):
    return Ed25519Key(data=key.asbytes())


def build_certificate(
    host_public_bytes,
    ca_key,
    principals,
    cert_type=CERT_TYPE_HOST,
    valid_after=NOW - DAY,
    valid_before=NOW + DAY,
    critical_options=None,
    key_id="paramiko-test",
    serial=1,
    signing_key=None,
):
    """
    Build (and sign) an ssh-ed25519-cert-v01@openssh.com blob, per
    PROTOCOL.certkeys.  The signing key defaults to the CA key.
    """
    m = Message()
    m.add_string(ED25519_CERT_TYPE)
    m.add_string(b"nonce-bytes-for-tests!")
    m.add_string(host_public_bytes)
    m.add_int64(serial)
    m.add_int(cert_type)
    m.add_string(key_id)
    pm = Message()
    for principal in principals:
        pm.add_string(principal)
    m.add_string(pm.asbytes())
    m.add_int64(valid_after)
    m.add_int64(valid_before)
    cm = Message()
    for name, data in (critical_options or {}).items():
        cm.add_string(name)
        cm.add_string(data)
    m.add_string(cm.asbytes())
    m.add_string(b"")  # no extensions
    m.add_string(b"")  # reserved
    m.add_string(ca_key.asbytes())
    signed_data = m.asbytes()
    signer = signing_key if signing_key is not None else ca_key
    signature = signer._signing_key.sign(signed_data).signature
    sm = Message()
    sm.add_string("ssh-ed25519")
    sm.add_string(signature)
    m.add_string(sm.asbytes())
    return m.asbytes()


def key_presenting_cert(cert_blob):
    """A public-only Ed25519Key as the client would build from the wire."""
    return Ed25519Key(data=cert_blob)


class CertFixture:
    """A CA, a host key, and a certificate binding them, for one hostname."""

    HOSTNAME = "127.0.0.1"

    def __init__(self, **cert_kwargs):
        self.ca_key = generate_ed25519_key()
        self.host_key = generate_ed25519_key()
        cert_kwargs.setdefault("principals", [self.HOSTNAME])
        self.cert_blob = build_certificate(
            self.host_key.verifying_key.encode(), self.ca_key, **cert_kwargs
        )

    def verifier(self, patterns=None, **kwargs):
        verifier = HostCertificateVerifier(**kwargs)
        verifier.add_ca_key(
            public_half(self.ca_key), patterns or [self.HOSTNAME]
        )
        return verifier


class OpenSSHCertificateTest(unittest.TestCase):
    def test_parse_fields(self):
        fixture = CertFixture(key_id="some-key-id", serial=42)
        cert = OpenSSHCertificate(fixture.cert_blob)
        self.assertEqual(ED25519_CERT_TYPE, cert.key_type)
        self.assertEqual(42, cert.serial)
        self.assertEqual(CERT_TYPE_HOST, cert.cert_type)
        self.assertEqual("some-key-id", cert.key_id)
        self.assertEqual([CertFixture.HOSTNAME], cert.principals)
        self.assertEqual({}, cert.critical_options)
        self.assertEqual({}, cert.extensions)
        self.assertEqual(fixture.ca_key.asbytes(), cert.signature_key)
        self.assertEqual(
            fixture.host_key.verifying_key.encode(), cert.public_key
        )

    def test_malformed_blob_rejected(self):
        with self.assertRaises(CertificateValidationError):
            OpenSSHCertificate(b"this is not a certificate")

    def test_wrong_cert_type_rejected(self):
        blob = Message()
        blob.add_string("ssh-rsa-cert-v01@openssh.com")
        with self.assertRaises(CertificateValidationError):
            OpenSSHCertificate(blob.asbytes())

    def test_from_key_requires_cert_blob(self):
        with self.assertRaises(CertificateValidationError):
            OpenSSHCertificate.from_key(generate_ed25519_key())


class HostCertificateVerifierTest(unittest.TestCase):
    def assert_rejected(self, verifier, cert_blob, hostname):
        with self.assertRaises(CertificateValidationError):
            verifier.verify(key_presenting_cert(cert_blob), hostname)

    def test_valid_certificate_accepted(self):
        fixture = CertFixture()
        fixture.verifier().verify(
            key_presenting_cert(fixture.cert_blob), CertFixture.HOSTNAME
        )

    def test_tampered_signature_rejected(self):
        fixture = CertFixture()
        blob = bytearray(fixture.cert_blob)
        blob[-1] ^= 0xFF
        self.assert_rejected(
            fixture.verifier(), bytes(blob), CertFixture.HOSTNAME
        )

    def test_tampered_signed_data_rejected(self):
        fixture = CertFixture()
        blob = bytearray(fixture.cert_blob)
        # Flip a bit inside the signed region (the key id, say) without
        # re-signing.
        blob[80] ^= 0xFF
        self.assert_rejected(
            fixture.verifier(), bytes(blob), CertFixture.HOSTNAME
        )

    def test_wrong_signing_key_rejected(self):
        fixture = CertFixture()
        blob = build_certificate(
            fixture.host_key.verifying_key.encode(),
            fixture.ca_key,
            [CertFixture.HOSTNAME],
            signing_key=generate_ed25519_key(),
        )
        self.assert_rejected(fixture.verifier(), blob, CertFixture.HOSTNAME)

    def test_wrong_hostname_rejected(self):
        fixture = CertFixture()
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, "other.example.com"
        )

    def test_expired_certificate_rejected(self):
        fixture = CertFixture(valid_after=NOW - 2 * DAY, valid_before=NOW - 1)
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_not_yet_valid_certificate_rejected(self):
        fixture = CertFixture(
            valid_after=NOW + DAY, valid_before=NOW + 2 * DAY
        )
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_user_certificate_rejected(self):
        fixture = CertFixture(cert_type=CERT_TYPE_USER)
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_unknown_critical_option_rejected(self):
        fixture = CertFixture(
            critical_options={"unknown-critical@example.com": b"data"}
        )
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_empty_principals_rejected_by_default(self):
        fixture = CertFixture(principals=[])
        self.assert_rejected(
            fixture.verifier(), fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_empty_principals_allowed_when_explicitly_enabled(self):
        fixture = CertFixture(principals=[])
        verifier = fixture.verifier(allow_wildcard_principals=True)
        verifier.verify(
            key_presenting_cert(fixture.cert_blob), CertFixture.HOSTNAME
        )

    def test_wildcard_principal_matches(self):
        fixture = CertFixture(principals=["*.example.com"])
        verifier = fixture.verifier(patterns=["*.example.com"])
        verifier.verify(
            key_presenting_cert(fixture.cert_blob), "www.example.com"
        )

    def test_untrusted_ca_rejected(self):
        fixture = CertFixture()
        verifier = HostCertificateVerifier()
        verifier.add_ca_key(
            public_half(generate_ed25519_key()), [CertFixture.HOSTNAME]
        )
        self.assert_rejected(
            verifier, fixture.cert_blob, CertFixture.HOSTNAME
        )

    def test_ca_host_range_enforced(self):
        fixture = CertFixture()
        verifier = fixture.verifier(patterns=["*.example.com"])
        self.assert_rejected(verifier, fixture.cert_blob, CertFixture.HOSTNAME)

    def test_ca_negated_host_range(self):
        fixture = CertFixture()
        verifier = fixture.verifier(patterns=["*", "!127.0.0.1"])
        self.assert_rejected(verifier, fixture.cert_blob, CertFixture.HOSTNAME)

    def test_non_ed25519_ca_rejected(self):
        verifier = HostCertificateVerifier()
        with self.assertRaises(ValueError):
            verifier.add_ca_key(RSAKey.generate(2048), ["*"])

    def test_empty_host_patterns_rejected(self):
        verifier = HostCertificateVerifier()
        with self.assertRaises(ValueError):
            verifier.add_ca_key(public_half(generate_ed25519_key()), [])


class CertServer(paramiko.ServerInterface):
    def check_auth_password(self, username, password):
        if (username, password) == ("slowdive", "pygmalion"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"


class HostCertificateHandshakeTest(unittest.TestCase):
    """
    Real handshakes over socket pairs: a server Transport presents (or
    mis-presents) a host certificate, an SSHClient must accept or reject.
    """

    HOSTNAME = "testhost.example.com"

    def setUp(self):
        self.client_sock, self.server_sock = socket.socketpair()
        self.event = threading.Event()
        self.threads = []
        self.transports = []

    def tearDown(self):
        for transport in self.transports:
            transport.close()
        if hasattr(self, "tc"):
            self.tc.close()
        self.client_sock.close()
        self.server_sock.close()
        for thread in self.threads:
            thread.join(5)

    def _serve(self, host_key):
        try:
            ts = Transport(self.server_sock)
            self.transports.append(ts)
            ts.add_server_key(host_key)
            ts.start_server(self.event, CertServer())
        except Exception:
            pass

    def _start_server(self, host_key):
        thread = threading.Thread(target=self._serve, args=(host_key,))
        thread.daemon = True
        thread.start()
        self.threads.append(thread)

    def _certified_host_key(self, fixture):
        host_key = fixture.host_key
        host_key.load_certificate(Message(fixture.cert_blob))
        return host_key

    def _connect(self, verifier="default", policy=None, **connect_kwargs):
        self.tc = SSHClient()
        if policy is not None:
            self.tc.set_missing_host_key_policy(policy)
        if verifier == "default":
            verifier = self.fixture.verifier(patterns=[self.HOSTNAME])
        if verifier is not None:
            self.tc.set_host_certificate_verifier(verifier)
        self.tc.connect(
            hostname=self.HOSTNAME,
            port=2222,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
            sock=self.client_sock,
            **connect_kwargs
        )

    def _assert_connected(self):
        self.assertTrue(self.event.wait(5.0))
        self.assertTrue(self.tc.get_transport().is_active())
        self.assertTrue(self.tc.get_transport().is_authenticated())

    def _assert_rejected(self, *args, **kwargs):
        with self.assertRaises(SSHException):
            self._connect(*args, **kwargs)
        # Nothing may have been learned about the server.
        self.assertEqual(0, len(self.tc.get_host_keys()))

    def test_valid_certificate_connects(self):
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        self._start_server(self._certified_host_key(self.fixture))
        # Even with AutoAddPolicy in place, the certificate path must be
        # taken and nothing may be added to the known-hosts structures.
        self._connect(policy=AutoAddPolicy())
        self._assert_connected()
        self.assertEqual(0, len(self.tc.get_host_keys()))

    def test_tampered_signature_rejected(self):
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        blob = bytearray(self.fixture.cert_blob)
        blob[-1] ^= 0xFF
        self.fixture.cert_blob = bytes(blob)
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_wrong_hostname_rejected(self):
        self.fixture = CertFixture(principals=["other.example.com"])
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_expired_certificate_rejected(self):
        self.fixture = CertFixture(
            principals=[self.HOSTNAME],
            valid_after=NOW - 2 * DAY,
            valid_before=NOW - 1,
        )
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_user_certificate_rejected(self):
        self.fixture = CertFixture(
            principals=[self.HOSTNAME], cert_type=CERT_TYPE_USER
        )
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_unknown_critical_option_rejected(self):
        self.fixture = CertFixture(
            principals=[self.HOSTNAME],
            critical_options={"unknown-critical@example.com": b"data"},
        )
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_empty_principals_rejected(self):
        self.fixture = CertFixture(principals=[])
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(policy=AutoAddPolicy())

    def test_no_verifier_configured_rejected(self):
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected(verifier=None, policy=AutoAddPolicy())

    def test_untrusted_ca_rejected(self):
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        self._start_server(self._certified_host_key(self.fixture))
        verifier = HostCertificateVerifier()
        verifier.add_ca_key(public_half(generate_ed25519_key()), ["*"])
        self._assert_rejected(verifier=verifier, policy=AutoAddPolicy())

    def test_certificate_without_private_key_rejected(self):
        # The certificate binds CA -> host public key B, but the server only
        # holds private key A: the handshake signature must not verify.
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        other_key = generate_ed25519_key()
        self.fixture.cert_blob = build_certificate(
            other_key.verifying_key.encode(),
            self.fixture.ca_key,
            [self.HOSTNAME],
        )
        self._start_server(self._certified_host_key(self.fixture))
        self._assert_rejected()

    def test_nonstandard_port_known_host_identity(self):
        # A known-hosts entry for the port-qualified identity must not
        # interfere: certificate principals are matched against the bare
        # hostname.
        self.fixture = CertFixture(principals=[self.HOSTNAME])
        self._start_server(self._certified_host_key(self.fixture))
        self.tc = SSHClient()
        rsa_key = RSAKey.from_private_key_file(_support("rsa.key"))
        self.tc.get_host_keys().add(
            "[{}]:2222".format(self.HOSTNAME),
            "ssh-rsa",
            RSAKey(data=rsa_key.asbytes()),
        )
        self.tc.set_host_certificate_verifier(
            self.fixture.verifier(patterns=[self.HOSTNAME])
        )
        self.tc.connect(
            hostname=self.HOSTNAME,
            port=2222,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
            sock=self.client_sock,
        )
        self._assert_connected()

    def test_bare_host_key_still_works(self):
        # Legacy flow: no certificate involved, plain known-hosts check.
        host_key = generate_ed25519_key()
        self._start_server(host_key)
        self.tc = SSHClient()
        self.tc.get_host_keys().add(
            "[{}]:2222".format(self.HOSTNAME),
            "ssh-ed25519",
            public_half(host_key),
        )
        self.tc.connect(
            hostname=self.HOSTNAME,
            port=2222,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
            sock=self.client_sock,
        )
        self._assert_connected()
