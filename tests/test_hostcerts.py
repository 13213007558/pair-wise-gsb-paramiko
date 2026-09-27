# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under
# the terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for
# more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.

"""
Tests for client-side OpenSSH host certificate verification.

These tests generate a local Ed25519 CA and host keys at runtime, issue
certificates per PROTOCOL.certkeys, and run real handshakes against an
in-process server.
"""

import socket
import threading
import time

import nacl.signing
import pytest

import paramiko
from paramiko import SSHClient
from paramiko.ed25519key import Ed25519Key
from paramiko.hostcerts import (
    CERT_TYPE_HOST,
    CERT_TYPE_USER,
    ED25519_CERT_KEY_TYPE,
    OpenSSHCertificate,
    HostCertificateVerifier,
)
from paramiko.message import Message
from paramiko.ssh_exception import HostCertificateError, SSHException

FOREVER = 2**64 - 1


def generate_ed25519_key():
    """Create an Ed25519Key holding both private and public halves."""
    signing_key = nacl.signing.SigningKey.generate()
    msg = Message()
    msg.add_string("ssh-ed25519")
    msg.add_string(bytes(signing_key.verify_key))
    key = Ed25519Key(data=msg.asbytes())
    key._signing_key = signing_key
    return key


def build_certificate(
    ca_key,
    host_key,
    principals,
    cert_type=CERT_TYPE_HOST,
    valid_after=0,
    valid_before=FOREVER,
    critical_options=None,
    key_id="paramiko-test",
    serial=1,
    signing_key=None,
):
    """
    Build a signed ssh-ed25519-cert-v01@openssh.com blob.

    ``signing_key`` defaults to ``ca_key``; pass a different key
    to produce a certificate whose signature key does not match its
    signature.
    """
    m = Message()
    m.add_string(ED25519_CERT_KEY_TYPE)
    m.add_string(b"\x00" * 32)  # nonce
    m.add_string(bytes(host_key.verifying_key))
    m.add_int64(serial)
    m.add_int(cert_type)
    m.add_string(key_id)
    principal_msg = Message()
    for principal in principals:
        principal_msg.add_string(principal)
    m.add_string(principal_msg.asbytes())
    m.add_int64(valid_after)
    m.add_int64(valid_before)
    options_msg = Message()
    for name, data in (critical_options or {}).items():
        options_msg.add_string(name)
        options_msg.add_string(data)
    m.add_string(options_msg.asbytes())
    m.add_string(b"")  # extensions
    m.add_string(b"")  # reserved
    m.add_string(ca_key.asbytes())  # signature key
    signer = signing_key if signing_key is not None else ca_key
    m.add_string(signer.sign_ssh_data(m.asbytes()).asbytes())
    return m.asbytes()


class PasswordServer(paramiko.ServerInterface):
    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        if (username, password) == ("slowdive", "pygmalion"):
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED


class TestHostCertificates:
    def setup_method(self):
        # Nonstandard port, to exercise the [host]:port known-hosts
        # identity vs bare-hostname certificate principals.
        self.port = 2222
        self.ca_key = generate_ed25519_key()
        self.host_key = generate_ed25519_key()
        self.tc = None
        self.ts = None

    def teardown_method(self):
        if self.tc is not None:
            self.tc.close()
        if self.ts is not None:
            self.ts.close()
        for sock in getattr(self, "_socks", ()):
            try:
                sock.close()
            except OSError:
                pass

    def _run_server(self, server_sock, server_host_key):
        self.ts = paramiko.Transport(server_sock)
        self.ts.add_server_key(server_host_key)
        try:
            self.ts.start_server(threading.Event(), PasswordServer())
        except (SSHException, EOFError, OSError):
            pass

    def _verifier(self, **kwargs):
        verifier = HostCertificateVerifier(**kwargs)
        verifier.add_ca_key(self.ca_key)
        return verifier

    def _good_cert(self, **kwargs):
        kwargs.setdefault("principals", ["localhost"])
        return build_certificate(self.ca_key, self.host_key, **kwargs)

    def _connect(
        self,
        cert_blob=None,
        verifier=None,
        server_key=None,
        policy=None,
        hostname="localhost",
    ):
        if server_key is None:
            server_key = self.host_key
            if cert_blob is not None:
                server_key.load_certificate(Message(cert_blob))
        client_sock, server_sock = socket.socketpair()
        self._socks = (client_sock, server_sock)
        threading.Thread(
            target=self._run_server,
            args=(server_sock, server_key),
            daemon=True,
        ).start()
        self.tc = SSHClient()
        if verifier is not None:
            self.tc.set_host_certificate_verifier(verifier)
        if policy is not None:
            self.tc.set_missing_host_key_policy(policy)
        self.tc.connect(
            hostname,
            port=self.port,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
            sock=client_sock,
        )
        return self.tc

    def test_valid_certificate_connects(self):
        tc = self._connect(
            cert_blob=self._good_cert(), verifier=self._verifier()
        )
        assert tc.get_transport().is_active()
        # The certificate algorithm was negotiated...
        assert tc.get_transport().host_key_type == ED25519_CERT_KEY_TYPE
        # ...and nothing (neither cert nor CA) was recorded as a bare
        # host key.
        assert len(tc.get_host_keys()) == 0

    def test_nonstandard_port_principal_is_bare_hostname(self):
        # The connection uses an ephemeral (non-22) port, so the
        # known-hosts identity would be "[localhost]:port" - but the
        # certificate principal is matched against the bare hostname.
        cert = self._good_cert(principals=["localhost"])
        tc = self._connect(cert_blob=cert, verifier=self._verifier())
        assert tc.get_transport().is_active()

    def test_tampered_signature_rejected(self):
        cert = bytearray(self._good_cert())
        cert[-1] ^= 0x01  # flip a bit inside the signature
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=bytes(cert), verifier=self._verifier())

    def test_untrusted_ca_rejected(self):
        # Signed by a different CA; the embedded signature key must not
        # become a trust root on its own.
        other_ca = generate_ed25519_key()
        cert = build_certificate(
            other_ca, self.host_key, principals=["localhost"]
        )
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_wrong_hostname_rejected(self):
        cert = self._good_cert(principals=["other.example.com"])
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_expired_certificate_rejected(self):
        cert = self._good_cert(valid_before=int(time.time()) - 60)
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_not_yet_valid_certificate_rejected(self):
        cert = self._good_cert(
            valid_after=int(time.time()) + 3600, valid_before=FOREVER
        )
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_user_certificate_rejected(self):
        cert = self._good_cert(cert_type=CERT_TYPE_USER)
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_unknown_critical_option_rejected(self):
        cert = self._good_cert(
            critical_options={"unknown-option": b"some-value"}
        )
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_empty_principals_rejected_by_default(self):
        cert = self._good_cert(principals=[])
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=cert, verifier=self._verifier())

    def test_empty_principals_allowed_when_explicitly_enabled(self):
        cert = self._good_cert(principals=[])
        verifier = self._verifier(allow_wildcard_principals=True)
        tc = self._connect(cert_blob=cert, verifier=verifier)
        assert tc.get_transport().is_active()

    def test_certificate_failure_not_delegated_to_auto_add_policy(self):
        cert = bytearray(self._good_cert())
        cert[-1] ^= 0x01
        with pytest.raises(HostCertificateError):
            self._connect(
                cert_blob=bytes(cert),
                verifier=self._verifier(),
                policy=paramiko.AutoAddPolicy(),
            )
        # AutoAddPolicy must not have recorded anything.
        assert len(self.tc.get_host_keys()) == 0

    def test_server_must_prove_possession_of_certified_key(self):
        # The server holds private key A but presents a certificate for
        # public key B: the handshake signature cannot verify.
        other_host_key = generate_ed25519_key()
        cert = build_certificate(
            self.ca_key, other_host_key, principals=["localhost"]
        )
        self.host_key.load_certificate(Message(cert))
        with pytest.raises(SSHException):
            self._connect(
                server_key=self.host_key, verifier=self._verifier()
            )

    def test_bare_host_key_still_accepted_via_known_hosts(self):
        # Verifier configured, but the server presents a plain key: the
        # classic known-hosts flow (with [host]:port identity) applies.
        client_sock, server_sock = socket.socketpair()
        self._socks = (client_sock, server_sock)
        threading.Thread(
            target=self._run_server,
            args=(server_sock, self.host_key),
            daemon=True,
        ).start()
        self.tc = SSHClient()
        self.tc.set_host_certificate_verifier(self._verifier())
        self.tc.get_host_keys().add(
            "[localhost]:{}".format(self.port), "ssh-ed25519", self.host_key
        )
        self.tc.connect(
            "localhost",
            port=self.port,
            username="slowdive",
            password="pygmalion",
            look_for_keys=False,
            allow_agent=False,
            sock=client_sock,
        )
        assert self.tc.get_transport().is_active()
        assert self.tc.get_transport().host_key_type == "ssh-ed25519"

    def test_ca_host_pattern_mismatch_rejected(self):
        verifier = HostCertificateVerifier()
        verifier.add_ca_key(self.ca_key, host_patterns=["*.example.com"])
        with pytest.raises(HostCertificateError):
            self._connect(cert_blob=self._good_cert(), verifier=verifier)

    def test_ca_host_pattern_match_accepted(self):
        verifier = HostCertificateVerifier()
        verifier.add_ca_key(self.ca_key, host_patterns=["!badhost", "local*"])
        tc = self._connect(cert_blob=self._good_cert(), verifier=verifier)
        assert tc.get_transport().is_active()


class TestVerifierUnits:
    def test_ca_key_must_be_ed25519(self):
        verifier = HostCertificateVerifier()
        with pytest.raises(ValueError):
            verifier.add_ca_key(paramiko.RSAKey.generate(2048))

    def test_ca_key_may_not_be_a_certificate(self):
        ca_key = generate_ed25519_key()
        host_key = generate_ed25519_key()
        cert = build_certificate(ca_key, host_key, principals=["x"])
        ca_key.load_certificate(Message(cert))
        verifier = HostCertificateVerifier()
        with pytest.raises(ValueError):
            verifier.add_ca_key(ca_key)

    def test_ca_key_loadable_from_public_key_string(self):
        ca_key = generate_ed25519_key()
        verifier = HostCertificateVerifier()
        verifier.add_ca_key(
            "ssh-ed25519 {} test-ca".format(ca_key.get_base64())
        )
        host_key = generate_ed25519_key()
        cert = build_certificate(ca_key, host_key, principals=["host1"])
        key = Ed25519Key(data=cert)
        parsed = verifier.verify(key, "host1")
        assert parsed.principals == ["host1"]
        assert parsed.cert_type == CERT_TYPE_HOST

    def test_non_ed25519_certificates_are_rejected(self):
        msg = Message()
        msg.add_string("ssh-rsa-cert-v01@openssh.com")
        msg.add_string(b"\x00" * 32)
        with pytest.raises(HostCertificateError):
            OpenSSHCertificate(msg.asbytes())

    def test_truncated_certificate_is_rejected(self):
        cert = bytearray(
            build_certificate(
                generate_ed25519_key(),
                generate_ed25519_key(),
                principals=["h"],
            )
        )
        with pytest.raises(HostCertificateError):
            OpenSSHCertificate(bytes(cert[:20]))
