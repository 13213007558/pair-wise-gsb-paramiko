"""
Tests for explicit OpenSSH host-certificate verification.

These tests deliberately avoid network *port binding* (unavailable in some
sandboxes) by driving real client/server ``Transport`` objects over an
in-process ``socket.socketpair``. All keys and certificates are generated in
memory with the cryptography/paramiko primitives, so the suite needs no
``ssh-keygen`` or external fixtures.
"""

import io
import socket
import threading
import unittest
from itertools import count

import paramiko
from paramiko import (
    Ed25519Key,
    HostCertificateAuthority,
    HostCertificateError,
    HostCertificateNameError,
    HostCertificateSignatureError,
    HostCertificateTrustError,
    HostCertificateValidityError,
    HostCertificateVerifier,
    Message,
    PublicBlob,
    RejectPolicy,
    SSHClient,
)
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)
from cryptography.hazmat.primitives import serialization

CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com"
HOST_A = "host-a.example.com"
HOST_B = "host-b.example.com"
USER_CERT_TYPE_KIND = 1
HOST_CERT_KIND = 2
MAX_UINT64 = (1 << 64) - 1


def _new_ed25519():
    """Generate a signing-capable Ed25519 PKey entirely in memory."""
    private = Ed25519PrivateKey.generate()
    pem = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return Ed25519Key(file_obj=io.StringIO(pem.decode()))


def _public_only(key):
    """Return a public-only copy of a signing key."""
    return Ed25519Key(data=key.asbytes())


def _section(strings=(), pairs=()):
    """Build a length-delimited certificate section (no inner count)."""
    msg = Message()
    for value in strings:
        msg.add_string(value)
    for name, value in pairs:
        msg.add_string(name)
        msg.add_string(value)
    return msg.asbytes()


def _certified_key_field(host_key):
    """
    Encode a key the way OpenSSH stores it inside a certificate.

    Ed25519 uses a single outer-prefixed raw value; RSA and ECDSA use their
    self-framed component strings without an enclosing type or length.
    """
    field = Message()
    if isinstance(host_key, Ed25519Key):
        field.add_string(host_key.verifying_key.encode())
    elif isinstance(host_key, paramiko.RSAKey):
        field.add_mpint(host_key.public_numbers.e)
        field.add_mpint(host_key.public_numbers.n)
    else:  # ECDSA: short curve name then uncompressed point
        field.add_string(host_key.ecdsa_curve.nist_name)
        field.add_string(
            host_key.verifying_key.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            )
        )
    return field.asbytes()


def build_host_certificate(
    host_key,
    ca_key,
    principals,
    kind=HOST_CERT_KIND,
    valid_after=0,
    valid_before=MAX_UINT64,
    critical_options=(),
    signer=None,
    signature_key=None,
    cert_type=CERT_TYPE,
):
    """
    Construct an OpenSSH host certificate and attach it to ``host_key``.

    ``signer`` controls which key actually signs (for tampering tests), while
    ``signature_key`` / ``ca_key`` control the embedded signature key field --
    allowing us to prove that field never establishes trust on its own.
    """
    signer = signer or ca_key
    message = Message()
    message.add_string(cert_type)
    message.add_string(b"\x00" * 32)  # nonce
    # The certified key field is family-specific (see helper).
    message.add_bytes(_certified_key_field(host_key))
    message.add_int64(next(_serial))
    message.add_int(kind)
    message.add_string("test-key-id")
    message.add_string(_section(strings=principals))
    message.add_int64(valid_after)
    message.add_int64(valid_before)
    crit_pairs = [(name, b"") for name in critical_options]
    message.add_string(_section(pairs=crit_pairs))
    message.add_string(_section())  # no extensions
    message.add_string(b"")  # reserved
    embedded = signature_key if signature_key is not None else ca_key
    message.add_string(embedded.asbytes())
    signature = signer.sign_ssh_data(message.asbytes())
    message.add_string(signature.asbytes())
    host_key.public_blob = PublicBlob(
        type_=cert_type, blob=message.asbytes()
    )
    return host_key


_serial = count(1)


class _RecordingServer(paramiko.ServerInterface):
    """Server that records whether any user-auth material ever arrived."""

    def __init__(self):
        self.auth_attempts = 0
        self.event = threading.Event()

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_publickey(self, username, key):
        self.auth_attempts += 1
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


class HostCertificateUnitTest(unittest.TestCase):
    def setUp(self):
        self.ca = _new_ed25519()
        self.rogue_ca = _new_ed25519()
        self.host_key = _new_ed25519()
        self.ca_public = _public_only(self.ca)
        self.verifier = HostCertificateVerifier(
            HostCertificateAuthority(
                self.ca_public, hostnames=["*.example.com"]
            )
        )

    def _verify(self, key, hostname=HOST_A, port=22):
        return self.verifier.verify_server_key(
            key,
            hostname=hostname,
            raw_hostname=hostname,
            port=port,
        )

    def test_valid_host_certificate_is_accepted(self):
        cert = build_host_certificate(self.host_key, self.ca, [HOST_A])
        result = self._verify(cert)
        self.assertEqual(result.valid_principals, [HOST_A])
        self.assertTrue(result.is_host_certificate())

    def test_wrong_principal_is_rejected_as_name_error(self):
        cert = build_host_certificate(self.host_key, self.ca, [HOST_B])
        with self.assertRaises(HostCertificateNameError):
            self._verify(cert, hostname=HOST_A)

    def test_user_certificate_is_rejected_as_name_error(self):
        cert = build_host_certificate(
            self.host_key, self.ca, [HOST_A], kind=USER_CERT_TYPE_KIND
        )
        with self.assertRaises(HostCertificateNameError):
            self._verify(cert)

    def test_expired_certificate_is_rejected_as_validity_error(self):
        cert = build_host_certificate(
            self.host_key, self.ca, [HOST_A],
            valid_after=1000, valid_before=2000,
        )
        with self.assertRaises(HostCertificateValidityError):
            self._verify(cert)

    def test_not_yet_valid_certificate_is_rejected(self):
        cert = build_host_certificate(
            self.host_key, self.ca, [HOST_A],
            valid_after=MAX_UINT64, valid_before=MAX_UINT64,
        )
        with self.assertRaises(HostCertificateValidityError):
            self._verify(cert)

    def test_untrusted_ca_signature_is_a_trust_error(self):
        cert = build_host_certificate(self.host_key, self.rogue_ca, [HOST_A])
        with self.assertRaises(HostCertificateTrustError):
            self._verify(cert)

    def test_embedded_signature_key_does_not_establish_trust(self):
        # Signed by nobody trusted; embedding a different key inside the
        # certificate must not cause it to validate.
        cert = build_host_certificate(
            self.host_key,
            ca_key=self.rogue_ca,
            principals=[HOST_A],
            signer=self.rogue_ca,
            signature_key=self.ca,  # embed the trusted CA anyway
        )
        with self.assertRaises(HostCertificateTrustError):
            self._verify(cert)

    def test_unknown_critical_option_is_rejected(self):
        cert = build_host_certificate(
            self.host_key, self.ca, [HOST_A],
            critical_options=["frobnicate"],
        )
        with self.assertRaises(HostCertificateSignatureError):
            self._verify(cert)

    def test_host_range_controls_which_ca_applies(self):
        verifier = HostCertificateVerifier(
            HostCertificateAuthority(self.ca_public, hostnames=[HOST_A])
        )
        cert = build_host_certificate(self.host_key, self.ca, [HOST_A])
        # In-range host works.
        verifier.verify_server_key(
            cert, hostname=HOST_A, raw_hostname=HOST_A, port=22
        )
        # The same cert presented while connecting to an out-of-range alias
        # cannot borrow this CA's trust.
        with self.assertRaises(HostCertificateTrustError):
            verifier.verify_server_key(
                cert, hostname=HOST_A, raw_hostname="evil.other.net", port=22
            )

    def test_negated_host_pattern_excludes_name(self):
        authority = HostCertificateAuthority(
            self.ca_public, hostnames=["*.example.com", "!host-b.example.com"]
        )
        self.assertTrue(authority.covers(HOST_A))
        self.assertFalse(authority.covers(HOST_B))
        self.assertFalse(authority.covers("elsewhere.net"))

    def test_port_scoped_authority_requires_matching_port(self):
        authority = HostCertificateAuthority(
            self.ca_public, hostnames=[HOST_A], port=2222
        )
        self.assertTrue(authority.covers(HOST_A, port=2222))
        self.assertFalse(authority.covers(HOST_A, port=22))

    def test_wildcard_principal_matches(self):
        cert = build_host_certificate(
            self.host_key, self.ca, ["*.example.com"]
        )
        self._verify(cert, hostname="anything.example.com")

    def test_rsa_certificate_round_trip(self):
        ca = paramiko.RSAKey.generate(bits=2048)
        host = paramiko.RSAKey.generate(bits=2048)
        cert = build_host_certificate(
            host,
            ca,
            ["rsa.example.com"],
            cert_type="rsa-sha2-512-cert-v01@openssh.com",
        )
        verifier = HostCertificateVerifier(
            HostCertificateAuthority(
                paramiko.RSAKey(data=ca.asbytes()),
                hostnames=["*.example.com"],
            )
        )
        result = verifier.verify_server_key(
            cert,
            hostname="rsa.example.com",
            raw_hostname="rsa.example.com",
            port=22,
        )
        self.assertEqual(result.key.get_name(), "ssh-rsa")

    def test_ecdsa_certificate_round_trip(self):
        ca = paramiko.ECDSAKey.generate()
        host = paramiko.ECDSAKey.generate()
        cert = build_host_certificate(
            host,
            ca,
            ["ec.example.com"],
            cert_type="ecdsa-sha2-nistp256-cert-v01@openssh.com",
        )
        verifier = HostCertificateVerifier(
            HostCertificateAuthority(
                paramiko.ECDSAKey(data=ca.asbytes()),
                hostnames=["*.example.com"],
            )
        )
        result = verifier.verify_server_key(
            cert,
            hostname="ec.example.com",
            raw_hostname="ec.example.com",
            port=22,
        )
        self.assertTrue(result.key.get_name().startswith("ecdsa-sha2-"))

    def test_non_certificate_key_is_rejected(self):
        plain = _public_only(self.host_key)
        with self.assertRaises(HostCertificateSignatureError):
            self._verify(plain)

    def test_verifier_requires_at_least_one_authority(self):
        with self.assertRaises(ValueError):
            HostCertificateVerifier([])

    def test_all_errors_derive_from_host_certificate_error(self):
        for exc in (
            HostCertificateTrustError,
            HostCertificateNameError,
            HostCertificateValidityError,
            HostCertificateSignatureError,
        ):
            self.assertTrue(issubclass(exc, HostCertificateError))

    def test_cert_kind_constants_match_openssh_values(self):
        from paramiko.host_certs import (
            SSH2_CERT_TYPE_HOST,
            SSH2_CERT_TYPE_USER,
        )

        self.assertEqual(HOST_CERT_KIND, SSH2_CERT_TYPE_HOST)
        self.assertEqual(USER_CERT_TYPE_KIND, SSH2_CERT_TYPE_USER)

    def test_public_key_file_loader_returns_verification_only_key(self):
        import tempfile
        from pathlib import Path

        pub_path = Path(tempfile.mkstemp(suffix=".pub")[1])
        pub_path.write_text(
            "ssh-ed25519 {}\n".format(
                self.ca_public.get_base64()
            )
        )
        loaded = paramiko.PKey.from_public_key_file(str(pub_path))
        self.assertFalse(loaded.can_sign())
        self.assertEqual(loaded.asbytes(), self.ca_public.asbytes())


class HostCertificateHandshakeTest(unittest.TestCase):
    """Full key-exchange handshakes over an in-process socket pair."""

    def setUp(self):
        self.ca = _new_ed25519()
        self.rogue_ca = _new_ed25519()
        self.client_key = _new_ed25519()
        self.ca_public = _public_only(self.ca)
        self.verifier = HostCertificateVerifier(
            HostCertificateAuthority(
                self.ca_public, hostnames=["*.example.com"]
            )
        )

    def _handshake(self, server_host_key, hostname=HOST_A, port=22,
                   verifier=None):
        server_sock, client_sock = socket.socketpair()
        server = _RecordingServer()

        def serve():
            transport = paramiko.Transport(server_sock)
            transport.add_server_key(server_host_key)
            transport.start_server(server.event, server)
            server.event.wait(5)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()

        client = SSHClient()
        client.set_missing_host_key_policy(RejectPolicy())
        outcome = {"error": None}
        try:
            client.connect(
                hostname,
                port=port,
                sock=client_sock,
                username="tester",
                pkey=self.client_key,
                look_for_keys=False,
                allow_agent=False,
                host_certificate_verifier=verifier or self.verifier,
            )
            outcome[
                "authenticated"
            ] = client.get_transport().is_authenticated()
        except HostCertificateError as error:
            outcome["error"] = error
        finally:
            client.close()
            server_sock.close()
        thread.join(timeout=5)
        outcome["auth_attempts"] = server.auth_attempts
        return outcome

    def test_trusted_ca_and_matching_host_completes_handshake(self):
        host_key = build_host_certificate(_new_ed25519(), self.ca, [HOST_A])
        outcome = self._handshake(host_key)
        self.assertIsNone(outcome["error"])
        self.assertTrue(outcome["authenticated"])

    def test_second_host_with_other_principal_fails(self):
        host_key = build_host_certificate(_new_ed25519(), self.ca, [HOST_B])
        outcome = self._handshake(host_key, hostname=HOST_A)
        self.assertIsInstance(outcome["error"], HostCertificateNameError)

    def test_user_certificate_used_as_host_key_fails(self):
        host_key = build_host_certificate(
            _new_ed25519(), self.ca, [HOST_A], kind=USER_CERT_TYPE_KIND
        )
        outcome = self._handshake(host_key)
        self.assertIsInstance(outcome["error"], HostCertificateNameError)

    def test_expired_host_certificate_fails(self):
        host_key = build_host_certificate(
            _new_ed25519(), self.ca, [HOST_A],
            valid_after=1000, valid_before=2000,
        )
        outcome = self._handshake(host_key)
        self.assertIsInstance(outcome["error"], HostCertificateValidityError)

    def test_self_appointed_ca_fails(self):
        host_key = build_host_certificate(
            _new_ed25519(), self.rogue_ca, [HOST_A]
        )
        outcome = self._handshake(host_key)
        self.assertIsInstance(outcome["error"], HostCertificateTrustError)

    def test_failure_occurs_before_user_authentication(self):
        host_key = build_host_certificate(
            _new_ed25519(), self.rogue_ca, [HOST_A]
        )
        outcome = self._handshake(host_key)
        self.assertIsInstance(outcome["error"], HostCertificateTrustError)
        # The server must never have been asked to authenticate the user.
        self.assertEqual(outcome["auth_attempts"], 0)

    def test_alias_outside_ca_range_cannot_bypass_scope(self):
        # A verifier scoped to HOST_A accepts the matching host but rejects a
        # connection whose raw connection name is an out-of-range alias, even
        # though the certificate principal and CA signature are otherwise
        # valid. The split between raw name and verification name is what
        # prevents the bypass.
        host_key = build_host_certificate(_new_ed25519(), self.ca, [HOST_A])
        verifier = HostCertificateVerifier(
            HostCertificateAuthority(self.ca_public, hostnames=[HOST_A])
        )
        verifier.verify_server_key(
            host_key, hostname=HOST_A, raw_hostname=HOST_A, port=22
        )
        with self.assertRaises(HostCertificateTrustError):
            verifier.verify_server_key(
                host_key,
                hostname=HOST_A,
                raw_hostname="alias.other.net",
                port=22,
            )

    def test_non_default_port_uses_bracketed_verification_name(self):
        host_key = build_host_certificate(
            _new_ed25519(), self.ca, ["[{}]:2222".format(HOST_A)]
        )
        verifier = HostCertificateVerifier(
            HostCertificateAuthority(
                self.ca_public, hostnames=[HOST_A], port=2222
            )
        )
        verifier.verify_server_key(
            host_key,
            hostname="[{}]:2222".format(HOST_A),
            raw_hostname=HOST_A,
            port=2222,
        )
        with self.assertRaises(HostCertificateTrustError):
            verifier.verify_server_key(
                host_key,
                hostname="[{}]:2222".format(HOST_A),
                raw_hostname=HOST_A,
                port=22,
            )

    def test_bare_key_known_hosts_still_works_without_verifier(self):
        host_key = _new_ed25519()  # no certificate attached
        server_sock, client_sock = socket.socketpair()
        server = _RecordingServer()

        def serve():
            transport = paramiko.Transport(server_sock)
            transport.add_server_key(host_key)
            transport.start_server(server.event, server)
            server.event.wait(5)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        client = SSHClient()
        client.get_host_keys().add(
            HOST_A, "ssh-ed25519", _public_only(host_key)
        )
        try:
            client.connect(
                HOST_A,
                sock=client_sock,
                username="tester",
                pkey=self.client_key,
                look_for_keys=False,
                allow_agent=False,
            )
            self.assertTrue(client.get_transport().is_authenticated())
        finally:
            client.close()
            server_sock.close()
        thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
