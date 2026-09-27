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
Client-side verification of OpenSSH host certificates.

This module implements the relying-party (client) side of OpenSSH public
key certificates as described in PROTOCOL.certkeys:

https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys

Only ``ssh-ed25519-cert-v01@openssh.com`` host certificates signed by
Ed25519 certificate authorities are supported.
"""

import fnmatch
import os
import struct
import time

from paramiko.message import Message
from paramiko.ssh_exception import HostCertificateError, SSHException

#: OpenSSH certificate type for user certificates (SSH_CERT_TYPE_USER).
CERT_TYPE_USER = 1
#: OpenSSH certificate type for host certificates (SSH_CERT_TYPE_HOST).
CERT_TYPE_HOST = 2
#: Certificate algorithm identifier suffix.
CERT_SUFFIX = "-cert-v01@openssh.com"
#: The only host certificate algorithm supported by this module.
ED25519_CERT_KEY_TYPE = "ssh-ed25519-cert-v01@openssh.com"


def _remaining(message):
    return len(message.asbytes()) - message.packet.tell()


class OpenSSHCertificate:
    """
    A parsed OpenSSH public key certificate.

    The certificate is parsed strictly per PROTOCOL.certkeys; no trust
    decisions are made here. Use `.HostCertificateVerifier` to validate
    a certificate against configured certificate authorities.
    """

    def __init__(self, blob):
        """
        Parse a certificate from its network/blob representation.

        :param bytes blob:
            the certificate blob (as found in a ``-cert.pub`` file or
            on the wire during key exchange).

        :raises .HostCertificateError:
            if the blob cannot be parsed as an OpenSSH certificate.
        """
        self.blob = blob
        try:
            self._parse(blob)
        except (IndexError, struct.error, UnicodeDecodeError) as e:
            raise HostCertificateError(
                "Unparseable host certificate: {}".format(e)
            )

    def _parse(self, blob):
        m = Message(blob)
        self.key_type = m.get_text()
        self.nonce = m.get_binary()
        # Key-type-specific public key material. Only Ed25519 certificates
        # are supported, where this is a single 32-byte string.
        if self.key_type != ED25519_CERT_KEY_TYPE:
            raise HostCertificateError(
                "Unsupported certificate type {!r}; only {!r} is "
                "supported".format(self.key_type, ED25519_CERT_KEY_TYPE)
            )
        self.public_key = m.get_binary()
        self.serial = m.get_int64()
        self.cert_type = m.get_int()
        self.key_id = m.get_text()
        principals = Message(m.get_binary())
        self.principals = []
        while _remaining(principals) > 0:
            self.principals.append(principals.get_text())
        self.valid_after = m.get_int64()
        self.valid_before = m.get_int64()
        self.critical_options = self._parse_name_data(m.get_binary())
        self.extensions = self._parse_name_data(m.get_binary())
        self.reserved = m.get_binary()
        self.signature_key = m.get_binary()
        # The signature is computed over all preceding fields, i.e. the
        # entire blob up to (but not including) the signature string.
        self.signed_data = blob[: m.packet.tell()]
        self.signature = m.get_binary()
        if _remaining(m) > 0:
            raise HostCertificateError(
                "Trailing data after certificate signature"
            )

    @staticmethod
    def _parse_name_data(data):
        result = {}
        m = Message(data)
        while _remaining(m) > 0:
            name = m.get_text()
            result[name] = m.get_binary()
        return result

    def __repr__(self):
        return (
            "OpenSSHCertificate(type={}, serial={}, principals={!r})".format(
                self.key_type, self.serial, self.principals
            )
        )


class HostCertificateVerifier:
    """
    Verifies OpenSSH host certificates against explicitly configured
    certificate authorities.

    Applications configure one or more trusted Ed25519 CA public keys
    (optionally restricted to a set of host patterns) and hand the
    verifier to `.SSHClient.set_host_certificate_verifier`. When a
    server subsequently presents a host certificate, the certificate -
    and only the certificate - is checked against this configuration;
    the CA keys are never added to any known-hosts style storage, and a
    certificate's embedded signature key is never trusted on its own.
    """

    def __init__(self, allow_wildcard_principals=False):
        """
        :param bool allow_wildcard_principals:
            whether certificates with an empty principal list (which
            OpenSSH treats as "valid for any host") are accepted.
            Defaults to ``False``, rejecting such certificates.
        """
        self.allow_wildcard_principals = allow_wildcard_principals
        self._ca_entries = []

    def add_ca_key(self, key, host_patterns=None):
        """
        Trust a certificate authority public key.

        :param key:
            an `.Ed25519Key`, a path to an OpenSSH ``.pub`` file, or
            a string containing one ``ssh-ed25519 ...`` public key
            line.
        :param host_patterns:
            optional iterable of host patterns (``*``/``?``
            wildcards, ``!`` prefix negates) limiting which target
            hostnames this CA may vouch for. ``None`` (the default)
            allows any host.

        :raises ValueError: if the key is not an Ed25519 public key.
        """
        from paramiko.ed25519key import Ed25519Key

        if isinstance(key, (str, os.PathLike)):
            key = self._load_ca_key(key)
        if not isinstance(key, Ed25519Key):
            raise ValueError(
                "Only Ed25519 certificate authorities are supported"
            )
        if key.public_blob is not None:
            raise ValueError(
                "CA keys must be plain public keys, not certificates"
            )
        patterns = None
        if host_patterns is not None:
            patterns = [str(pattern) for pattern in host_patterns]
        self._ca_entries.append((key, patterns))

    @staticmethod
    def _load_ca_key(value):
        from paramiko.ed25519key import Ed25519Key
        from paramiko.pkey import PublicBlob

        if os.path.isfile(value):
            blob = PublicBlob.from_file(value)
        else:
            blob = PublicBlob.from_string(str(value))
        return Ed25519Key(data=blob.key_blob)

    def verify(self, key, hostname, now=None):
        """
        Verify a host key certificate presented for ``hostname``.

        :param .PKey key:
            the host key object presented by the server, carrying a
            certificate in its ``public_blob``.
        :param str hostname:
            the target hostname (without any port decoration) the
            certificate must be valid for.
        :param float now:
            timestamp to validate against; defaults to the current time.

        :return: the parsed `.OpenSSHCertificate` on success.
        :raises .HostCertificateError: on any validation failure.
        """
        if now is None:
            now = time.time()
        public_blob = getattr(key, "public_blob", None)
        if public_blob is None or not public_blob.key_type.endswith(
            CERT_SUFFIX
        ):
            raise HostCertificateError(
                "Server did not present a host certificate"
            )
        cert = OpenSSHCertificate(public_blob.key_blob)
        self._check_cert_type(cert)
        self._check_critical_options(cert)
        self._check_validity_window(cert, now)
        self._check_principals(cert, hostname)
        ca_key = self._find_ca_key(cert, hostname)
        self._check_signature(cert, ca_key)
        return cert

    def _check_cert_type(self, cert):
        if cert.cert_type != CERT_TYPE_HOST:
            raise HostCertificateError(
                "Certificate is not a host certificate (type {})".format(
                    cert.cert_type
                )
            )

    def _check_critical_options(self, cert):
        # No critical options are defined for host certificates; any
        # present option is therefore unknown and must be rejected.
        if cert.critical_options:
            raise HostCertificateError(
                "Certificate has unknown critical options: {}".format(
                    ", ".join(sorted(cert.critical_options))
                )
            )

    def _check_validity_window(self, cert, now):
        if now < cert.valid_after:
            raise HostCertificateError("Certificate is not yet valid")
        if now >= cert.valid_before:
            raise HostCertificateError("Certificate has expired")

    def _check_principals(self, cert, hostname):
        if not cert.principals:
            if not self.allow_wildcard_principals:
                raise HostCertificateError(
                    "Certificate has an empty principal list"
                )
            return
        if hostname not in cert.principals:
            raise HostCertificateError(
                "Hostname {!r} is not a valid principal of the "
                "certificate".format(hostname)
            )

    def _find_ca_key(self, cert, hostname):
        try:
            signature_key_type = Message(cert.signature_key).get_text()
        except (SSHException, struct.error, UnicodeDecodeError):
            signature_key_type = None
        if signature_key_type != "ssh-ed25519":
            raise HostCertificateError(
                "Certificate signature key is not an Ed25519 key"
            )
        for ca_key, patterns in self._ca_entries:
            if ca_key.asbytes() != cert.signature_key:
                continue
            if patterns is not None and not self._host_matches(
                hostname, patterns
            ):
                continue
            return ca_key
        raise HostCertificateError(
            "Certificate was not signed by a trusted CA for host "
            "{!r}".format(hostname)
        )

    @staticmethod
    def _host_matches(hostname, patterns):
        hostname = hostname.lower()
        matched = False
        for pattern in patterns:
            negated = pattern.startswith("!")
            candidate = pattern[1:] if negated else pattern
            if fnmatch.fnmatchcase(hostname, candidate.lower()):
                if negated:
                    return False
                matched = True
        return matched

    def _check_signature(self, cert, ca_key):
        if not ca_key.verify_ssh_sig(
            cert.signed_data, Message(cert.signature)
        ):
            raise HostCertificateError(
                "Certificate signature verification failed"
            )
