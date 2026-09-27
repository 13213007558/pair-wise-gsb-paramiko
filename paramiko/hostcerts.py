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
Client-side verification of OpenSSH host certificates.

Only ``ssh-ed25519-cert-v01@openssh.com`` host certificates signed by
Ed25519 certificate authorities are supported, as described in
`PROTOCOL.certkeys
<https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys>`_.

Trust is configured explicitly by the application: one or more CA public
keys are registered on a `.HostCertificateVerifier`, each with the range of
hosts it is allowed to vouch for.  The signature key embedded in a
certificate is treated purely as untrusted input to be checked against that
configuration - it never becomes a trust root on its own.
"""

import time
from fnmatch import fnmatchcase

from paramiko.message import Message
from paramiko.ssh_exception import SSHException

ED25519_CERT_TYPE = "ssh-ed25519-cert-v01@openssh.com"
ED25519_KEY_TYPE = "ssh-ed25519"

#: Certificate type value for user certificates (not accepted as host keys).
CERT_TYPE_USER = 1
#: Certificate type value for host certificates.
CERT_TYPE_HOST = 2


class CertificateValidationError(SSHException):
    """
    Raised when an OpenSSH host certificate fails validation.

    This is a subclass of `.SSHException`, so existing error handling around
    `.SSHClient.connect` keeps working; certificate failures are, however,
    always fatal to the connection and never fall back to missing-host-key
    policies such as `.AutoAddPolicy`.
    """

    pass


class OpenSSHCertificate:
    """
    Parsed ``ssh-ed25519-cert-v01@openssh.com`` certificate blob.

    Parsing follows the format described in OpenSSH's
    ``PROTOCOL.certkeys``; only syntactic validation is performed here.
    Use `.HostCertificateVerifier` to actually verify a certificate against
    trusted CA keys, validity windows and target hostnames.
    """

    def __init__(self, blob):
        """
        Parse a certificate from its network/blob representation.

        :param bytes blob: the certificate blob (as sent during key exchange,
            or as the base64-decoded contents of a ``-cert.pub`` file)
        :raises CertificateValidationError: if the blob is malformed or is
            not an ``ssh-ed25519-cert-v01@openssh.com`` certificate
        """
        self._blob = blob
        msg = Message(blob)
        try:
            self.key_type = msg.get_text()
            if self.key_type != ED25519_CERT_TYPE:
                raise CertificateValidationError(
                    "Unsupported certificate type {!r} (only {} is "
                    "supported)".format(self.key_type, ED25519_CERT_TYPE)
                )
            self.nonce = msg.get_binary()
            self.public_key = msg.get_binary()
            self.serial = msg.get_int64()
            self.cert_type = msg.get_int()
            self.key_id = msg.get_text()
            self.principals = self._parse_string_list(msg.get_binary())
            self.valid_after = msg.get_int64()
            self.valid_before = msg.get_int64()
            self.critical_options = self._parse_options(msg.get_binary())
            self.extensions = self._parse_options(msg.get_binary())
            self.reserved = msg.get_binary()
            self.signature_key = msg.get_binary()
            # Everything up to and including the signature key is covered by
            # the CA signature.
            self.signed_data = blob[: len(msg.get_so_far())]
            self.signature = msg.get_binary()
            if msg.get_remainder():
                raise CertificateValidationError(
                    "Trailing data after certificate signature"
                )
        except CertificateValidationError:
            raise
        except Exception as e:
            raise CertificateValidationError(
                "Malformed certificate: {}".format(e)
            )

    @staticmethod
    def _parse_string_list(data):
        entries = []
        msg = Message(data)
        while msg.get_remainder():
            entries.append(msg.get_text())
        return entries

    @staticmethod
    def _parse_options(data):
        options = {}
        msg = Message(data)
        while msg.get_remainder():
            name = msg.get_text()
            value = msg.get_binary()
            options[name] = value
        return options

    @classmethod
    def from_key(cls, key):
        """
        Extract a certificate from a `.PKey` presenting one (i.e. a key
        whose ``public_blob`` is an
        ``ssh-ed25519-cert-v01@openssh.com`` blob).

        :raises CertificateValidationError: if the key does not carry such a
            certificate
        """
        blob = getattr(key, "public_blob", None)
        if blob is None or blob.key_type != ED25519_CERT_TYPE:
            raise CertificateValidationError(
                "Server did not present an {} host certificate".format(
                    ED25519_CERT_TYPE
                )
            )
        return cls(blob.key_blob)


class HostCertificateVerifier:
    """
    Verifies OpenSSH Ed25519 host certificates against explicitly configured
    certificate authorities.

    Each CA public key is registered together with the range of hosts it may
    vouch for (a list of ``fnmatch``-style patterns; entries prefixed with
    ``!`` are negated, as in OpenSSH pattern lists).  A certificate is
    only accepted when:

    - it is a host (not user) ``ssh-ed25519-cert-v01@openssh.com``
      certificate;
    - it carries no critical options (unknown critical options are rejected,
      per the protocol);
    - the current time is within its validity window;
    - the target hostname matches one of its principals (an empty principal
      list is rejected unless ``allow_wildcard_principals`` was enabled,
      in which case it is treated as a wildcard);
    - its signature key exactly matches a configured CA key whose host range
      covers the target hostname, and the CA signature verifies.

    .. versionadded:: 3.6
    """

    def __init__(self, allow_wildcard_principals=False):
        """
        :param bool allow_wildcard_principals: when ``True``, certificates
            with an empty principal list are treated as valid for any host.
            Defaults to ``False`` (empty principal lists are rejected).
        """
        self.allow_wildcard_principals = allow_wildcard_principals
        # list of (Ed25519Key, (pattern, ...))
        self._authorities = []

    def add_ca_key(self, key, host_patterns):
        """
        Trust an Ed25519 CA public key for a range of hosts.

        :param key: the CA public key (an `.Ed25519Key`; anything else is
            rejected, as only Ed25519 CAs are supported)
        :param host_patterns: iterable of ``fnmatch``-style patterns
            (e.g. ``["*.example.com", "bastion.example.com"]``) naming the
            hosts this CA may vouch for; ``!`-prefixed entries negate a
            match.  Must not be empty.
        """
        from paramiko.ed25519key import Ed25519Key

        if not isinstance(key, Ed25519Key):
            raise ValueError(
                "Only Ed25519 certificate authorities are supported"
            )
        patterns = tuple(host_patterns)
        if not patterns:
            raise ValueError(
                "host_patterns must name at least one host pattern"
            )
        self._authorities.append((key, patterns))

    def verify(self, key, hostname):
        """
        Verify the host certificate presented by a server.

        :param key: the `.PKey` the server presented during key exchange
            (e.g. ``Transport.get_remote_server_key()``)
        :param str hostname: the hostname (or IP) the client intended to
            connect to - matched against the certificate principals, without
            any port decoration
        :raises CertificateValidationError: on any validation failure
        """
        cert = OpenSSHCertificate.from_key(key)
        self._verify_cert(cert, hostname)

    def _verify_cert(self, cert, hostname):
        if cert.cert_type != CERT_TYPE_HOST:
            raise CertificateValidationError(
                "Certificate is not a host certificate (type {})".format(
                    cert.cert_type
                )
            )
        if cert.critical_options:
            raise CertificateValidationError(
                "Certificate contains unknown critical options: {}".format(
                    ", ".join(sorted(cert.critical_options))
                )
            )
        now = int(time.time())
        if now < cert.valid_after:
            raise CertificateValidationError(
                "Certificate is not yet valid (valid after {})".format(
                    cert.valid_after
                )
            )
        if now > cert.valid_before:
            raise CertificateValidationError(
                "Certificate has expired (valid before {})".format(
                    cert.valid_before
                )
            )
        self._verify_principals(cert, hostname)
        ca_key = self._find_ca_key(cert, hostname)
        if ca_key is None:
            raise CertificateValidationError(
                "Certificate was not signed by a trusted CA for host "
                "{!r}".format(hostname)
            )
        if not ca_key.verify_ssh_sig(
            cert.signed_data, Message(cert.signature)
        ):
            raise CertificateValidationError(
                "Certificate signature verification failed"
            )

    def _verify_principals(self, cert, hostname):
        if not cert.principals:
            if self.allow_wildcard_principals:
                return
            raise CertificateValidationError(
                "Certificate has an empty principal list"
            )
        for principal in cert.principals:
            if fnmatchcase(hostname, principal):
                return
        raise CertificateValidationError(
            "Hostname {!r} is not among the certificate principals {}".format(
                hostname, cert.principals
            )
        )

    def _find_ca_key(self, cert, hostname):
        for ca_key, patterns in self._authorities:
            if ca_key.asbytes() != cert.signature_key:
                continue
            if self._host_matches_patterns(hostname, patterns):
                return ca_key
        return None

    @staticmethod
    def _host_matches_patterns(hostname, patterns):
        matched = False
        for pattern in patterns:
            if pattern.startswith("!"):
                if fnmatchcase(hostname, pattern[1:]):
                    return False
            elif fnmatchcase(hostname, pattern):
                matched = True
        return matched
