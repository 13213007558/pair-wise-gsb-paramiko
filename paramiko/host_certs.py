# Copyright (C) 2026 Paramiko.io
#
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
# 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA.

"""
OpenSSH host certificate verification.

This module implements an *opt-in* trust model based on OpenSSH certificate
authorities (CAs), as described in
https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.certkeys .

Unlike the bare-key handling in `.hostkeys`, a caller does not provision one
entry per machine. Instead it configures one or more
`.HostCertificateAuthority` objects, each pairing a trusted CA public key
with the host name range (and, optionally, port) that CA is allowed to vouch
for. A
`.HostCertificateVerifier` then enforces, for every connection:

* the server actually presented a *host* certificate (not a user certificate);
* the certificate's principals match the name used for host verification;
* the current time is within the certificate's validity window;
* the certificate is signed by a CA that is trusted *for that host*;
* the certificate carries no unrecognized critical options.

The key the certificate certifies, and the signature key embedded in the
certificate itself, never establish trust on their own -- only an explicitly
configured CA can do that.
"""

import fnmatch
import time

from paramiko.message import Message
from paramiko.pkey import PKey
from paramiko.ssh_exception import (
    HostCertificateNameError,
    HostCertificateSignatureError,
    HostCertificateTrustError,
    HostCertificateValidityError,
)

#: Certificate type values defined by OpenSSH. Host certificates must carry
#: the host value; a user certificate (the other value) is never accepted as
#: proof of a server's identity.
SSH2_CERT_TYPE_USER = 1
SSH2_CERT_TYPE_HOST = 2

_CERT_SUFFIX = "-cert-v01@openssh.com"

#: Critical options a host certificate is permitted to carry. Any other
#: critical option is, per the OpenSSH spec, grounds for outright rejection.
#: Host certificates have no standardized critical options, so this is empty;
#: it exists to make the allow-listing behavior explicit and testable.
KNOWN_CRITICAL_OPTIONS = frozenset()


def _is_cert_type(key_type):
    return isinstance(key_type, str) and key_type.endswith(_CERT_SUFFIX)


def _base_key_type(key_type):
    if not _is_cert_type(key_type):
        return key_type
    base = key_type[: -len(_CERT_SUFFIX)]
    # RSA certificates are negotiated under the rsa-sha2 algorithm names, but
    # the certified key material is the classic ssh-rsa public key.
    if base in ("rsa-sha2-256", "rsa-sha2-512"):
        return "ssh-rsa"
    return base


def host_matches_pattern(name, pattern):
    """
    Return whether ``name`` matches a single OpenSSH-style host pattern.

    Supports shell wildcards (``*``, ``?`` and character classes). A leading
    ``!`` marks a *negated* pattern: this returns the underlying wildcard
    match (without applying the negation), leaving exclusion semantics to
    `.name_in_range`. A bare ``*`` matches any name.
    """
    if pattern is None:
        return False
    if pattern.startswith("!"):
        pattern = pattern[1:]
    return fnmatch.fnmatchcase(name, pattern)


def name_in_range(name, patterns):
    """
    Return whether ``name`` is accepted by a pattern list.

    The list follows OpenSSH semantics: patterns are evaluated in order. A
    matching negated pattern (``!foo``) excludes the name outright; otherwise
    at least one positive (non-negated) pattern must match. An empty list
    matches nothing (callers default to ``["*"]`` when they truly mean "any
    host").
    """
    matched = False
    for pattern in patterns:
        if not host_matches_pattern(name, pattern):
            continue
        if pattern.startswith("!"):
            return False
        matched = True
    return matched


def _read_name_list(section):
    """Parse a length-delimited section of concatenated name strings."""
    inner = Message(section)
    names = []
    while inner.get_remainder():
        names.append(inner.get_text())
    return names


def _read_name_value_pairs(section):
    """Parse a length-delimited section of ``(name, value-string)`` pairs."""
    inner = Message(section)
    pairs = []
    while inner.get_remainder():
        name = inner.get_text()
        # Per PROTOCOL.certkeys the value is doubly nested: an outer SSH
        # string whose contents are themselves an SSH string. Peel both
        # layers; an empty value (option merely "present") stays empty.
        outer = inner.get_binary()
        if outer:
            value = Message(outer).get_binary()
        else:
            value = b""
        pairs.append((name, value))
    return pairs


class HostCertificate:
    """
    Parsed contents of an OpenSSH ``*-cert-v01@openssh.com`` host certificate.

    Instances are produced by `.from_message` / `.from_key`; they are not
    normally constructed directly. All verification logic lives on
    `.HostCertificateAuthority` and `.HostCertificateVerifier`.
    """

    def __init__(
        self,
        cert_type,
        nonce,
        key,
        serial,
        cert_kind,
        key_id,
        valid_principals,
        valid_after,
        valid_before,
        critical_options,
        extensions,
        reserved,
        ca_key,
        signature,
        raw,
        signed_bytes,
    ):
        self.cert_type = cert_type
        self.nonce = nonce
        self.key = key
        self.serial = serial
        self.cert_kind = cert_kind
        self.key_id = key_id
        self.valid_principals = valid_principals
        self.valid_after = valid_after
        self.valid_before = valid_before
        self.critical_options = critical_options
        self.extensions = extensions
        self.reserved = reserved
        self.ca_key = ca_key
        self.signature = signature
        self.raw = raw
        self.signed_bytes = signed_bytes

    def __repr__(self):
        return "<HostCertificate type={} principals={!r} serial={}>".format(
            self.cert_type, self.valid_principals, self.serial
        )

    @classmethod
    def from_message(cls, message):
        """
        Parse a certificate from a network `.Message` (or raw blob bytes).

        :raises `.HostCertificateSignatureError`: if the blob is not a
            recognizable OpenSSH certificate.
        """
        if isinstance(message, (bytes, bytearray)):
            message = Message(bytes(message))
        start = message.packet.tell()
        cert_type = message.get_text()
        if not _is_cert_type(cert_type):
            raise HostCertificateSignatureError(
                "Server presented non-certificate host key {!r}; a host "
                "certificate is required".format(cert_type)
            )
        nonce = message.get_binary()

        # Rebuild the certified public key into the standalone type-prefixed
        # blob the key loaders consume. The on-disk field encoding differs by
        # family (see PROTOCOL.certkeys):
        #
        # * Ed25519 stores a single outer-length-prefixed raw 32-byte value;
        # * RSA stores the self-framed ``e`` and ``n`` mpint strings back to
        #   back, and ECDSA its curve-name and point strings back to back, in
        #   both cases with no enclosing length of their own.
        base_type = _base_key_type(cert_type)
        if base_type == "ssh-ed25519":
            key_blob = Message()
            key_blob.add_string(base_type)
            key_blob.add_string(message.get_binary())
        else:
            key_blob = Message()
            key_blob.add_string(base_type)
            if base_type == "ssh-rsa":
                key_blob.add_mpint(message.get_mpint())
                key_blob.add_mpint(message.get_mpint())
            else:
                # ECDSA: curve identifier string then public point string.
                key_blob.add_string(message.get_string())
                key_blob.add_string(message.get_string())
        key = PKey.from_type_string(base_type, key_blob.asbytes())

        serial = message.get_int64()
        cert_kind = message.get_int()
        key_id = message.get_text()

        # valid principals, critical options and extensions are each encoded as
        # a length-prefixed section whose contents are concatenated SSH
        # strings (name, plus a value string for the two maps), with *no*
        # separate count. The section's own length delimits the contents, so
        # parse until the inner stream is exhausted.
        valid_principals = _read_name_list(message.get_binary())

        valid_after = message.get_int64()
        valid_before = message.get_int64()

        critical_options = {}
        for name, value in _read_name_value_pairs(message.get_binary()):
            # An empty value marks an option/extension that is merely present.
            critical_options[name] = value

        extensions = {}
        for name, value in _read_name_value_pairs(message.get_binary()):
            extensions[name] = value

        reserved = message.get_binary()
        ca_key = None
        try:
            ca_key_blob = message.get_binary()
            ca_type = Message(ca_key_blob).get_text()
            ca_key = PKey.from_type_string(ca_type, ca_key_blob)
        except Exception:
            # A malformed embedded CA key simply cannot validate anything;
            # trust is decided by configured CAs, never by this field.
            ca_key = None

        # The CA signature covers the entire certificate up to and including
        # the CA key, but not the signature field that follows.
        signed_end = message.packet.tell()
        signature = message.get_binary()

        message.rewind()
        signed_bytes = message.get_bytes(signed_end - start)

        return cls(
            cert_type=cert_type,
            nonce=nonce,
            key=key,
            serial=serial,
            cert_kind=cert_kind,
            key_id=key_id,
            valid_principals=valid_principals,
            valid_after=valid_after,
            valid_before=valid_before,
            critical_options=critical_options,
            extensions=extensions,
            reserved=reserved,
            ca_key=ca_key,
            signature=signature,
            raw=message.asbytes(),
            signed_bytes=signed_bytes,
        )

    @classmethod
    def from_key(cls, server_key):
        """
        Extract a certificate from a host `.PKey` received during key exchange.

        The key classes stash the original certificate blob (when the server
        offers a ``*-cert-*`` algorithm) on ``public_blob``.

        :raises `.HostCertificateSignatureError`: if the key carries no
            certificate.
        """
        blob = getattr(server_key, "public_blob", None)
        if blob is None or not _is_cert_type(getattr(blob, "key_type", "")):
            raise HostCertificateSignatureError(
                "Server host key {!r} is not an OpenSSH certificate".format(
                    server_key.get_name()
                )
            )
        return cls.from_message(blob.key_blob)

    def is_host_certificate(self):
        return self.cert_kind == SSH2_CERT_TYPE_HOST

    def principal_matches(self, name):
        """Return whether ``name`` is an authorized principal."""
        if not self.valid_principals:
            # An empty principal list means "no restriction" in OpenSSH; for
            # host certs that still has to match the requested name, and a
            # wildcard principal is how CAs normally express "any host".
            return False
        for principal in self.valid_principals:
            # A bracketed [host]:port principal is compared literally so the
            # square brackets are not mistaken for fnmatch character classes.
            if principal.startswith("[") or name.startswith("["):
                if principal == name:
                    return True
            elif fnmatch.fnmatchcase(name, principal):
                return True
        return False

    def is_valid_at(self, now):
        return self.valid_after <= now < self.valid_before


class HostCertificateAuthority:
    """
    A trusted host certificate authority plus the host range it may cover.

    Trust is two-dimensional: the CA's public key must validate the
    certificate's signature *and* the connected host must fall within the
    configured ``hostnames`` range (optionally constrained to a single
    ``port``). A CA trusted for ``db-*`` cannot be used to authenticate
    ``bastion`` even if it happens to hold a technically valid certificate for
    it.

    :param .PKey ca_key: the CA's *public* key (private material is never
        needed for verification).
    :param hostnames: host name pattern(s) this CA is trusted for. Supports
        ``*``/``?`` wildcards and leading ``!`` negation; defaults to
        ``["*"]``.
    :param int port: optional port restriction. When given, the authority only
        applies to the bracketed ``[host]:port`` verification name.
    """

    def __init__(self, ca_key, hostnames=None, port=None):
        if not isinstance(ca_key, PKey):
            raise TypeError("ca_key must be a paramiko PKey instance")
        # Verification only ever uses the public/verifying half; private keys
        # are accepted for convenience since verify_ssh_sig works on both.
        self.ca_key = ca_key
        if hostnames is None:
            hostnames = ["*"]
        if isinstance(hostnames, str):
            hostnames = [hostnames]
        self.hostnames = list(hostnames)
        if port is not None and not (0 < int(port) < 65536):
            raise ValueError("port must be between 1 and 65535")
        self.port = None if port is None else int(port)

    def __repr__(self):
        return "<HostCertificateAuthority key={} hosts={!r} port={}>".format(
            self.ca_key.get_name(), self.hostnames, self.port
        )

    def covers(self, hostname, port=None):
        """
        Return whether this authority is allowed to vouch for ``hostname``.

        ``hostname`` is the raw host name; the optional ``port`` participates
        when the authority was created with a port restriction.
        """
        if self.port is not None and port != self.port:
            return False
        return name_in_range(hostname, self.hostnames)

    def verify(self, certificate, principal_name, port=None, now=None):
        """
        Validate ``certificate`` against this authority.

        ``principal_name`` is the name the certificate must authorize (the
        host-key verification name, bracketed with the port for non-default
        ports). The authority's configured host range is enforced separately
        by `.covers` against the raw connection name before this is called.

        :raises `.HostCertificateNameError`: wrong certificate type or
            principal.
        :raises `.HostCertificateValidityError`: outside the validity window.
        :raises `.HostCertificateSignatureError`: unknown critical option.
        :raises `.HostCertificateTrustError`: a CA signature that does not
            verify.
        :return: the validated `.HostCertificate` on success.
        """
        if not certificate.is_host_certificate():
            raise HostCertificateNameError(
                "Certificate serial {} is not a host certificate (cert type "
                "{})".format(certificate.serial, certificate.cert_kind)
            )

        if not certificate.principal_matches(principal_name):
            raise HostCertificateNameError(
                "Host {!r} is not among the certificate's valid principals "
                "{!r}".format(principal_name, certificate.valid_principals)
            )

        if now is None:
            now = int(time.time())
        if not certificate.is_valid_at(now):
            raise HostCertificateValidityError(
                "Certificate serial {} is not valid at {} "
                "(window {}..{})".format(
                    certificate.serial,
                    now,
                    certificate.valid_after,
                    certificate.valid_before,
                )
            )

        unknown = sorted(
            set(certificate.critical_options) - set(KNOWN_CRITICAL_OPTIONS)
        )
        if unknown:
            raise HostCertificateSignatureError(
                "Certificate serial {} carries unrecognized critical "
                "option(s) {!r} which must cause rejection".format(
                    certificate.serial, unknown
                )
            )

        if not self._signature_valid(certificate):
            # The configured CA did not sign this certificate, so it cannot be
            # trusted via this anchor (distinct from a broken SSH handshake).
            raise HostCertificateTrustError(
                "Certificate serial {} was not signed by trusted CA {}".format(
                    certificate.serial, self.ca_key.get_name()
                )
            )
        return certificate

    def _signature_valid(self, certificate):
        try:
            return self.ca_key.verify_ssh_sig(
                certificate.signed_bytes, Message(certificate.signature)
            )
        except Exception:
            return False


class HostCertificateVerifier:
    """
    Entry point for explicit host-certificate verification.

    Configure one with the `.HostCertificateAuthority` object(s) the
    application trusts, then hand it to `.SSHClient.connect` (or call
    `.verify_server_key` directly). Verification always runs *after* the SSH
    key-exchange handshake signature has been checked but *before* any user
    authentication material is sent.
    """

    def __init__(self, authorities):
        if isinstance(authorities, HostCertificateAuthority):
            authorities = [authorities]
        authorities = list(authorities)
        if not authorities:
            raise ValueError(
                "HostCertificateVerifier requires at least one "
                "HostCertificateAuthority"
            )
        self.authorities = authorities

    def __repr__(self):
        return "<HostCertificateVerifier authorities={}>".format(
            len(self.authorities)
        )

    def verify_server_key(
        self, server_key, hostname, raw_hostname=None, port=None, now=None
    ):
        """
        Verify a key-exchange host key against the configured authorities.

        :param .PKey server_key: the key returned by
            `.Transport.get_remote_server_key`.
        :param str hostname: the name used for host-key verification, i.e. the
            certificate principal to match. For a non-default port the caller
            passes the bracketed ``[host]:port`` form, mirroring
            ``known_hosts`` semantics.
        :param str raw_hostname: the actual host name the TCP connection was
            made to, used for the configured CA host-range check. Defaults to
            ``hostname`` with any ``[host]:port`` bracketing stripped. Keeping
            this distinct from ``hostname`` means a configured range cannot be
            bypassed by connecting under a different alias.
        :param int port: the TCP port, used for port-scoped authorities.
        :param int now: override for the current epoch time (testing).
        :raises `.HostCertificateError`: on any verification failure.
        """
        if raw_hostname is None:
            raw_hostname = hostname
            if raw_hostname.startswith("[") and "]:" in raw_hostname:
                raw_hostname = raw_hostname[1:].split("]:", 1)[0]
        certificate = HostCertificate.from_key(server_key)

        # The trust anchor's configured range is checked against the real
        # connection name (and port), not the principal-matching alias.
        in_scope = [
            authority
            for authority in self.authorities
            if authority.covers(raw_hostname, port=port)
        ]
        if not in_scope:
            raise HostCertificateTrustError(
                "No configured host certificate authority is trusted for "
                "host {!r} (port {})".format(raw_hostname, port)
            )

        # Hard, content-level failures (wrong cert type, principal, validity
        # window, or an unrecognized critical option) are identical regardless
        # of which in-scope CA we ask, so surface the first one directly.
        # Signature mismatches instead mean "this CA doesn't vouch for it" and
        # are accumulated in case another in-scope CA does.
        trust_failures = []
        for authority in in_scope:
            try:
                return authority.verify(
                    certificate, hostname, port=port, now=now
                )
            except HostCertificateTrustError as error:
                trust_failures.append(str(error))
        if trust_failures:
            raise HostCertificateTrustError(
                "No configured host certificate authority produced a valid "
                "signature for host {!r}: {}".format(
                    hostname, "; ".join(trust_failures)
                )
            )
        # Unreachable in practice; verify() always raises or returns.
        raise HostCertificateTrustError(
            "Unable to verify host certificate for {!r}".format(hostname)
        )
