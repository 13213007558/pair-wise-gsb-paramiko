"""
Host-certificate based SSH client example.

Unlike the classic ``known_hosts`` workflow, this client maintains *no*
per-machine bare public keys. It trusts a single OpenSSH host certificate
authority (CA) and declares the host name range that CA is allowed to vouch
for. Paramiko then enforces, on every connection, that the server presents a
valid host certificate:

* signed by the configured CA,
* of the *host* certificate type,
* naming the connected host among its principals,
* inside its validity window, and
* carrying no unrecognized critical options.

The only trust inputs here are the CA's public key and the host range -- there
is deliberately no per-host public key to maintain.

Usage::

    python host_certificate_client.py <host> [port]

Expects a PEM/OpenSSH-format CA *public* key path in ``HOST_CA_PUBLIC_KEY``
(defaults to ``./host_ca.pub``).
"""

import os
import sys

import paramiko
from paramiko import HostCertificateAuthority, HostCertificateVerifier
from paramiko.ssh_exception import HostCertificateError

# The hosts the CA is trusted for. Wildcards ("*", "?") and leading "!"
# negations are supported, mirroring OpenSSH host patterns. Narrow this to the
# real naming zone the operations team's CA is responsible for.
TRUSTED_HOST_RANGE = ["*.example.com"]


def build_verifier():
    ca_path = os.environ.get("HOST_CA_PUBLIC_KEY", "host_ca.pub")
    # A public key is sufficient -- no CA private material is ever needed to
    # verify a host certificate.
    ca_public_key = paramiko.PKey.from_public_key_file(ca_path)
    authority = HostCertificateAuthority(
        ca_public_key, hostnames=TRUSTED_HOST_RANGE
    )
    return HostCertificateVerifier(authority)


def connect(hostname, port=22, username=None):
    client = paramiko.SSHClient()
    verifier = build_verifier()
    # No load_system_host_keys() / load_host_keys() needed: the verifier fully
    # replaces the bare-key trust model for this connection.
    client.connect(
        hostname=hostname,
        port=port,
        username=username,
        host_certificate_verifier=verifier,
    )
    return client


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 1
    hostname = argv[1]
    port = int(argv[2]) if len(argv) > 2 else 22
    try:
        client = connect(hostname, port=port)
    except HostCertificateError as error:
        # The concrete subclass already tells you whether this was a trust,
        # name, validity or signature problem.
        print(
            "Host certificate verification failed ({}): {}".format(
                type(error).__name__, error
            )
        )
        return 2
    try:
        stdin, stdout, stderr = client.exec_command("whoami")
        print(stdout.read().decode().strip())
    finally:
        client.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
