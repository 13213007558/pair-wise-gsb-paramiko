import logging
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from paramiko import Message, RSAKey
from paramiko.common import byte_chr
from paramiko.ssh_exception import SSHException

from ._util import server
from paramiko.agent import (
    SESSION_BIND_EXTENSION,
    SSH_AGENT_FAILURE,
    SSH_AGENT_SUCCESS,
    SSH2_AGENT_IDENTITIES_ANSWER,
    SSH2_AGENT_SIGN_RESPONSE,
    Agent,
    AgentClientProxy,
    cSSH2_AGENTC_EXTENSION,
    cSSH2_AGENTC_REQUEST_IDENTITIES,
    cSSH2_AGENTC_SIGN_REQUEST,
    _read_agent_message,
    _write_agent_message,
)


class MemoryAgent(threading.Thread):
    def __init__(
        self, response=SSH_AGENT_SUCCESS, disconnect_after_bind=False
    ):
        super().__init__(daemon=True)
        self.local, self.remote = socket.socketpair()
        self.response = response
        self.disconnect_after_bind = disconnect_after_bind
        self.messages = []
        self.bindings = []
        self.signature_requests = 0
        self._ready = threading.Event()

    def run(self):
        self._ready.set()
        while True:
            try:
                ptype, msg = _read_agent_message(self.local)
            except (OSError, SSHException):
                return
            self.messages.append(ptype)
            if ptype == ord(cSSH2_AGENTC_EXTENSION):
                name = msg.get_text()
                host_blob = msg.get_binary()
                session_id = msg.get_binary()
                signature = msg.get_binary()
                host_key = RSAKey(data=host_blob)
                host_key.verify_ssh_sig(session_id, Message(signature))
                self.bindings.append(
                    {
                        "extension": name,
                        "host_key": host_key,
                        "session_id": session_id,
                    }
                )
                if self.disconnect_after_bind:
                    self.local.close()
                    return
                reply = Message()
                reply.add_byte(byte_chr(self.response))
                _write_agent_message(self.local, reply)
            elif ptype == ord(cSSH2_AGENTC_SIGN_REQUEST):
                self.signature_requests += 1
                msg.get_binary()
                msg.get_binary()
                msg.get_int()
                reply = Message()
                reply.add_byte(byte_chr(SSH2_AGENT_SIGN_RESPONSE))
                reply.add_string(b"signature")
                _write_agent_message(self.local, reply)
            elif ptype == ord(cSSH2_AGENTC_REQUEST_IDENTITIES):
                reply = Message()
                reply.add_byte(byte_chr(SSH2_AGENT_IDENTITIES_ANSWER))
                reply.add_int(0)
                _write_agent_message(self.local, reply)
            else:
                reply = Message()
                reply.add_byte(byte_chr(SSH_AGENT_FAILURE))
                _write_agent_message(self.local, reply)


class FakeTransport:
    def __init__(self, key, session_id):
        self.key = key
        self.session_id = session_id

    def get_agent_session_binding(self):
        return SimpleNamespace(
            host_key=self.key.asbytes(),
            session_id=self.session_id,
            handshake_signature=self.key.sign_ssh_data(
                self.session_id, "rsa-sha2-512"
            ),
        )


class FakeChannel:
    def __init__(self, transport, sock, chanid):
        self.transport = transport
        self.sock = sock
        self.chanid = chanid
        self.closed = False

    def get_transport(self):
        return self.transport

    def get_id(self):
        return self.chanid

    def close(self):
        if not self.closed:
            self.closed = True
            self.sock.close()

    def shutdown(self, how):
        pass

    def send(self, data):
        return self.sock.send(data)

    def recv(self, size):
        return self.sock.recv(size)

    def fileno(self):
        return self.sock.fileno()


def start_proxy(channel, agent_socket, strict, monkeypatch, proxies):
    monkeypatch.setattr(
        "paramiko.agent.get_agent_connection", lambda: agent_socket
    )
    proxy = AgentClientProxy(channel, strict_session_bind=strict)
    proxies.append(proxy)
    return proxy


def wait_bindings(agent, count):
    for _ in range(100):
        if len(agent.bindings) >= count:
            return
        time.sleep(0.01)
    assert len(agent.bindings) == count


def read_frame(sock):
    sock.settimeout(1)
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            return None
        header += chunk
    size = struct.unpack(">I", header)[0]
    payload = b""
    while len(payload) < size:
        chunk = sock.recv(size - len(payload))
        if not chunk:
            return None
        payload += chunk
    return payload


def sign_request(key):
    request = Message()
    request.add_byte(cSSH2_AGENTC_SIGN_REQUEST)
    request.add_string(key.asbytes())
    request.add_string(b"authentication-request")
    request.add_int(0)
    return request


def test_multi_hop_forwarding_binds_each_session(monkeypatch):
    keys = [RSAKey.generate(2048) for _ in range(2)]
    sessions = [b"first-session-id", b"second-session-id"]
    proxies = []
    terminal_agent = MemoryAgent()
    terminal_agent.start()
    terminal_agent._ready.wait(1)

    hop_a_local, hop_a_remote = socket.socketpair()
    hop_b_local, hop_b_remote = socket.socketpair()
    hop_a_channel = FakeChannel(
        FakeTransport(keys[0], sessions[0]), hop_a_local, 30
    )
    hop_b_channel = FakeChannel(
        FakeTransport(keys[1], sessions[1]), hop_b_local, 40
    )
    start_proxy(hop_a_channel, hop_b_remote, False, monkeypatch, proxies)
    start_proxy(
        hop_b_channel,
        terminal_agent.remote,
        False,
        monkeypatch,
        proxies,
    )

    _write_agent_message(hop_a_remote, sign_request(keys[0]))
    wait_bindings(terminal_agent, 2)
    response = read_frame(hop_a_remote)
    assert response[0] == SSH2_AGENT_SIGN_RESPONSE
    assert Message(response[1:]).get_binary() == b"signature"

    assert terminal_agent.signature_requests == 1
    assert terminal_agent.messages == [
        ord(cSSH2_AGENTC_EXTENSION),
        ord(cSSH2_AGENTC_EXTENSION),
        ord(cSSH2_AGENTC_SIGN_REQUEST),
    ]
    assert [
        binding["extension"] for binding in terminal_agent.bindings
    ] == [SESSION_BIND_EXTENSION, SESSION_BIND_EXTENSION]
    assert {binding["host_key"] for binding in terminal_agent.bindings} == set(
        keys
    )
    assert {
        binding["session_id"] for binding in terminal_agent.bindings
    } == set(sessions)

    for proxy in proxies:
        proxy.close()
    hop_a_channel.close()
    hop_b_channel.close()
    hop_a_remote.close()
    hop_b_remote.close()
    terminal_agent.local.close()


@pytest.mark.parametrize("response", [SSH_AGENT_FAILURE, 28])
def test_strict_binding_failure_sends_failure_and_disconnects(
    monkeypatch, response
):
    key = RSAKey.generate(2048)
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(
        FakeTransport(key, b"strict-session"), agent_side, 11
    )
    agent = MemoryAgent(response=response)
    agent.start()
    agent._ready.wait(1)
    proxies = []
    start_proxy(channel, agent.remote, True, monkeypatch, proxies)

    assert read_frame(remote) == bytes([SSH_AGENT_FAILURE])
    time.sleep(0.01)
    assert channel.closed is True
    wait_bindings(agent, 1)
    assert agent.signature_requests == 0

    with pytest.raises(OSError):
        _write_agent_message(remote, sign_request(key))
    assert agent.signature_requests == 0

    proxies[0].close()
    channel.close()
    agent.local.close()
    agent_side.close()


def test_strict_binding_disconnect_blocks_signatures(monkeypatch):
    key = RSAKey.generate(2048)
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(
        FakeTransport(key, b"disconnect-session"), agent_side, 12
    )
    agent = MemoryAgent(disconnect_after_bind=True)
    agent.start()
    agent._ready.wait(1)
    proxies = []
    start_proxy(channel, agent.remote, True, monkeypatch, proxies)

    assert read_frame(remote) == bytes([SSH_AGENT_FAILURE])
    time.sleep(0.01)
    assert channel.closed is True
    wait_bindings(agent, 1)
    assert agent.signature_requests == 0

    proxies[0].close()
    channel.close()
    agent_side.close()


def test_strict_mode_without_session_binding_rejects_before_signature(
    monkeypatch,
):
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(None, agent_side, 15)
    agent = MemoryAgent()
    agent.start()
    agent._ready.wait(1)
    proxies = []
    start_proxy(channel, agent.remote, True, monkeypatch, proxies)

    assert read_frame(remote) == bytes([SSH_AGENT_FAILURE])
    time.sleep(0.01)
    assert channel.closed is True
    assert agent.messages == []
    assert agent.signature_requests == 0

    proxies[0].close()
    agent.local.close()
    agent_side.close()


def test_strict_mode_without_agent_rejects_before_signature(monkeypatch):
    remote, agent_side = socket.socketpair()
    key = RSAKey.generate(2048)
    channel = FakeChannel(
        FakeTransport(key, b"no-agent-session"), agent_side, 17
    )
    monkeypatch.setattr("paramiko.agent.get_agent_connection", lambda: None)
    AgentClientProxy(channel, strict_session_bind=True)

    assert read_frame(remote) == bytes([SSH_AGENT_FAILURE])
    time.sleep(0.01)
    assert channel.closed is True
    with pytest.raises(OSError):
        _write_agent_message(remote, sign_request(key))

    agent_side.close()


def test_lenient_binding_failure_preserves_unbound_forwarding(monkeypatch):
    key = RSAKey.generate(2048)
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(
        FakeTransport(key, b"lenient-session"), agent_side, 13
    )
    agent = MemoryAgent(response=28)
    agent.start()
    agent._ready.wait(1)
    proxies = []
    start_proxy(channel, agent.remote, False, monkeypatch, proxies)
    wait_bindings(agent, 1)

    _write_agent_message(remote, sign_request(key))
    assert read_frame(remote)[0] == SSH2_AGENT_SIGN_RESPONSE
    assert agent.messages == [
        ord(cSSH2_AGENTC_EXTENSION),
        ord(cSSH2_AGENTC_SIGN_REQUEST),
    ]
    assert agent.signature_requests == 1

    proxies[0].close()
    channel.close()
    agent.local.close()
    agent_side.close()


def test_lenient_mode_without_session_binding_preserves_legacy_behavior(
    monkeypatch,
):
    key = RSAKey.generate(2048)
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(None, agent_side, 16)
    agent = MemoryAgent(response=28)
    agent.start()
    agent._ready.wait(1)
    proxies = []
    start_proxy(channel, agent.remote, False, monkeypatch, proxies)

    _write_agent_message(remote, sign_request(key))
    assert read_frame(remote)[0] == SSH2_AGENT_SIGN_RESPONSE
    assert agent.bindings == []
    assert agent.messages == [ord(cSSH2_AGENTC_SIGN_REQUEST)]

    proxies[0].close()
    agent.local.close()
    agent_side.close()


def test_local_agent_authentication_does_not_bind(monkeypatch):
    memory_agent = MemoryAgent()
    memory_agent.start()
    memory_agent._ready.wait(1)
    monkeypatch.setattr(
        "paramiko.agent.get_agent_connection", lambda: memory_agent.remote
    )

    agent = Agent()
    assert agent.get_keys() == ()
    agent.close()
    assert memory_agent.bindings == []
    memory_agent.local.close()


def test_transport_binding_uses_initial_kex_and_survives_rekey():
    with server() as (client, peer):
        binding = client.get_agent_session_binding()
        host_key = client.get_remote_server_key()

        assert binding.host_key == client.get_remote_server_key().asbytes()
        assert binding.session_id == client.session_id
        assert host_key.verify_ssh_sig(
            binding.session_id, Message(binding.handshake_signature)
        )
        assert peer.get_agent_session_binding() is None

        initial = (
            binding.host_key,
            binding.session_id,
            bytes(binding.handshake_signature),
        )
        client.packetizer.REKEY_BYTES = 16384
        channel = client.open_session()
        channel.exec_command("yes")
        forwarded = peer.accept(1)
        for _ in range(20):
            channel.send(b"x" * 1024)
        for _ in range(50):
            if client.H != client.session_id:
                break
            time.sleep(0.05)

        assert client.H != client.session_id
        rebound = client.get_agent_session_binding()
        assert (
            rebound.host_key,
            rebound.session_id,
            bytes(rebound.handshake_signature),
        ) == initial

        channel.close()
        forwarded.close()


def test_binding_logs_only_result_and_channel_id(monkeypatch, caplog):
    key = RSAKey.generate(2048)
    session_id = b"logged-session"
    signature = key.sign_ssh_data(session_id, "rsa-sha2-512")
    remote, agent_side = socket.socketpair()
    channel = FakeChannel(FakeTransport(key, session_id), agent_side, 14)
    agent = MemoryAgent()
    agent.start()
    agent._ready.wait(1)
    proxies = []
    with caplog.at_level(logging.DEBUG, logger="paramiko.agent"):
        start_proxy(channel, agent.remote, True, monkeypatch, proxies)
        wait_bindings(agent, 1)

    assert "session binding succeeded on channel 14" in caplog.text
    assert session_id.decode() not in caplog.text
    assert repr(key.asbytes()) not in caplog.text
    assert repr(bytes(signature)) not in caplog.text

    proxies[0].close()
    channel.close()
    agent.local.close()
    agent_side.close()
