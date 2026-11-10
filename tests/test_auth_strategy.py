"""
Tests for `.AuthStrategy` source iteration and result classification.

These pin down the distinction between a rejected factor, a partially
accepted factor (server wants more), and a genuinely completed
authentication, including two-factor flows driven through real
client/server `.Transport` pairs wired together with in-memory loop
sockets (no network involved).
"""

import threading
from unittest.mock import Mock

import pytest

from paramiko import (
    AUTH_FAILED,
    AUTH_PARTIALLY_SUCCESSFUL,
    AUTH_SUCCESSFUL,
    AuthFailure,
    AuthResult,
    AuthStrategy,
    Ed25519Key,
    InMemoryPrivateKey,
    Password,
    RSAKey,
    ServerInterface,
    SSHClient,
    Transport,
)
from paramiko.ssh_exception import (
    AuthenticationException,
    PartialAuthentication,
)

from ._loop import LoopSocket
from ._util import TestServer, _support


class _ListStrategy(AuthStrategy):
    """Strategy whose sources are supplied up front (as a list)."""

    def __init__(self, sources):
        super().__init__(ssh_config=None)
        self._sources = sources

    def get_sources(self):
        yield from self._sources


class _RecordingStrategy(AuthStrategy):
    """Strategy yielding fresh sources on every call to get_sources()."""

    def __init__(self, factory):
        super().__init__(ssh_config=None)
        self.factory = factory
        self.calls = 0

    def get_sources(self):
        self.calls += 1
        yield from self.factory()


def _loopback_transports(server=None):
    socks = LoopSocket()
    sockc = LoopSocket()
    sockc.link(socks)
    tc = Transport(sockc)
    ts = Transport(socks)
    ts.add_server_key(RSAKey.from_private_key_file(_support("rsa.key")))
    event = threading.Event()
    ts.start_server(event, server or TestServer())
    # Start the client side (key exchange) without authenticating yet; this
    # lets the server thread finish negotiation and signal the event.
    tc.connect()
    event.wait(1.0)
    assert event.is_set()
    assert tc.is_active()
    assert ts.is_active()
    return tc, ts, socks, sockc


class TestTwoFactorProtocol:
    """
    End-to-end behavior against the in-memory protocol test server.

    The ``paranoid`` user on `.TestServer` requires publickey *then*
    password: the first factor returns ``AUTH_PARTIALLY_SUCCESSFUL`` and
    only the combination completes authentication.
    """

    def setup_method(self):
        self.key = Ed25519Key.from_private_key_file(_support("ed25519.key"))

    def test_partial_pubkey_then_password_success_opens_session(self):
        tc, ts, socks, sockc = _loopback_transports()
        try:
            assert not tc.is_authenticated()
            strategy = _ListStrategy(
                [
                    InMemoryPrivateKey("paranoid", self.key),
                    Password("paranoid", lambda: "paranoid"),
                ]
            )
            result = strategy.authenticate(tc)
            # First factor recorded as partial (remaining methods list),
            # second as real success (empty list rendered as 'success').
            assert isinstance(result, AuthResult)
            assert len(result) == 2
            assert result[0].result == ["password"]
            assert result[1].result == []
            assert tc.is_authenticated()
            # Only a fully authenticated transport may open a session.
            chan = tc.open_session()
            assert chan is not None
            chan.close()
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_partial_pubkey_then_bad_password_raises_explained_failure(self):
        tc, ts, socks, sockc = _loopback_transports()
        try:
            strategy = _ListStrategy(
                [
                    InMemoryPrivateKey("paranoid", self.key),
                    Password("paranoid", lambda: "not-the-password"),
                ]
            )
            with pytest.raises(AuthFailure) as info:
                strategy.authenticate(tc)
            # No session can be opened on an unauthenticated transport.
            assert not tc.is_authenticated()
            result = info.value.result
            assert isinstance(result, AuthResult)
            # Full attempt history preserved for diagnostics: the accepted
            # pubkey factor plus the rejected password factor.
            assert len(result) == 2
            assert isinstance(result[0].source, InMemoryPrivateKey)
            assert result[0].result == ["password"]
            assert isinstance(result[1].source, Password)
            assert isinstance(result[1].result, AuthenticationException)
            rendered = str(info.value)
            assert "InMemoryPrivateKey" in rendered
            assert "password" in rendered
            assert "Password" in rendered
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_password_getter_not_called_before_pubkey_factor_runs(self):
        tc, ts, socks, sockc = _loopback_transports()
        try:
            calls = []

            def get_password():
                calls.append("called")
                return "paranoid"

            strategy = _ListStrategy(
                [
                    InMemoryPrivateKey("paranoid", self.key),
                    Password("paranoid", get_password),
                ]
            )
            strategy.authenticate(tc)
            # Lazily fetched exactly once, and only when its source was
            # actually reached after the partial pubkey result.
            assert calls == ["called"]
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_sources_after_completion_are_never_touched(self):
        tc, ts, socks, sockc = _loopback_transports()
        try:
            untouched = Mock()
            untouched.authenticate = Mock(
                side_effect=AssertionError("must not run after success")
            )
            strategy = _ListStrategy(
                [
                    InMemoryPrivateKey("paranoid", self.key),
                    Password("paranoid", lambda: "paranoid"),
                    untouched,
                ]
            )
            result = strategy.authenticate(tc)
            assert len(result) == 2
            untouched.authenticate.assert_not_called()
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()

    def test_legacy_client_connect_also_completes_same_two_factor_flow(self):
        # Parity check: old SSHClient._auth handles the same server responses
        # via the return-value-of-auth-methods contract.
        tc, ts, socks, sockc = _loopback_transports()
        client = SSHClient()
        try:
            client._transport = tc
            client._auth(
                username="paranoid",
                password="paranoid",
                pkey=self.key,
                key_filenames=[],
                allow_agent=False,
                look_for_keys=False,
                passphrase=None,
            )
            assert tc.is_authenticated()
            chan = tc.open_session()
            assert chan is not None
            chan.close()
        finally:
            client.close()
            ts.close()
            socks.close()
            sockc.close()


class _ChameleonServer(ServerInterface):
    """
    Server whose advertised remaining methods change between attempts.

    The publickey factor is partially accepted with ``password`` offered;
    the password factor is then rejected while the server advertises a
    *different* method list than the one returned after the first factor.
    """

    def get_allowed_auths(self, username):
        if self.phase < 2:
            return "publickey,password"
        return "publickey,keyboard-interactive"

    def check_auth_publickey(self, username, key):
        self.phase = 1
        return AUTH_PARTIALLY_SUCCESSFUL

    def check_auth_password(self, username, password):
        self.phase = 2
        return AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return AUTH_SUCCESSFUL

    def __init__(self):
        self.phase = 0


class TestResultClassification:
    def test_partial_success_without_exception_is_not_final_success(self):
        # A source that returns the "remaining methods" list directly (as
        # Transport auth methods do for partial auth) must not be treated as
        # a completed login merely because it did not raise.
        source = Mock()
        source.authenticate.return_value = ["password"]
        strategy = _ListStrategy([source])
        transport = Mock()
        with pytest.raises(AuthFailure) as info:
            strategy.authenticate(transport)
        assert info.value.result[0].result == ["password"]
        transport.is_authenticated.assert_not_called()

    def test_partial_authentication_exception_continues_to_next_source(self):
        first = Mock()
        first.authenticate.side_effect = PartialAuthentication(
            ["password"]
        )
        second = Mock()
        second.authenticate.return_value = []
        strategy = _ListStrategy([first, second])
        result = strategy.authenticate(Mock())
        assert len(result) == 2
        # The partial factor is recorded with its remaining-method list, not
        # the exception object.
        assert result[0].result == ["password"]
        assert result[1].result == []
        second.authenticate.assert_called_once()

    def test_real_success_is_empty_list_and_short_circuits(self):
        first = Mock()
        first.authenticate.return_value = []
        second = Mock()
        strategy = _ListStrategy([first, second])
        result = strategy.authenticate(Mock())
        assert len(result) == 1
        second.authenticate.assert_not_called()

    def test_failure_exception_is_recorded_and_sources_keep_being_tried(self):
        boom = Mock()
        boom.authenticate.side_effect = AuthenticationException("nope")
        ok = Mock()
        ok.authenticate.return_value = []
        strategy = _ListStrategy([boom, ok])
        result = strategy.authenticate(Mock())
        assert result[0].result is boom.authenticate.side_effect
        assert result[1].result == []

    def test_exhausted_sources_raise_failure_with_full_attempt_record(self):
        first = Mock()
        first.authenticate.side_effect = AuthenticationException("one")
        second = Mock()
        second.authenticate.return_value = ["publickey"]
        third = Mock()
        third.authenticate.side_effect = PartialAuthentication(
            ["keyboard-interactive"]
        )
        strategy = _ListStrategy([first, second, third])
        with pytest.raises(AuthFailure) as info:
            strategy.authenticate(Mock())
        result = info.value.result
        assert len(result) == 3
        assert isinstance(result[0].result, AuthenticationException)
        assert result[1].result == ["publickey"]
        assert result[2].result == ["keyboard-interactive"]

    def test_lazy_generator_is_consumed_one_source_at_a_time(self):
        # The password getter must not be evaluated before its source is
        # reached, and sources after a completed login are never even created.
        events = []
        getter = Mock(
            side_effect=lambda: events.append("password-fetched") or "pw"
        )

        def make_sources():
            first = Mock()
            first.authenticate.side_effect = PartialAuthentication(
                ["password"]
            )
            events.append("first-created")
            yield first
            events.append("second-created")
            yield Password("user", getter)
            events.append("third-created")
            third = Mock()
            third.authenticate.return_value = []
            yield third

        transport = Mock()
        transport.auth_password.return_value = []
        strategy = _RecordingStrategy(make_sources)
        result = strategy.authenticate(transport)
        # Iteration stopped at the completing password source: the third
        # source was never created, and the getter ran exactly once.
        assert events == [
            "first-created",
            "second-created",
            "password-fetched",
        ]
        assert len(result) == 2
        getter.assert_called_once_with()
        assert strategy.calls == 1

    def test_second_authenticate_call_does_not_inherit_first_call_state(self):
        transport = Mock()

        def partial_source():
            source = Mock()
            source.authenticate.side_effect = PartialAuthentication(
                ["password"]
            )
            return source

        failing_password = Mock()
        failing_password.authenticate.side_effect = AuthenticationException(
            "bad password"
        )
        strategy = _RecordingStrategy(
            lambda: [partial_source(), failing_password]
        )
        # First call: partial then failure -> AuthFailure with its own record.
        with pytest.raises(AuthFailure) as first_info:
            strategy.authenticate(transport)
        assert len(first_info.value.result) == 2
        # A brand-new call gets a fresh record; nothing carries over, and the
        # old failing source object is never revisited.
        good_password = Mock()
        good_password.authenticate.return_value = []
        strategy.factory = lambda: [partial_source(), good_password]
        result = strategy.authenticate(transport)
        assert len(result) == 2
        assert result[1].source is good_password
        assert result[1].result == []
        # The first call's password source was tried exactly once (in that
        # first call); it was not part of the second attempt at all.
        assert failing_password.authenticate.call_count == 1
        good_password.authenticate.assert_called_once()

    def test_disconnect_mid_auth_ends_in_auth_failure(self):
        # Transport.wait_for_response surfaces a dead transport as an
        # AuthenticationException; the strategy must record and move on /
        # raise rather than mistake it for success.
        source = Mock()
        source.authenticate.side_effect = AuthenticationException(
            "Authentication failed: transport shut down or saw EOF"
        )
        strategy = _ListStrategy([source])
        with pytest.raises(AuthFailure) as info:
            strategy.authenticate(Mock())
        assert len(info.value.result) == 1
        assert isinstance(
            info.value.result[0].result, AuthenticationException
        )

    def test_changing_server_allowed_methods_drives_until_exhaustion(self):
        tc, ts, socks, sockc = _loopback_transports(
            server=_ChameleonServer()
        )
        try:
            key = Ed25519Key.from_private_key_file(
                _support("ed25519.key")
            )
            strategy = _ListStrategy(
                [
                    InMemoryPrivateKey("paranoid", key),
                    Password("paranoid", lambda: "whatever"),
                ]
            )
            with pytest.raises(AuthFailure) as info:
                strategy.authenticate(tc)
            result = info.value.result
            # First factor's remaining methods were advertised then...
            assert result[0].result == ["publickey", "password"]
            # ...the server changed its mind on the second failure.
            assert isinstance(result[1].result, AuthenticationException)
            assert (
                result[1].result.allowed_types
                == ["publickey", "keyboard-interactive"]
            )
            assert not tc.is_authenticated()
        finally:
            tc.close()
            ts.close()
            socks.close()
            sockc.close()
