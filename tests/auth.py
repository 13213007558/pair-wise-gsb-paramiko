"""
Tests focusing primarily on the authentication step.

Thus, they concern AuthHandler and AuthStrategy, with a side of Transport.
"""

from logging import Logger
from unittest.mock import Mock

from pytest import raises

from paramiko import (
    AgentKey,
    AuthenticationException,
    AuthFailure,
    AuthResult,
    AuthSource,
    AuthStrategy,
    BadAuthenticationType,
    Ed25519Key,
    InMemoryPrivateKey,
    NoneAuth,
    OnDiskPrivateKey,
    Password,
    PartialAuthentication,
    PKey,
    PrivateKey,
    RSAKey,
    SourceResult,
    SSHException,
)

from ._util import (
    _support,
    server,
    unicodey,
)


class AuthHandler_:
    """
    Most of these tests are explicit about the auth method they call.

    This is because not too many other tests do so (they rely on the implicit
    auth trigger of various connect() kwargs).
    """

    def bad_auth_type(self):
        """
        verify that we get the right exception when an unsupported auth
        type is requested.
        """
        # Server won't allow password auth for this user, so should fail
        # and return just publickey allowed types
        with server(
            connect=dict(username="unknown", password="error"),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, BadAuthenticationType)
            assert err.allowed_types == ["publickey"]

    def bad_password(self):
        """
        verify that a bad password gets the right exception, and that a retry
        with the right password works.
        """
        # NOTE: Transport.connect doesn't do any auth upfront if no userauth
        # related kwargs given.
        with server(defer=True) as (tc, ts):
            # Auth once, badly
            with raises(AuthenticationException):
                tc.auth_password(username="slowdive", password="error")
            # And again, correctly
            tc.auth_password(username="slowdive", password="pygmalion")

    def multipart_auth(self):
        """
        verify that multipart auth works.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password(
                username="paranoid", password="paranoid"
            ) == ["publickey"]
            key = Ed25519Key.from_private_key_file(_support("ed25519.key"))
            assert tc.auth_publickey(username="paranoid", key=key) == []

    def interactive_auth(self):
        """
        verify keyboard-interactive auth works.
        """

        def handler(title, instructions, prompts):
            self.got_title = title
            self.got_instructions = instructions
            self.got_prompts = prompts
            return ["cat"]

        with server(defer=True) as (tc, ts):
            assert tc.auth_interactive("commie", handler) == []
            assert self.got_title == "password"
            assert self.got_prompts == [("Password", False)]

    def interactive_fallback(self):
        """
        verify that a password auth attempt will fallback to "interactive"
        if password auth isn't supported but interactive is.
        """
        with server(defer=True) as (tc, ts):
            # This username results in an allowed_auth of just kbd-int,
            # and has a configured interactive->response on the server.
            assert tc.auth_password("commie", "cat") == []

    def utf8(self):
        """
        verify that utf-8 encoding happens in authentication.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("utf8", unicodey) == []

    def non_utf8(self):
        """
        verify that non-utf-8 encoded passwords can be used for broken
        servers.
        """
        with server(defer=True) as (tc, ts):
            assert tc.auth_password("non-utf8", "\xff") == []

    def auth_exception_when_disconnected(self):
        """
        verify that we catch a server disconnecting during auth, and report
        it as an auth failure.
        """
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(AuthenticationException),
        ):
            tc.auth_password("bad-server", "hello")

    def non_responsive_triggers_auth_exception(self):
        """
        verify that authentication times out if server takes to long to
        respond (or never responds).
        """
        with (
            server(defer=True, skip_verify=True) as (tc, ts),
            raises(AuthenticationException) as info,
        ):
            tc.auth_timeout = 1  # 1 second, to speed up test
            tc.auth_password("unresponsive-server", "hello")
            assert "Authentication timeout" in str(info.value)


class SHA2SignaturePubkeys:
    def pubkey_auth_honors_disabled_algorithms(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(
                disabled_algorithms=dict(
                    pubkeys=["rsa-sha2-256", "rsa-sha2-512"]
                )
            ),
            catch_error=True,
        ) as (_, _, err):
            assert isinstance(err, SSHException)
            assert "no RSA pubkey algorithms" in str(err)

    def first_client_preferred_algo_used_when_no_server_sig_algs(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(username="slowdive", pkey=privkey),
            server_init=dict(
                disabled_algorithms=dict(
                    # Disable both SHA2 just to keep previous theme of this
                    # test alive (auth failure but w/ proof we tried offering
                    # something)
                    pubkeys=["rsa-sha2-256", "rsa-sha2-512"]
                ),
                # Don't publish server-sig-algs, forcing use of fallback on the
                # client side
                server_sig_algs=False,
            ),
            # Incidentally prove we're using the filtered algorithm list on the
            # client side - taking out 512 means we should offer 256
            client_init=dict(
                disabled_algorithms=dict(pubkeys=["rsa-sha2-512"])
            ),
            catch_error=True,
        ) as (tc, ts, err):
            # There was no agreement, we threw an exception...
            assert not tc.is_authenticated()
            assert isinstance(err, AuthenticationException)
            # ...but we can observe the client did their best guess at what an
            # agreement /could/ have been, and it was 256
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"

    def sha2_512(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(disabled_algorithms=dict(pubkeys=["rsa-sha2-256"])),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-512"

    def sha2_256(self):
        privkey = RSAKey.from_private_key_file(_support("rsa.key"))
        with server(
            pubkeys=[privkey],
            connect=dict(pkey=privkey),
            init=dict(disabled_algorithms=dict(pubkeys=["rsa-sha2-512"])),
        ) as (tc, ts):
            assert tc.is_authenticated()
            assert tc._agreed_pubkey_algorithm == "rsa-sha2-256"


class AuthSource_:
    class base_class:
        def init_requires_and_saves_username(self):
            with raises(TypeError):
                AuthSource()
            assert AuthSource(username="foo").username == "foo"

        def dunder_repr_delegates_to_helper(self):
            source = AuthSource("foo")
            source._repr = Mock(wraps=lambda: "whatever")
            repr(source)
            source._repr.assert_called_once_with()

        def repr_helper_prints_basic_kv_pairs(self):
            assert repr(AuthSource("foo")) == "AuthSource()"
            assert (
                AuthSource("foo")._repr(bar="open") == "AuthSource(bar='open')"
            )

        def authenticate_takes_transport_and_is_abstract(self):
            # TODO: this test kinda just goes away once we're typed?
            with raises(TypeError):
                AuthSource("foo").authenticate()
            with raises(NotImplementedError):
                AuthSource("foo").authenticate(None)

    class NoneAuth_:
        def authenticate_auths_none(self):
            trans = Mock()
            result = NoneAuth("foo").authenticate(trans)
            trans.auth_none.assert_called_once_with("foo")
            assert result is trans.auth_none.return_value

        def repr_shows_class(self):
            assert repr(NoneAuth("foo")) == "NoneAuth()"

    class Password_:
        def init_takes_and_stores_password_getter(self):
            with raises(TypeError):
                Password("foo")
            getter = Mock()
            pw = Password("foo", password_getter=getter)
            assert pw.password_getter is getter

        def repr_adds_username(self):
            pw = Password("foo", password_getter=Mock())
            assert repr(pw) == "Password(user='foo')"

        def authenticate_gets_and_supplies_password(self):
            getter = Mock(return_value="bar")
            trans = Mock()
            pw = Password("foo", password_getter=getter)
            result = pw.authenticate(trans)
            trans.auth_password.assert_called_once_with("foo", "bar")
            assert result is trans.auth_password.return_value

    class PrivateKey_:
        def authenticate_calls_publickey_with_pkey(self):
            source = PrivateKey(username="foo")
            source.pkey = Mock()  # set by subclasses
            trans = Mock()
            result = source.authenticate(trans)
            trans.auth_publickey.assert_called_once_with("foo", source.pkey)
            assert result is trans.auth_publickey.return_value

    class InMemoryPrivateKey_:
        def init_takes_pkey_object(self):
            with raises(TypeError):
                InMemoryPrivateKey("foo")
            pkey = Mock()
            source = InMemoryPrivateKey(username="foo", pkey=pkey)
            assert source.pkey is pkey

        def repr_shows_pkey_repr(self):
            pkey = PKey.from_path(_support("ed25519.key"))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow))"  # noqa
            )

        def repr_appends_agent_flag_when_AgentKey(self):
            real_key = PKey.from_path(_support("ed25519.key"))
            pkey = AgentKey(agent=None, blob=bytes(real_key))
            source = InMemoryPrivateKey("foo", pkey)
            assert (
                repr(source)
                == "InMemoryPrivateKey(pkey=PKey(alg=ED25519, bits=256, fp=SHA256:J6VESFdD3xSChn8y9PzWzeF+1tl892mOy2TqkMLO4ow)) [agent]"  # noqa
            )

    class OnDiskPrivateKey_:
        def init_takes_source_path_and_pkey(self):
            with raises(TypeError):
                OnDiskPrivateKey("foo")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar")
            with raises(TypeError):
                OnDiskPrivateKey("foo", "bar", "biz")
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert source.username == "foo"
            assert source.source == "ssh-config"
            assert source.path == "of-exile"
            assert source.pkey == "notreally"

        def init_requires_specific_value_for_source(self):
            with raises(
                ValueError,
                match=r"source argument must be one of: \('ssh-config', 'python-config', 'implicit-home'\)",  # noqa
            ):
                OnDiskPrivateKey("foo", source="what?", path="meh", pkey="no")

        def repr_reflects_source_path_and_pkey(self):
            source = OnDiskPrivateKey(
                username="foo",
                source="ssh-config",
                path="of-exile",
                pkey="notreally",
            )
            assert (
                repr(source)
                == "OnDiskPrivateKey(key='notreally', source='ssh-config', path='of-exile')"  # noqa
            )


class AuthResult_:
    def setup_method(self):
        self.strat = AuthStrategy(None)

    def acts_like_list_with_strategy_attribute(self):
        with raises(TypeError):
            AuthResult()
        # kwarg works by itself
        AuthResult(strategy=self.strat)
        # or can be given as posarg w/ regular list() args after
        result = AuthResult(self.strat, [1, 2, 3])
        assert result.strategy is self.strat
        assert result == [1, 2, 3]
        assert isinstance(result, list)

    def repr_is_list_repr_untouched(self):
        result = AuthResult(self.strat, [1, 2, 3])
        assert repr(result) == "[1, 2, 3]"

    class dunder_str:
        def is_multiline_display_of_sourceresult_tuples(self):
            result = AuthResult(self.strat)
            result.append(SourceResult("foo", "bar"))
            result.append(SourceResult("biz", "baz"))
            assert str(result) == "foo -> bar\nbiz -> baz"

        def shows_str_not_repr_of_auth_source_and_result(self):
            result = AuthResult(self.strat)
            result.append(
                SourceResult(NoneAuth("foo"), ["password", "pubkey"])
            )
            assert str(result) == "NoneAuth() -> ['password', 'pubkey']"

        def empty_list_result_values_show_success_string(self):
            result = AuthResult(self.strat)
            result.append(SourceResult(NoneAuth("foo"), []))
            assert str(result) == "NoneAuth() -> success"


class AuthFailure_:
    def is_an_AuthenticationException(self):
        assert isinstance(AuthFailure(None), AuthenticationException)

    def init_requires_result(self):
        with raises(TypeError):
            AuthFailure()
        result = AuthResult(None)
        fail = AuthFailure(result=result)
        assert fail.result is result

    def str_is_newline_plus_result_str(self):
        result = AuthResult(None)
        result.append(SourceResult(NoneAuth("foo"), Exception("onoz")))
        fail = AuthFailure(result)
        assert str(fail) == "\nNoneAuth() -> onoz"


class AuthStrategy_:
    def init_requires_ssh_config_param_and_sets_up_a_logger(self):
        with raises(TypeError):
            AuthStrategy()
        conf = object()
        strat = AuthStrategy(ssh_config=conf)
        assert strat.ssh_config is conf
        assert isinstance(strat.log, Logger)
        assert strat.log.name == "paramiko.auth_strategy"

    def get_sources_is_abstract(self):
        with raises(NotImplementedError):
            AuthStrategy(None).get_sources()

    class authenticate:
        def setup_method(self):
            self.strat = AuthStrategy(None)  # ssh_config not used directly
            self.source, self.transport = NoneAuth(None), Mock()
            self.source.authenticate = Mock()
            self.strat.get_sources = Mock(return_value=[self.source])

        def requires_and_uses_transport_with_methods_returning_result(self):
            with raises(TypeError):
                self.strat.authenticate()
            result = self.strat.authenticate(self.transport)
            self.strat.get_sources.assert_called_once_with()
            self.source.authenticate.assert_called_once_with(self.transport)
            assert isinstance(result, AuthResult)
            assert result.strategy is self.strat
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is self.source.authenticate.return_value

        def logs_sources_attempted(self):
            self.strat.log = Mock()
            self.strat.authenticate(self.transport)
            self.strat.log.debug.assert_called_once_with("Trying NoneAuth()")

        def raises_AuthFailure_if_no_successes(self):
            self.strat.log = Mock()
            oops = Exception("onoz")
            self.source.authenticate.side_effect = oops
            with raises(AuthFailure) as info:
                self.strat.authenticate(self.transport)
            result = info.value.result
            assert isinstance(result, AuthResult)
            assert len(result) == 1
            source_res = result[0]
            assert isinstance(source_res, SourceResult)
            assert source_res.source is self.source
            assert source_res.result is oops
            self.strat.log.info.assert_called_once_with(
                "Authentication via NoneAuth() failed with Exception"
            )

        def short_circuits_on_successful_auth(self):
            kaboom = Mock(authenticate=Mock(side_effect=Exception("onoz")))
            self.strat.get_sources.return_value = [self.source, kaboom]
            result = self.strat.authenticate(self.transport)
            # No exception, and it's just a regular ol Result
            assert isinstance(result, AuthResult)
            # And it did not capture any attempt to execute the 2nd source
            assert len(result) == 1
            assert result[0].source is self.source

        def skips_sources_whose_methods_server_does_not_allow(self):
            key = InMemoryPrivateKey(username="user", pkey=Mock())
            key.authenticate = Mock(return_value=["password"])
            none = NoneAuth("user")
            none.authenticate = Mock()
            password = Password("user", password_getter=Mock())
            password.authenticate = Mock(return_value=[])
            # First source partially succeeds, second completes auth
            self.transport.is_authenticated.side_effect = [False, True]
            self.strat.get_sources.return_value = [key, none, password]
            result = self.strat.authenticate(self.transport)
            # NoneAuth was never tried: 'none' not in server-allowed methods
            none.authenticate.assert_not_called()
            # Skipped sources don't appear in the result either
            assert [x.source for x in result] == [key, password]
            assert result[0].result == ["password"]
            assert result[1].result == []

        def does_not_resubmit_source_which_completed_a_stage(self):
            # A source with no declared 'methods', partially succeeding,
            # must not be re-submitted if the generator yields it again.
            source = AuthSource("user")
            source.authenticate = Mock(return_value=["password"])
            self.transport.is_authenticated.return_value = False
            self.strat.get_sources.return_value = [source, source]
            with raises(AuthFailure):
                self.strat.authenticate(self.transport)
            assert source.authenticate.call_count == 1

        def treats_PartialAuthentication_exception_as_partial_success(self):
            key = AuthSource("user")
            key.authenticate = Mock(
                side_effect=PartialAuthentication(["password"])
            )
            password = Password("user", password_getter=Mock())
            password.authenticate = Mock(return_value=[])
            self.transport.is_authenticated.return_value = True
            self.strat.get_sources.return_value = [key, password]
            result = self.strat.authenticate(self.transport)
            assert len(result) == 2
            partial = result[0].result
            assert isinstance(partial, PartialAuthentication)
            assert partial.allowed_types == ["password"]
            assert result[1].source is password


def _key_source(username):
    key = Ed25519Key.from_private_key_file(_support("ed25519.key"))
    return InMemoryPrivateKey(username=username, pkey=key)


def _password_source(username, password):
    return Password(username, password_getter=lambda: password)


def _multipart_strategy(sources):
    class MultipartAuthStrategy(AuthStrategy):
        def get_sources(self):
            yield from sources

    return MultipartAuthStrategy(ssh_config=None)


class AuthStrategy_multipart:
    """
    Multi-step (eg 2FA) auth, run against the in-repo local SSH server.
    """

    def publickey_then_password(self):
        with server(defer=True) as (tc, ts):
            strat = _multipart_strategy(
                [
                    _key_source("paranoid"),
                    _password_source("paranoid", "paranoid"),
                ]
            )
            result = strat.authenticate(tc)
            assert tc.is_authenticated()
            # Both stages recorded; 1st shows remaining methods, 2nd success
            assert len(result) == 2
            assert result[0].result == ["password"]
            assert result[1].result == []

    def publickey_then_keyboard_interactive(self):
        with server(defer=True) as (tc, ts):
            strat = _multipart_strategy(
                [
                    _key_source("paranoid2"),
                    _password_source("paranoid2", "cat"),
                ]
            )
            result = strat.authenticate(tc)
            assert tc.is_authenticated()
            assert len(result) == 2
            assert result[0].result == ["keyboard-interactive"]
            assert result[1].result == []

    def second_stage_failure_raises_AuthFailure(self):
        with server(defer=True) as (tc, ts):
            strat = _multipart_strategy(
                [
                    _key_source("paranoid"),
                    _password_source("paranoid", "not-the-password"),
                ]
            )
            with raises(AuthFailure) as info:
                strat.authenticate(tc)
            result = info.value.result
            assert not tc.is_authenticated()
            # Per-stage attempts are preserved
            assert len(result) == 2
            assert result[0].result == ["password"]
            assert isinstance(result[1].result, AuthenticationException)
            # Secrets never leak into the result or its string form
            assert "not-the-password" not in str(result)
            assert "not-the-password" not in str(info.value)
