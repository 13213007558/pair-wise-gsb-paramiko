"""
Modern, adaptable authentication machinery.

Replaces certain parts of `.SSHClient`. For a concrete implementation, see the
``OpenSSHAuthStrategy`` class in `Fabric <https://fabfile.org>`_.
"""

from collections import namedtuple

from .agent import AgentKey
from .ssh_exception import (
    AuthenticationException,
    BadAuthenticationType,
    PartialAuthentication,
)
from .util import get_logger


class AuthSource:
    """
    Some SSH authentication source, such as a password, private key, or agent.

    See subclasses in this module for concrete implementations.

    All implementations must accept at least a ``username`` (``str``) kwarg.

    The ``method`` class attribute names the SSH protocol authentication
    method a source implements (eg ``"password"``), or is `None` when
    the source does not map cleanly onto a single method. `AuthStrategy`
    uses it to match sources against the server-supplied list of currently
    allowable methods.
    """

    method = None

    def __init__(self, username):
        self.username = username

    def _repr(self, **kwargs):
        # TODO: are there any good libs for this? maybe some helper from
        # structlog?
        pairs = [f"{k}={v!r}" for k, v in kwargs.items()]
        joined = ", ".join(pairs)
        return f"{self.__class__.__name__}({joined})"

    def __repr__(self):
        return self._repr()

    def authenticate(self, transport):
        """
        Perform authentication.
        """
        raise NotImplementedError


class NoneAuth(AuthSource):
    """
    Auth type "none", ie https://www.rfc-editor.org/rfc/rfc4252#section-5.2 .
    """

    method = "none"

    def authenticate(self, transport):
        return transport.auth_none(self.username)


class Password(AuthSource):
    """
    Password authentication.

    :param callable password_getter:
        A lazy callable that should return a `str` password value at
        authentication time, such as a `functools.partial` wrapping
        `getpass.getpass`, an API call to a secrets store, or similar.

        If you already know the password at instantiation time, you should
        simply use something like ``lambda: "my literal"`` (for a literal, but
        also, shame on you!) or ``lambda: variable_name`` (for something stored
        in a variable).
    """

    method = "password"

    def __init__(self, username, password_getter):
        super().__init__(username=username)
        self.password_getter = password_getter

    def __repr__(self):
        # Password auth is marginally more 'username-caring' than pkeys, so may
        # as well log that info here.
        return super()._repr(user=self.username)

    def authenticate(self, transport):
        # Lazily get the password, in case it's prompting a user
        # TODO: be nice to log source _of_ the password?
        password = self.password_getter()
        return transport.auth_password(self.username, password)


# TODO (backwards incompat): twiddle this, or PKey, or both, so they're more
# obviously distinct.
# TODO (backwards incompat): the obvious is to make this more wordy
# (PrivateKeyAuth), the minimalist approach might be to rename PKey to just Key
# (esp given all the subclasses are WhateverKey and not WhateverPKey)
class PrivateKey(AuthSource):
    """
    Essentially a mixin for private keys.

    Knows how to auth, but leaves key material discovery/loading/decryption to
    subclasses.

    Subclasses **must** ensure that they've set ``self.pkey`` to a decrypted
    `.PKey` instance before calling ``super().authenticate``; typically
    either in their ``__init__``, or in an overridden ``authenticate`` prior to
    its `super` call.
    """

    method = "publickey"

    def authenticate(self, transport):
        return transport.auth_publickey(self.username, self.pkey)


class KeyboardInteractive(AuthSource):
    """
    Keyboard-interactive authentication (RFC 4256), aka challenge-response.

    :param callable secret_getter:
        A lazy callable invoked once per server prompt, as
        ``secret_getter(prompt, echo)``, returning the `str` answer. The
        ``echo`` flag is the server's own hint about whether the answer
        should be echoed to a human user; it is preserved and passed through
        untouched.

        The callable is only invoked when the server actually issues a
        challenge, so when this source sits behind another factor (eg a
        private key) the secret is never requested unless a second factor is
        truly required.

    .. note::
        Answers obtained from ``secret_getter`` are never stored on the
        instance, nor included in ``repr`` or log output.
    """

    method = "keyboard-interactive"

    def __init__(self, username, secret_getter):
        super().__init__(username=username)
        self.secret_getter = secret_getter

    def __repr__(self):
        # As with Password, the username is useful context; the secret, and
        # any answers derived from it, must never appear here.
        return super()._repr(user=self.username)

    def authenticate(self, transport):
        def handler(title, instructions, prompts):
            # NOTE: Transport calls this once per challenge round, so
            # multi-round authentication works transparently; prompt echo
            # flags are forwarded to the getter as-is.
            return [
                self.secret_getter(prompt, echo) for prompt, echo in prompts
            ]

        return transport.auth_interactive(self.username, handler)


class InMemoryPrivateKey(PrivateKey):
    """
    An in-memory, decrypted `.PKey` object.
    """

    def __init__(self, username, pkey):
        super().__init__(username=username)
        # No decryption (presumably) necessary!
        self.pkey = pkey

    def __repr__(self):
        # NOTE: most of interesting repr-bits for private keys is in PKey.
        # TODO: tacking on agent-ness like this is a bit awkward, but, eh?
        rep = super()._repr(pkey=self.pkey)
        if isinstance(self.pkey, AgentKey):
            rep += " [agent]"
        return rep


class OnDiskPrivateKey(PrivateKey):
    """
    Some on-disk private key that needs opening and possibly decrypting.

    :param str source:
        String tracking where this key's path was specified; should be one of
        ``"ssh-config"``, ``"python-config"``, or ``"implicit-home"``.
    :param Path path:
        The filesystem path this key was loaded from.
    :param PKey pkey:
        The `PKey` object this auth source uses/represents.
    """

    def __init__(self, username, source, path, pkey):
        super().__init__(username=username)
        self.source = source
        allowed = ("ssh-config", "python-config", "implicit-home")
        if source not in allowed:
            raise ValueError(f"source argument must be one of: {allowed!r}")
        self.path = path
        # Superclass wants .pkey, other two are mostly for display/debugging.
        self.pkey = pkey

    def __repr__(self):
        return self._repr(
            key=self.pkey, source=self.source, path=str(self.path)
        )


# TODO re sources: is there anything in an OpenSSH config file that doesn't fit
# into what Paramiko already had kwargs for?


SourceResult = namedtuple("SourceResult", ["source", "result"])


# TODO: tempting to make this an OrderedDict, except the keys essentially want
# to be rich objects (AuthSources) which do not make for useful user indexing?
# TODO: members being vanilla tuples is pretty old-school/expedient; they
# "really" want to be something that's type friendlier (unless the tuple's 2nd
# member being a Union of two types is "fine"?), which I assume means yet more
# classes, eg an abstract SourceResult with concrete AuthSuccess and
# AuthFailure children?
# TODO: arguably we want __init__ typechecking of the members (or to leverage
# mypy by classifying this literally as list-of-AuthSource?)
class AuthResult(list):
    """
    Represents a partial or complete SSH authentication attempt.

    This class conceptually extends `AuthStrategy` by pairing the former's
    authentication **sources** with the **results** of trying to authenticate
    with them.

    `AuthResult` is a (subclass of) `list` of `namedtuple`, which are of the
    form ``namedtuple('SourceResult', 'source', 'result')`` (where the
    ``source`` member is an `AuthSource` and the ``result`` member is either a
    return value from the relevant `.Transport` method, or an exception
    object).

    .. note::
        Transport auth method results are always themselves a ``list`` of "next
        allowable authentication methods".

        In the simple case of "you just authenticated successfully", it's an
        empty list; if your auth was rejected but you're allowed to try again,
        it will be a list of string method names like ``pubkey`` or
        ``password``.

        The ``__str__`` of this class represents the empty-list scenario as the
        word ``success``, which should make reading the result of an
        authentication session more obvious to humans.

    Instances also have a `strategy` attribute referencing the `AuthStrategy`
    which was attempted.
    """

    def __init__(self, strategy, *args, **kwargs):
        self.strategy = strategy
        super().__init__(*args, **kwargs)

    def __str__(self):
        # NOTE: meaningfully distinct from __repr__, which still wants to use
        # superclass' implementation.
        # TODO: go hog wild, use rich.Table? how is that on degraded term's?
        # TODO: test this lol
        return "\n".join(
            f"{x.source} -> {x.result or 'success'}" for x in self
        )


# TODO (backwards incompat): descend from SSHException or even just Exception
class AuthFailure(AuthenticationException):
    """
    Basic exception wrapping an `AuthResult` indicating overall auth failure.

    Note that `AuthFailure` descends from `AuthenticationException` but is
    generally "higher level"; the latter is now only raised by individual
    `AuthSource` attempts and should typically only be seen by users when
    encapsulated in this class. It subclasses `AuthenticationException`
    primarily for backwards compatibility reasons.
    """

    def __init__(self, result):
        self.result = result

    def __str__(self):
        return "\n" + str(self.result)


class AuthStrategy:
    """
    This class represents one or more attempts to auth with an SSH server.

    By default, subclasses must at least accept an ``ssh_config``
    (`.SSHConfig`) keyword argument, but may opt to accept more as needed for
    their particular strategy.
    """

    def __init__(
        self,
        ssh_config,
    ):
        self.ssh_config = ssh_config
        self.log = get_logger(__name__)

    def get_sources(self):
        """
        Generator yielding `AuthSource` instances, in the order to try.

        This is the primary override point for subclasses: you figure out what
        sources you need, and ``yield`` them.

        Subclasses _of_ subclasses may find themselves wanting to do things
        like filtering or discarding around a call to `super`.
        """
        raise NotImplementedError

    def authenticate(self, transport):
        """
        Handles attempting `AuthSource` instances yielded from `get_sources`.

        You *normally* won't need to override this, but it's an option for
        advanced users.
        """
        overall_result = AuthResult(strategy=self)
        # TODO: arguably we could fit in a "send none auth, record allowed auth
        # types sent back" thing here as OpenSSH-client does, but that likely
        # wants to live in fabric.OpenSSHAuthStrategy as not all target servers
        # will implement it!
        # TODO: needs better "server told us too many attempts" checking!
        # Auth methods the server most recently told us it will still accept;
        # None means "server hasn't said, so anything goes".
        allowed = None
        # Methods which already succeeded as one factor of a multi-factor
        # authentication; re-offering them would be meaningless.
        completed = set()
        for source in self.get_sources():
            method = getattr(source, "method", None)
            if method is not None:
                if method in completed:
                    self.log.debug(
                        f"Skipping {source}: {method} already completed"
                    )
                    continue
                if allowed is not None and method not in allowed:
                    self.log.debug(
                        f"Skipping {source}: server only allows {allowed}"
                    )
                    continue
            self.log.debug(f"Trying {source}")
            try:
                result = source.authenticate(transport)
            except PartialAuthentication as e:
                # Defensive: Transport auth methods normally return the
                # partial method list instead of raising, but SSHClient has
                # historically had to catch this, so handle it just in case.
                result = list(e.allowed_types)
                overall_result.append(SourceResult(source, result))
                if method is not None:
                    completed.add(method)
                allowed = result
                continue
            except AuthenticationException as e:
                # NOTE: deliberately narrow - protocol errors (SSHException)
                # and bugs in user callbacks (eg TypeError from a password
                # getter) must propagate, not masquerade as bad credentials.
                overall_result.append(SourceResult(source, e))
                if not transport.is_active():
                    # Connection died mid-auth; that's not a credential
                    # failure and no further source can possibly work.
                    raise
                result = e
                if isinstance(e, BadAuthenticationType):
                    allowed = list(e.allowed_types)
                # NOTE: showing type, not message, for tersity & also most of
                # the time it's basically just "Authentication failed."
                source_class = e.__class__.__name__
                self.log.info(
                    f"Authentication via {source} failed with {source_class}"
                )
                continue
            overall_result.append(SourceResult(source, result))
            if transport.is_authenticated():
                break
            # A non-empty list result means partial success: this factor was
            # accepted, and the server named the methods it will accept next.
            if isinstance(result, list) and result:
                if method is not None:
                    completed.add(method)
                allowed = list(result)
                self.log.info(
                    f"Partial authentication via {source}; "
                    f"server now allows {allowed}"
                )
        # Only trust the Transport itself to say whether we made it; a
        # source returning an empty list without the Transport agreeing is
        # not a success.
        if not transport.is_authenticated():
            raise AuthFailure(result=overall_result)
        return overall_result

    # TODO: is there anything OpenSSH client does which _can't_ cleanly map to
    # iterating a generator?
