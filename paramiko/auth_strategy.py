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
    """

    #: SSH userauth method names this source may speak, or ``None`` when
    #: unknown. `AuthStrategy` uses this to skip sources the server has
    #: already said it will not accept.
    methods = None

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

    methods = ("none",)

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

    # NOTE: 'keyboard-interactive' included because Transport.auth_password
    # automatically falls back to it when the server doesn't allow 'password'
    # but does allow interactive auth.
    methods = ("password", "keyboard-interactive")

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

    methods = ("publickey",)

    def authenticate(self, transport):
        return transport.auth_publickey(self.username, self.pkey)


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
        # Auth methods the server has told us it's still willing to accept;
        # None means "no idea yet, anything goes".
        allowed = None
        # Sources which already completed one stage of a multipart auth.
        # Re-submitting the same credential for the same stage can't advance
        # the process, so such sources get skipped if encountered again.
        completed = []
        for source in self.get_sources():
            # The one true success criterion: the transport considers itself
            # authenticated _right now_ (don't wait until, say, channel open
            # time to discover a multipart auth never finished).
            if transport.is_authenticated():
                break
            # Skip sources whose methods the server has ruled out.
            if (
                allowed is not None
                and source.methods is not None
                and not any(method in allowed for method in source.methods)
            ):
                self.log.debug(
                    f"Skipping {source}: server only allows {allowed}"
                )
                continue
            # Skip sources which already completed a stage (eg a generator
            # yielding the same credential twice).
            if any(source is previous for previous in completed):
                self.log.debug(
                    f"Skipping {source}: already completed an auth stage"
                )
                continue
            self.log.debug(f"Trying {source}")
            try:  # NOTE: this really wants to _only_ wrap the authenticate()!
                result = source.authenticate(transport)
            # Multipart auth (eg 2FA), exception flavor: one stage succeeded,
            # server says which methods it still accepts.
            except PartialAuthentication as e:
                result = e
                allowed = list(e.allowed_types)
                completed.append(source)
                self.log.info(
                    f"Partial authentication via {source}; "
                    f"server now allows {allowed}"
                )
            except Exception as e:
                result = e
                # TODO: look at what this could possibly raise, we don't really
                # want Exception here, right? just SSHException subclasses? or
                # do we truly want to capture anything at all with assumption
                # it's easy enough for users to look afterwards?
                # NOTE: showing type, not message, for tersity & also most of
                # the time it's basically just "Authentication failed."
                source_class = e.__class__.__name__
                self.log.info(
                    f"Authentication via {source} failed with {source_class}"
                )
                # Failures may still tell us what the server accepts; honor
                # that when picking subsequent sources.
                if isinstance(e, BadAuthenticationType):
                    allowed = list(e.allowed_types)
            else:
                # Multipart auth, return-value flavor: Transport auth methods
                # hand back the list of still-acceptable methods when a stage
                # succeeds but full authentication isn't finished.
                if isinstance(result, (list, tuple)) and result:
                    allowed = list(result)
                    completed.append(source)
                    self.log.info(
                        f"Partial authentication via {source}; "
                        f"server now allows {allowed}"
                    )
            overall_result.append(SourceResult(source, result))
        # Gotta die here if nothing worked, otherwise Transport's main loop
        # just kinda hangs out until something times out!
        if not transport.is_authenticated():
            raise AuthFailure(result=overall_result)
        # Success: give back what was done, in case they care.
        return overall_result

    # TODO: is there anything OpenSSH client does which _can't_ cleanly map to
    # iterating a generator?
