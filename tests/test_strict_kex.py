# Protocol-level regression tests for RFC 8308 strict key exchange.
#
# These tests deliberately assert against protocol states rather than the
# implementation's internal bookkeeping: sequence-number expectations are
# expressed as "first packet of a NEWKEYS epoch" / "continuation of the
# running stream", and every claim is cross-checked against the wire view the
# peer's packetizer actually authenticates.
#
# Each test documents the shortest failing packet sequence and, in comments,
# the state at every step, so a maintainer can tell whether a failure happens
# before the key switch, during it, or on the first packet after it.

from pytest import mark, raises

from paramiko import MessageOrderError, Packetizer, Transport
from paramiko.common import (
    MSG_CHANNEL_DATA,
    MSG_DEBUG,
    MSG_EXT_INFO,
    MSG_IGNORE,
    MSG_KEXINIT,
    MSG_NEWKEYS,
    MSG_SERVICE_REQUEST,
    byte_chr,
    byte_ord,
)
from paramiko.message import Message
from paramiko.ssh_exception import SSHException

from ._util import server


# Fixed, tiny application payload carried on the first data-bearing packet
# after a key switch. No external SSH service is involved: both ends talk
# over the in-memory LoopSocket pair supplied by the server() helper.
SMALL_PAYLOAD = b"strict-kex-ping"


def _seq_in(packetizer):
    return packetizer._Packetizer__sequence_number_in


def _seq_out(packetizer):
    return packetizer._Packetizer__sequence_number_out


class TracingPacketizer(Packetizer):
    """Packetizer that records the seqno used for each MAC and packet type."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Each entry is (direction, packet type, seqno seen by the MAC).
        self.events = []

    def send_message(self, data):
        self.events.append(
            ("out", byte_ord(data.asbytes()[0:1]), _seq_out(self))
        )
        return super().send_message(data)

    def read_message(self):
        cmd, msg = super().read_message()
        self.events.append(("in", cmd, msg.seqno))
        return cmd, msg


class TracingTransport(Transport):
    """Transport snapshotting seqno state around the asymmetric key switch."""

    def __init__(self, *args, **kwargs):
        kwargs.setdefault("packetizer_class", TracingPacketizer)
        super().__init__(*args, **kwargs)
        # Snapshots keyed by direction and NEWKEYS boundary.
        self.snapshots = []

    def _snapshot(self, boundary):
        self.snapshots.append(
            (boundary, _seq_in(self.packetizer), _seq_out(self.packetizer))
        )

    def _activate_outbound(self):
        # State just before the local NEWKEYS is sent: the outbound epoch
        # has not been reset yet, inbound still runs the old stream.
        self._snapshot("before-outbound-switch")
        super()._activate_outbound()
        # NEWKEYS itself consumed the last seqno of the old epoch; the
        # outbound counter is now zeroed for the next (application) packet,
        # while the inbound side has not seen the peer's NEWKEYS.
        self._snapshot("after-outbound-switch")

    def _activate_inbound(self):
        # Peer NEWKEYS arrived and is about to be authenticated on the old
        # inbound stream; only the inbound counter gets reset afterwards.
        self._snapshot("before-inbound-switch")
        super()._activate_inbound()
        self._snapshot("after-inbound-switch")


def _wire_events(transport):
    return transport.packetizer.events


def _events(transport, direction):
    return [e for e in _wire_events(transport) if e[0] == direction]


def _types(transport, direction):
    return [ptype for _, ptype, _ in _events(transport, direction)]


def _ignore_message():
    msg = Message()
    msg.add_byte(byte_chr(MSG_IGNORE))
    msg.add_bytes(b"rogue")
    return msg


def _debug_message():
    msg = Message()
    msg.add_byte(byte_chr(MSG_DEBUG))
    msg.add_boolean(False)
    msg.add_string(b"rogue")
    msg.add_string(b"en")
    return msg


class RogueMessageTransport(TracingTransport):
    """Inserts one foreign message in the middle of the initial kex.

    The injection point is after both sides have agreed on algorithms but
    before the kex engine produces NEWKEYS, i.e. the Terrapin window.
    """

    rogue = MSG_IGNORE

    def _negotiate_keys(self, m):
        super()._negotiate_keys(m)
        self._send_message(_ignore_or_debug(self.rogue))


def _ignore_or_debug(ptype):
    if ptype == MSG_DEBUG:
        return _debug_message()
    return _ignore_message()


class RekeyRogueTransport(TracingTransport):
    """Inserts a foreign message during a later rekey, never the first kex."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._negotiations = 0

    def _negotiate_keys(self, m):
        super()._negotiate_keys(m)
        self._negotiations += 1
        if self._negotiations > 1:
            self._send_message(_ignore_message())


class LaxOrderTransport(TracingTransport):
    """Mutant: the in-exchange foreign-message guard is disabled."""

    def _enforce_strict_kex(self, ptype):
        return None


class InboundResetMutantPacketizer(TracingPacketizer):
    # Client-side mutant: the inbound NEWKEYS reset is dropped. The outbound
    # reset deliberately delegates to the base class so this mutant is
    # strictly one-directional.
    def reset_seqno_in(self):
        return None

    def reset_seqno_out(self):
        Packetizer.reset_seqno_out(self)


class OutboundResetMutantPacketizer(TracingPacketizer):
    def reset_seqno_out(self):
        return None

    def reset_seqno_in(self):
        Packetizer.reset_seqno_in(self)


class InboundResetMutantTransport(TracingTransport):
    def __init__(self, *args, **kwargs):
        kwargs["packetizer_class"] = InboundResetMutantPacketizer
        super().__init__(*args, **kwargs)


class OutboundResetMutantTransport(TracingTransport):
    def __init__(self, *args, **kwargs):
        kwargs["packetizer_class"] = OutboundResetMutantPacketizer
        super().__init__(*args, **kwargs)


class TestInitialStrictKex:
    def test_both_sides_strict_reset_each_direction_around_newkeys(self):
        # Wire sequence (client view):
        #   1. KEXINIT..KEXDH_REPLY run on the initial stream (seqno 0..n)
        #   2. client NEWKEYS: last packet of the old outbound stream
        #   3. server NEWKEYS: last packet of the old inbound stream
        #   4. first application packet must start a fresh seqno-0 stream
        with server(
            transport_factory=TracingTransport,
            server_transport_factory=TracingTransport,
        ) as (tc, ts):
            # Both ends know strict mode was negotiated, not assumed; the
            # live counters already count post-switch application traffic, so
            # the reset itself is asserted via the recorded NEWKEYS boundary.
            assert tc.agreed_on_strict_kex
            assert ts.agreed_on_strict_kex
            assert tc.initial_kex_done and ts.initial_kex_done

            out_types = _types(tc, "out")
            in_types = _types(tc, "in")
            assert MSG_NEWKEYS in out_types and MSG_NEWKEYS in in_types
            # NEWKEYS is the last packet of each old stream, hence a nonzero
            # seqno on every direction...
            newkeys_out = [
                event
                for event in _events(tc, "out")
                if event[1] == MSG_NEWKEYS
            ]
            newkeys_in = [
                event for event in _events(tc, "in") if event[1] == MSG_NEWKEYS
            ]
            assert all(event[2] > 0 for event in newkeys_out + newkeys_in)
            # The first application packet after the switch is the
            # ssh-userauth SERVICE_REQUEST, and it authenticates on the new
            # stream, hence seqno 0 rather than continuing the old counter.
            first_app = _events(tc, "out")[out_types.index(MSG_NEWKEYS) + 1]
            assert first_app[1] == MSG_SERVICE_REQUEST
            assert first_app[2] == 0
            assert tc.is_authenticated()

    def test_inbound_and_outbound_switch_are_separate_events(self):
        # The two directions do not flip atomically: each side sends its own
        # NEWKEYS (outbound switch) independently of processing the peer's
        # (inbound switch). A single Transport instance must survive the gap
        # rather than being rebuilt to hide the ordering.
        with server(
            transport_factory=TracingTransport,
            server_transport_factory=TracingTransport,
        ) as (tc, ts):
            for transport in (tc, ts):
                # The same packetizer object spans both switches: the state
                # machine advances, nothing is rebuilt to paper over gaps.
                packetizer_before = transport.packetizer
                boundaries = [name for name, _, _ in transport.snapshots]
                assert boundaries == [
                    "before-outbound-switch",
                    "after-outbound-switch",
                    "before-inbound-switch",
                    "after-inbound-switch",
                ]
                assert transport.packetizer is packetizer_before
                before_out, after_out, before_in, after_in = (
                    transport.snapshots
                )
                # The outbound reset only touches the outbound counter; the
                # inbound stream keeps counting the old exchange.
                assert after_out[2] < before_out[2]
                assert after_out[1] == before_out[1]
                # The inbound reset only touches the inbound counter; the
                # already-switched outbound stream must be left alone.
                assert after_in[1] < before_in[1]
                assert after_in[2] == after_out[2]

    def test_strict_resets_apply_again_on_rekey(self):
        # Sequence across a rekey:
        #   old epoch packets -> KEXINIT (keeps counting) -> local NEWKEYS
        #   (outbound reset) -> peer NEWKEYS (inbound reset) -> application
        #   packet at seqno 0 of the new epoch.
        with server(
            transport_factory=TracingTransport,
            server_transport_factory=TracingTransport,
        ) as (tc, ts):
            chan = tc.open_session()
            chan.exec_command("yes")
            schan = ts.accept(1.0)
            exchange_hash_before = tc.H
            tc.renegotiate_keys()
            # The session id stays fixed (it is derived from the first
            # exchange), but the rekey produces a fresh exchange hash and a
            # second NEWKEYS boundary.
            assert tc.H != exchange_hash_before
            assert tc.session_id == exchange_hash_before

            newkeys_out = [
                index
                for index, (_, ptype, _) in enumerate(_events(tc, "out"))
                if ptype == MSG_NEWKEYS
            ]
            newkeys_in = [
                index
                for index, (_, ptype, _) in enumerate(_events(tc, "in"))
                if ptype == MSG_NEWKEYS
            ]
            # Two complete switches: initial kex and the rekey.
            assert len(newkeys_out) == 2 and len(newkeys_in) == 2

            # The rekey KEXINIT is not a boundary: it continues the running
            # stream with a nonzero seqno. The fresh stream is proven by the
            # first application packet sent after the switch below.
            rekey_kexinit = [
                event
                for event in _events(tc, "out")
                if event[1] == MSG_KEXINIT
            ][1]
            assert rekey_kexinit[2] > 0

            # End-to-end proof that both sides really switched contexts: a
            # fixed small payload round-trips after the rekey.
            chan.send(SMALL_PAYLOAD)
            assert schan.recv(len(SMALL_PAYLOAD)) == SMALL_PAYLOAD
            # The data packet is the first packet of the new epoch and is
            # authenticated at seqno 0 against the post-rekey MAC key.
            post_rekey = _events(tc, "out")[newkeys_out[1] + 1 :]
            assert post_rekey and post_rekey[0][2] == 0
            assert post_rekey[0][1] == MSG_CHANNEL_DATA

    def test_ext_info_is_allowed_as_first_post_newkeys_packet(self):
        # Positive control for extension messages: the server's EXT_INFO is
        # the only thing permitted between NEWKEYS and the first user packet,
        # and it travels on the reset stream (seqno 0 of the new epoch).
        with server(
            defer=True,
            transport_factory=TracingTransport,
            server_transport_factory=TracingTransport,
        ) as (tc, ts):
            server_out = _events(ts, "out")
            newkeys_index = _types(ts, "out").index(MSG_NEWKEYS)
            assert server_out[newkeys_index + 1][1] == MSG_EXT_INFO
            assert server_out[newkeys_index + 1][2] == 0
            # The client accepts it as an ordinary extension, not an order
            # violation, and remains in the post-NEWKEYS state.
            client_in = _events(tc, "in")
            assert client_in[newkeys_index + 1][1] == MSG_EXT_INFO
            assert client_in[newkeys_index + 1][2] == 0
            assert tc.initial_kex_done and not tc.saved_exception


class TestNonStrictAndForeignMessages:
    @mark.parametrize("strict_side", ["client", "server"])
    def test_one_side_opting_out_disables_strict_everywhere(
        self, strict_side
    ):
        # Negotiation is AND: a missing kex-strict marker on either side
        # means neither side may reset seqnos or enforce ordering.
        kwargs = (
            dict(client_init=dict(strict_kex=False))
            if strict_side == "client"
            else dict(server_init=dict(strict_kex=False))
        )
        with server(
            transport_factory=TracingTransport,
            server_transport_factory=TracingTransport,
            **kwargs,
        ) as (tc, ts):
            assert not tc.agreed_on_strict_kex
            assert not ts.agreed_on_strict_kex
            # No reset happened: counters continue past the NEWKEYS boundary.
            assert _seq_in(tc.packetizer) > 0
            assert _seq_out(tc.packetizer) > 0
            assert tc.is_authenticated()

    @mark.parametrize("ptype", [MSG_IGNORE, MSG_DEBUG])
    def test_foreign_message_in_initial_strict_kex_fails_before_newkeys(
        self, ptype
    ):
        # Shortest failing sequence:
        #   KEXINIT/KEXDH exchange (strict agreed) -> rogue packet -> abort.
        # The failure must land before NEWKEYS, inside the initial exchange.
        class Server(RogueMessageTransport):
            rogue = ptype

        with raises(MessageOrderError):
            with server(server_transport_factory=Server):
                pass

    def test_same_foreign_message_is_tolerated_when_not_strict(self):
        # Control for the above: without strict agreement the exchange is
        # allowed to finish, proving the guard is strict-mode specific.
        with server(
            server_transport_factory=RogueMessageTransport,
            client_init=dict(strict_kex=False),
            server_init=dict(strict_kex=False),
        ) as (tc, ts):
            assert not tc.agreed_on_strict_kex
            assert MSG_IGNORE in _types(ts, "out")
            assert tc.is_authenticated()

    def test_foreign_message_during_later_rekey_is_tolerated(self):
        # Strict ordering only protects the *initial* kex. During a rekey the
        # stream is already protected, so an injected IGNORE must not abort
        # the second exchange.
        with server(
            transport_factory=TracingTransport,
            server_transport_factory=RekeyRogueTransport,
        ) as (tc, ts):
            tc.renegotiate_keys()
            assert ts._negotiations == 2
            assert MSG_IGNORE in _types(ts, "out")
            assert tc.is_active() and ts.is_active()
            assert tc.saved_exception is None


class TestSeqnoResetMutation:
    # Mutation under test: the client drops the post-NEWKEYS reset in one
    # direction only; the other direction delegates to the real Packetizer.
    # Shortest failing sequence for either direction:
    #   KEXINIT..KEXDH exchange -> NEWKEYS exchanged -> first packet of the
    #   new epoch authenticated with a stale seqno -> "Mismatched MAC".
    # The failure is never inside the key exchange; it is always on the first
    # packet after the switch.

    def test_missing_inbound_reset_breaks_first_post_newkeys_packet(self):
        # Client keeps counting its inbound stream instead of zeroing it, so
        # the server's first post-NEWKEYS packet (EXT_INFO, which the peer
        # authenticated at seqno 0) is MAC-checked against the client's stale
        # context and rejected.
        with server(
            catch_error=True,
            transport_factory=InboundResetMutantTransport,
        ) as (tc, _, err):
            assert isinstance(err, SSHException)
            assert "Mismatched MAC" in str(err)
            # Last packet accepted before the error is NEWKEYS; the following
            # inbound packet never reaches the event list because its MAC is
            # verified first.
            assert _events(tc, "in")[-1][1] == MSG_NEWKEYS
            assert tc.initial_kex_done

    def test_missing_outbound_reset_breaks_first_post_newkeys_packet(self):
        # Client keeps counting after sending NEWKEYS, so its first
        # application packet (SERVICE_REQUEST) carries the old stream's seqno
        # and the correctly-zeroed server rejects it.
        with server(
            catch_error=True,
            transport_factory=OutboundResetMutantTransport,
        ) as (tc, _, err):
            assert isinstance(err, SSHException)
            assert "Mismatched MAC" in str(err)
            out_events = _events(tc, "out")
            newkeys_index = _types(tc, "out").index(MSG_NEWKEYS)
            first_after = out_events[newkeys_index + 1]
            assert first_after[1] == MSG_SERVICE_REQUEST
            assert first_after[2] != 0


class TestOrderEnforcementMutation:
    # Mutation under test: relax the in-exchange foreign-message guard.
    # Expected shortest failing sequence:
    #   strict KEXINIT agreed -> rogue IGNORE inside the exchange is wrongly
    #   accepted -> NEWKEYS -> handshake completes. A correct implementation
    #   raises MessageOrderError before NEWKEYS instead.

    def test_disabled_guard_lets_rogue_packet_through_initial_kex(self):
        # Baseline: a strict client with the real guard rejects the rogue
        # packet before NEWKEYS, leaving the initial kex unfinished.
        with raises(MessageOrderError):
            with server(
                server_transport_factory=RogueMessageTransport,
            ):
                pass

        # Mutant: with the guard neutralized the same wire sequence is
        # wrongly tolerated and the exchange runs all the way through. A
        # source-level guard regression makes these two behave identically,
        # which the baseline assertion above then fails on.
        with server(
            catch_error=True,
            transport_factory=LaxOrderTransport,
            server_transport_factory=RogueMessageTransport,
        ) as (tc, ts, err):
            assert err is None
            assert MSG_IGNORE in _types(ts, "out")
            assert MSG_NEWKEYS in _types(tc, "in")
            assert tc.saved_exception is None
            assert tc.initial_kex_done
