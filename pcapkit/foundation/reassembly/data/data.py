# -*- coding: utf-8 -*-
"""shared data models for reassembly"""

from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import StrEnum, auto
from pcapkit.utilities.pickle import ReduceAsProtocol2

__all__ = ['ReassemblyData', 'Completion', 'Deferred']

if TYPE_CHECKING:
    from typing import Any, Callable, Optional

    from pcapkit.const.reg.apptype import TCP as AppType_TCP
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.const.tls.handshake_type import HandshakeType
    from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram
    from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.protocols.application.dtls.data import DTLSHandshake
    from pcapkit.protocols.protocol import ProtocolBase

# registry key an analyser dispatches a reassembled payload on; see ``Deferred``
_KT = TypeVar('_KT', 'TransType', 'tuple[AppType_TCP, AppType_TCP]', 'tuple[HandshakeType, int, int]')


class Completion(EnumLookup, StrEnum):
    """How completely a datagram was reassembled, and why it stopped.

    Derives from :class:`~pcapkit.corekit.enum.EnumLookup` per GitHub issue
    :issue:`877`'s ruling that every non-registry enumeration shares that lookup
    contract; the class defines neither ``get`` nor ``_missing_`` of its own.

    This is the value of
    :attr:`Datagram.completed <pcapkit.foundation.reassembly.data.ip.Datagram.completed>`,
    which widens a plain :obj:`bool` rather than adding a second channel beside
    it: reassembly has more outcomes to report than a :obj:`bool` can hold, since
    a buffer abandoned under the :rfc:`1122` / :rfc:`8200` reassembly timeout is
    a different event from one that simply had not finished when the capture
    did. An expired datagram says "these fragments are gone", a partial one says
    "these fragments had not arrived yet".

    Truthiness is that of a :obj:`bool`: :attr:`COMPLETE` is the only truthy
    member, so ``if datagram.completed:`` reads as it would for a boolean.
    Equality against :obj:`True` and :obj:`False` is *not* preserved --
    ``datagram.completed == True`` is :data:`False` even for a complete datagram --
    so a caller comparing against a boolean has to compare against a member
    instead.

    It derives from :mod:`pcapkit.utilities.compat`'s ``StrEnum``, as
    :class:`~pcapkit.protocols.application.httpv1.protocol.Type` does, which buys what a
    plain :class:`enum.Enum` does not: the value survives
    :func:`json.dumps` -- a plain enumeration raises :exc:`TypeError` there, and
    :meth:`Datagram.to_dict <pcapkit.corekit.infoclass.Info.to_dict>` hands this
    field straight out -- and ``datagram.completed == 'timeout'`` works, so a
    state can be tested for without importing this class.
    :class:`pcapkit.const.pcapng.tls_key_label.TLSKeyLabel` is the same kind of
    string enumeration, but it is generated like its :mod:`pcapkit.const.pcapng`
    siblings (:issue:`886`), so it derives from |aenum|_'s own
    ``StrEnum``, alongside :class:`~pcapkit.corekit.enum.EnumRegistry`. The
    properties above hold for it, as ``aenum.StrEnum`` is a :class:`str`
    subclass, but ``isinstance``/``issubclass`` against
    ``pcapkit.utilities.compat.StrEnum`` does not on Python 3.11 and later,
    where that name is the stdlib ``enum.StrEnum``.

    Warning:
        Being a :class:`str` whose members other than :attr:`COMPLETE` are
        **falsy** makes this a non-empty string that tests false, so ``bool(x)``
        and ``bool(str(x))`` disagree. That is deliberate -- the truthiness above
        is what lets ``if datagram.completed:`` read as a boolean test -- but code
        that takes this for an ordinary string and tests it for truth will read it
        backwards.

    """

    #: Reassembled in whole: every octet of the datagram was received.
    COMPLETE = auto()

    #: Fragments were still outstanding when the buffer was flushed -- at the end
    #: of the capture, or when the session was torn down (a TCP RST, a TCP SYN on
    #: a 4-tuple already buffered, or an IPv4 datagram whose identifier was
    #: reused by an unfragmented packet).
    #: The missing octets may simply not have been captured.
    PARTIAL = auto()

    #: Reassembly was **abandoned** under the reassembly timeout, i.e. the
    #: capture clock advanced past the deadline of
    #: :attr:`Reassembly.timeout
    #: <pcapkit.foundation.reassembly.reassembly.Reassembly.timeout>`
    #: seconds after the first-arriving fragment while the datagram was still
    #: incomplete. :rfc:`8200#section-4.5` requires the held fragments be
    #: discarded, so no further fragment will ever be added to this datagram.
    TIMEOUT = auto()

    #: Reassembly was **abandoned** because a fragment overlapped another of the
    #: same datagram without being an exact duplicate of it, which
    #: :rfc:`8200#section-4.5` discards an IPv6 datagram for. The overlapping
    #: fragment's octets are not in the payload; ``conflict`` still lists where
    #: they disagreed with the octets kept.
    #:
    #: .. versionadded:: 1.6.0
    OVERLAP = auto()

    def __bool__(self) -> 'bool':
        """Whether the datagram was reassembled in whole.

        Only :attr:`COMPLETE` is truthy; every other member describes an
        incomplete datagram.

        Note:
            This override is what a :class:`str` base does *not* give -- every
            non-empty string is otherwise truthy, which would make an incomplete
            datagram read as a complete one. ``__str__`` needs no such
            override: :mod:`pcapkit.utilities.compat`'s ``StrEnum`` already
            renders a member as its value.

        """
        return self is Completion.COMPLETE


class Deferred(ReduceAsProtocol2, Generic[_KT]):
    """A postponed analysis of a reassembled payload.

    A reassembled datagram's ``packet`` is a second, full parse of the payload
    the datagram just reassembled. Nothing about postponing it is specific to any
    one reassembler, which is why this lives beside
    :class:`~pcapkit.foundation.reassembly.data.data.ReassemblyData` rather than in
    any one protocol's data module.

    IP reassembly is the case that made it necessary. IPv4 reassembly submits a
    datagram for *every* frame whose **DF** flag is clear -- not only the
    fragmented ones, since an unfragmented frame still reaches
    :meth:`IP.reassembly <pcapkit.foundation.reassembly.ip.IP.reassembly>` and is
    submitted there as a trivially complete datagram -- so an eager parse would
    re-parse captures holding no fragments at all: :file:`http.pcap` has 1117
    IPv4 frames, none of them fragmented, and the eager parse measured 86% of the
    cost of IP reassembly over it.

    TCP reassembly defers its ``packet`` as well
    (:meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>`), at a far
    smaller saving, being FIN/RST-driven rather than per-frame -- 222 submits per
    :file:`http.pcap` pass against 1117. DTLS reassembly defers its own for
    parity with IP and TCP rather than for a saving, since a handshake message
    reaches it only once fragmented (:issue:`2531`).

    Holding the call here defers it to the first read of
    :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.ip.Datagram.packet>`,
    where :class:`~pcapkit.corekit.packet.DeferredPacket` runs it, so a caller that
    wants the parsed payload still gets exactly the object an eager call would
    produce, and one that does not never pays for it.

    The class is generic because the reassemblers do *not* dispatch on the
    same kind of value, and each analyser declares the one it takes. The type
    parameter is that value's type, so an instance's ``proto`` and the parameter
    its ``analyze`` expects are the same type rather than a union every call
    site would have to widen to:

    * :meth:`IP.submit <pcapkit.foundation.reassembly.ip.IP.submit>` builds a
      ``Deferred[TransType]``. It passes the payload protocol type, a
      :class:`~pcapkit.const.reg.transtype.TransType` read from the reassembled
      datagram's **Protocol** / **Next Header** field, to the parse
      :func:`~pcapkit.foundation.analysis.ip.ip_datagram` runs:
      :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`,
      which looks the next layer up by protocol registry number.
    * :meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` builds a
      ``Deferred[tuple[AppType_TCP, AppType_TCP]]``. It passes a
      ``(source, destination)`` port pair to the parse
      :func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` runs, because
      :meth:`Transport.analyze
      <pcapkit.protocols.transport.transport.Transport.analyze>` overrides that
      parameter to one: a reassembled transport-layer payload carries no
      protocol number, so its application protocol is inferred from the ports.
    * :meth:`DTLS._datagram_from_fragment
      <pcapkit.foundation.reassembly.dtls.DTLS._datagram_from_fragment>` builds a
      ``Deferred[tuple[HandshakeType, int, int]]`` for a complete message. It
      passes the message's ``(msg_type, length, message_seq)``, its handshake
      header as if unfragmented (:rfc:`6347#section-4.2.3`), to the decoder
      :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` runs,
      :meth:`DTLS.analyze_handshake
      <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`, which reads
      the body by its :class:`~pcapkit.const.tls.handshake_type.HandshakeType`.

    Those are the cases the type parameter is constrained to. IP's and TCP's are
    *named registry values* rather than one named value and one pair of bare
    port numbers: a port is a member of
    :class:`~pcapkit.const.reg.apptype.tcp.TCP` here -- the per-transport
    registry itself, not the base
    :class:`~pcapkit.const.reg.apptype.apptype.AppType`, since that is what
    :meth:`TCP._make_ports <pcapkit.foundation.reassembly.tcp.TCP._make_ports>`
    really answers with -- so what the deferred analysis dispatches on is of a
    piece with what the eager path dispatches on at
    :attr:`TCP.src <pcapkit.protocols.transport.tcp.protocol.TCP.src>`, whichever
    reassembler built it. (Of a piece, not identical: for an *unassigned* port
    the two paths build equal members by different routes, which
    ``TCP.submit``'s own docstring records.)

    The pairing the regression actually produced -- a port pair handed to an
    analyser declared over :class:`~pcapkit.const.reg.transtype.TransType` --
    is rejected, which is the direction a real mismatch takes and the one
    :issue:`2417` was about.

    Rejecting the *reverse* pairing is not guaranteed by mypy alone, for a
    reason outside this class: |aenum|_ ships no type stubs, so under
    ``ignore_missing_imports`` the ``aenum.IntEnum`` base of
    :class:`~pcapkit.const.reg.transtype.TransType` resolves to ``Any``. A
    ``TransType`` is therefore accepted where a
    ``tuple[AppType_TCP, AppType_TCP]`` is
    expected, and a ``Deferred[TransType]`` built over the port-pair analyser
    type-checks clean. That is a gap in the dependency's type coverage rather
    than in the constraint, which would bite both ways were ``TransType`` fully
    typed; the values the reassemblers really pass are pinned by the tests
    either way.

    Args:
        analyze: The analyser to call: the parse
            :mod:`pcapkit.foundation.analysis` runs for the engine, bound to
            the reassembly object's protocol for IP and TCP, whose ``analyze``
            it calls, and that protocol's ``analyze_handshake`` for DTLS.
        proto: What the analyser dispatches the payload on -- the payload
            protocol type for IP, the port pair for TCP, the handshake header
            for DTLS, as above.
        payload: Reassembled payload to parse.

    .. versionadded:: 1.5.0

    .. versionchanged:: 1.6.0

       Also constrained to the DTLS handshake header, and the analyser may
       return a :class:`~pcapkit.protocols.application.dtls.data.DTLSHandshake`
       (:issue:`2531`). IP's and TCP's analyser is the parse their
       :mod:`pcapkit.foundation.analysis` module runs, bound to the
       reassembly's protocol, rather than that protocol's bound ``analyze``
       (:issue:`2581`). Protocol 0 and 1 reduce as protocol 2 does, through
       :class:`~pcapkit.utilities.pickle.ReduceAsProtocol2`, which carries the
       slots in Python's own default state, in place of a reduction and a
       ``__getstate__`` of its own (:issue:`2714`).

    """

    __slots__ = ('analyze', 'proto', 'payload')

    def __init__(self, analyze: 'Callable[[_KT, bytes], ProtocolBase | DTLSHandshake]',
                 proto: '_KT', payload: 'bytes') -> 'None':
        # NOTE: annotated on assignment, as in :mod:`pcapkit.corekit.multidict`: mypy cannot infer
        # a slotted attribute's type from a type variable.
        self.analyze: 'Callable[[_KT, bytes], ProtocolBase | DTLSHandshake]' = analyze
        self.proto: '_KT' = proto
        self.payload = payload

    def __call__(self) -> 'ProtocolBase | DTLSHandshake':
        """Run the postponed analysis.

        Returns:
            Parsed payload.

        """
        return self.analyze(self.proto, self.payload)

    def __setstate__(
        self,
        state: 'tuple[Optional[dict[str, Any]], dict[str, Any]] | dict[str, Any]',
    ) -> 'None':
        """Unpickling support.

        Accepts the ``(dict_or_None, slots)`` pair Python's own default state
        construction builds for a slotted class, which every pickle of this
        class carries under protocol 2 and above, and which
        :class:`~pcapkit.utilities.pickle.ReduceAsProtocol2` carries under
        protocol 0 and 1 too. It also accepts a bare :obj:`dict` of
        ``{slot: value}``, the state a first, unreleased fix for :issue:`2423`
        pickled (:issue:`2425`).

        """
        if isinstance(state, dict):
            dict_state, slots = None, state
        else:
            dict_state, slots = state
        if dict_state:
            self.__dict__.update(dict_state)
        for slot, value in slots.items():
            setattr(self, slot, value)


@info_final
class ReassemblyData(Info):
    """Data storage for reassembly."""

    #: IPv4 reassembled data.
    ipv4: 'tuple[IP_Datagram, ...]'
    #: IPv6 reassembled data.
    ipv6: 'tuple[IP_Datagram, ...]'
    #: TCP reassembled data.
    tcp: 'tuple[TCP_Datagram, ...]'
    #: DTLS reassembled handshake messages.
    dtls: 'tuple[DTLS_Datagram, ...]'

    if TYPE_CHECKING:
        def __init__(self, ipv4: 'Optional[tuple[IP_Datagram, ...]]', ipv6: 'Optional[tuple[IP_Datagram, ...]]', tcp: 'Optional[tuple[TCP_Datagram, ...]]', dtls: 'Optional[tuple[DTLS_Datagram, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
