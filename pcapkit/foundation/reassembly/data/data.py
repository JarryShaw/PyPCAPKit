# -*- coding: utf-8 -*-
"""shared data models for reassembly"""

import copyreg
from typing import TYPE_CHECKING, Generic, TypeVar

from pcapkit.corekit.enum import EnumLookup
from pcapkit.corekit.infoclass import Info, info_final
from pcapkit.utilities.compat import StrEnum, auto

__all__ = ['ReassemblyData', 'Completion', 'Deferred']

if TYPE_CHECKING:
    from typing import Any, Callable, Optional, SupportsIndex

    from pcapkit.const.reg.apptype import TCP as AppType_TCP
    from pcapkit.const.reg.transtype import TransType
    from pcapkit.const.tls.handshake_type import HandshakeType
    from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram
    from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.protocols.data.application.dtls import DTLSHandshake
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
    :class:`~pcapkit.protocols.application.httpv1.Type` does, which buys what a
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


class Deferred(Generic[_KT]):
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
      datagram's **Protocol** / **Next Header** field, to
      :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`,
      which looks the next layer up by protocol registry number.
    * :meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` builds a
      ``Deferred[tuple[AppType_TCP, AppType_TCP]]``. It passes a
      ``(source, destination)`` port pair, because :meth:`Transport.analyze
      <pcapkit.protocols.transport.transport.Transport.analyze>` overrides that
      parameter to one: a reassembled transport-layer payload carries no
      protocol number, so its application protocol is inferred from the ports.
    * :meth:`DTLS._datagram_from_fragment
      <pcapkit.foundation.reassembly.dtls.DTLS._datagram_from_fragment>` builds a
      ``Deferred[tuple[HandshakeType, int, int]]`` for a complete message. It
      passes the message's ``(msg_type, length, message_seq)``, its handshake
      header as if unfragmented (:rfc:`6347#section-4.2.3`), to the decoder
      :func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` runs, which reads
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
    :attr:`TCP.src <pcapkit.protocols.transport.tcp.TCP.src>`, whichever
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
        analyze: The analyser to call:
            :meth:`Protocol.analyze <pcapkit.protocols.protocol.Protocol.analyze>`
            bound to the reassembly object's protocol for IP and TCP, the
            handshake decoder for DTLS.
        proto: What the analyser dispatches the payload on -- the payload
            protocol type for IP, the port pair for TCP, the handshake header
            for DTLS, as above.
        payload: Reassembled payload to parse.

    .. versionadded:: 1.5.0

    .. versionchanged:: 1.6.0

       Also constrained to the DTLS handshake header, and the analyser may
       return a :class:`~pcapkit.protocols.data.application.dtls.DTLSHandshake`
       (:issue:`2531`).

    """

    __slots__ = ('analyze', 'proto', 'payload')

    def __init__(self, analyze: 'Callable[[_KT, bytes], ProtocolBase | DTLSHandshake]',
                 proto: '_KT', payload: 'bytes') -> 'None':
        # NOTE: the two type-parameterized attributes are annotated on their
        # assignment, as ``_omd_bucket`` in :mod:`pcapkit.corekit.multidict`
        # does. A slotted class declares no class-level attributes, so mypy
        # infers each one from this assignment, and it cannot infer a *class*
        # attribute's type from a type variable -- it asks for an annotation
        # instead. ``payload`` needs none: :obj:`bytes` is inferred.
        self.analyze: 'Callable[[_KT, bytes], ProtocolBase | DTLSHandshake]' = analyze
        self.proto: '_KT' = proto
        self.payload = payload

    def __call__(self) -> 'ProtocolBase | DTLSHandshake':
        """Run the postponed analysis.

        Returns:
            Parsed payload.

        """
        return self.analyze(self.proto, self.payload)

    def __reduce_ex__(self, protocol: 'SupportsIndex') -> 'Any':
        """Pickling support for protocol 0 and 1.

        :meth:`object.__reduce_ex__` hands protocol 0 and 1 off to
        :func:`copyreg._reduce_ex`, which -- *before* it ever consults
        :meth:`__getstate__` -- walks ``type(self).__mro__`` looking for the
        first base that is either not a heap type or whose own ``__new__`` is
        bound to itself, to compute a base-object state via ``base(self)``. On
        CPython, :class:`~typing.Generic` is a heap type and its ``__new__``
        is just the inherited ``object.__new__`` (bound to ``object``, not to
        ``Generic``), so neither check fires there and the walk continues to
        :class:`object` itself, which *is* a non-heap type -- the walk's first
        check breaks on it, so ``base`` is ``object`` and the computed state is
        :data:`None`. On GraalPy 25.4, ``Generic`` is itself a non-heap
        (built-in) type there -- ``Generic.__flags__`` lacks ``_HEAPTYPE`` --
        so the walk's *first* check breaks on ``Generic`` directly, one step
        earlier than on CPython, without ever reaching the ``__new__`` check
        at all. ``base`` therefore resolves to ``Generic`` itself, and the
        walk calls ``Generic(self)``, which raises::

            TypeError: typing.Generic() takes no arguments

        :meth:`__getstate__`/:meth:`__setstate__` never run in that failure:
        they only ever supply the *dict* half of the reduction tuple the walk
        above is computing the *base-object* half for, so defining them
        (:issue:`2423`, :issue:`2425`) does nothing to protect against a
        GraalPy-specific outcome of a walk that happens before either is
        consulted.

        This override sidesteps the walk entirely rather than trying to steer
        it: for protocol 0 and 1 it hard-codes the one outcome the walk was
        ever going to reach for this class -- ``base=object``,
        ``state=None`` -- and builds the same ``(callable, args, state)``
        reduction :func:`copyreg._reduce_ex` itself would have, with
        :meth:`__getstate__`'s own ``(dict_or_None, slots)`` pair as the
        third element, restored through :meth:`__setstate__` exactly as
        before. ``Deferred`` has no base below :class:`object` that could
        need special handling -- :class:`~typing.Generic` carries no runtime
        state of its own -- so hard-coding that outcome changes nothing about
        *what* gets pickled, only *how* protocol 0 and 1 get there: the MRO
        walk, and ``Generic`` along with it, is no longer part of the route at
        all. Protocol 2 and above are untouched, deferring to
        :meth:`object.__reduce_ex__` exactly as before this method existed --
        their own ``__reduce_ex__`` never walked the MRO this way to begin
        with, building a reduction straight from ``__getstate__`` instead.

        A subclass that overrides ``__reduce__`` is checked for first, and
        deferred to, before any of the above: :meth:`object.__reduce_ex__`
        itself does this -- for *every* protocol, including 0 and 1, it
        calls a non-default ``__reduce__`` in preference to building a
        reduction of its own -- so hard-coding the protocol 0/1 tuple here
        without the same check would silently drop such a subclass's
        override at exactly those two protocols, while protocol 2 and above
        (going through ``object.__reduce_ex__`` unchanged) kept honouring
        it.

        """
        if type(self).__reduce__ is not object.__reduce__:
            return self.__reduce__()
        if int(protocol) >= 2:
            return object.__reduce_ex__(self, protocol)
        return (copyreg._reconstructor, (type(self), object, None),  # type: ignore[attr-defined] # pylint: disable=protected-access
                self.__getstate__())

    def __getstate__(self) -> 'tuple[Optional[dict[str, Any]], dict[str, Any]]':
        """Pickling support.

        A slotted class with no ``__dict__`` has nothing for the default
        :mod:`pickle` reduction to read. :mod:`copyreg` refuses outright with
        *"cannot be pickled"* under protocol 0 or 1 whenever
        ``type(self).__getstate__`` is still the inherited default -- which is
        why defining *any* ``__getstate__`` here, even one that only calls the
        default, clears protocols 0 and 1 (:issue:`2423`). Protocol 2 and above
        never needed one: their own ``__reduce_ex__`` already walks
        ``__slots__`` directly.

        The shape returned -- an instance-``__dict__`` state (or :data:`None`)
        paired with a slots-state :obj:`dict` -- is deliberately the same one
        Python's own default state construction produces for a slotted class,
        rather than a bespoke flat :obj:`dict`. A flat shape would be a *new*
        pickle format for this class: a ``Deferred`` already pickled by a
        released version under protocol 2 or above -- every one of them built
        this same ``(dict_or_None, slots)`` pair -- would fail to unpickle
        against a flat-shaped :meth:`__setstate__`, and the reverse.

        The slot names come from :func:`copyreg._slotnames`, the standard
        library's own helper for this exact job, rather than a hand-rolled
        walk of ``type(self).__mro__`` and each class's ``__slots__``: a
        subclass of ``Deferred`` may spell a slot as a bare string
        (``__slots__ = 'extra'``, valid Python for one slot named by the
        whole string) or as a private, name-mangled one
        (``__slots__ = ('__secret',)``, stored on the instance under
        ``_<ClassName>__secret``), and a hand-rolled walk that assumes every
        ``__slots__`` is an iterable of already-resolved attribute names gets
        both wrong -- the first by iterating the string's *characters*, the
        second by testing the unmangled name ``hasattr`` never finds
        (:issue:`2425`). ``_slotnames`` already handles both, the same way
        protocol 0 and 1 reduction has relied on it to for decades.

        """
        slotnames = copyreg._slotnames(type(self))  # type: ignore[attr-defined] # pylint: disable=protected-access
        slots = {name: getattr(self, name) for name in slotnames if hasattr(self, name)}
        dict_state = dict(self.__dict__) if getattr(self, '__dict__', None) else None
        return (dict_state, slots)

    def __setstate__(
        self,
        state: 'tuple[Optional[dict[str, Any]], dict[str, Any]] | dict[str, Any]',
    ) -> 'None':
        """Unpickling support; the counterpart to :meth:`__getstate__`.

        Accepts the ``(dict_or_None, slots)`` pair :meth:`__getstate__` builds
        above -- the shape every released, pre-:issue:`2423` pickle already
        used under protocol 2 and above -- and, for a pickle made by this
        class's own first, unreleased fix for :issue:`2423`, a bare :obj:`dict`
        of ``{slot: value}`` (:issue:`2425`).

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
