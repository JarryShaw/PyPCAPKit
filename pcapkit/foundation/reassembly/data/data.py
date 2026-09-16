# -*- coding: utf-8 -*-
"""shared data models for reassembly"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = ['ReassemblyData', 'Deferred', 'DeferredPacket']

if TYPE_CHECKING:
    from typing import Callable, Optional

    from typing import Any

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.protocols.protocol import ProtocolBase as Protocol


class Deferred:
    """A postponed analysis of a reassembled payload.

    A reassembled datagram's ``packet`` is a second, full parse of the payload
    the datagram just reassembled. Nothing about postponing it is specific to any
    one reassembler, which is why this lives beside
    :class:`~pcapkit.foundation.reassembly.data.ReassemblyData` rather than in
    either protocol's data module.

    IP reassembly is the case that made it necessary. It submits a datagram for
    *every* frame -- not only the fragmented ones, since a frame that is not
    fragmented in any sense still reaches
    :meth:`IP.reassembly <pcapkit.foundation.reassembly.ip.IP.reassembly>` and is
    submitted there as a trivially complete datagram -- so the eager parse
    re-parsed captures holding no fragments at all: :file:`http.pcap` has 1117
    IPv4 frames, none of them fragmented, and the parse was 86% of the cost of IP
    reassembly over it.

    TCP reassembly builds its ``packet`` eagerly too
    (:meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>`). It is a
    far smaller cost there, being FIN/RST-driven rather than per-frame -- 222
    submits per :file:`http.pcap` pass against 1117 -- so it is left for its own
    change, but it can use this unmodified when someone gets to it.

    Holding the call here defers it to the first read of
    :attr:`Datagram.packet`, so a caller that wants the parsed payload still gets
    exactly the object the eager call produced, and one that does not never pays
    for it.

    Args:
        analyze: The analyser to call, i.e.
            :meth:`Protocol.analyze <pcapkit.protocols.protocol.ProtocolBase.analyze>`
            bound to the reassembly object's protocol.
        proto: Payload protocol type.
        payload: Reassembled payload to parse.

    """

    __slots__ = ('analyze', 'proto', 'payload')

    def __init__(self, analyze: 'Callable[[TransType, bytes], Protocol]',
                 proto: 'TransType', payload: 'bytes') -> 'None':
        self.analyze = analyze
        self.proto = proto
        self.payload = payload

    def __call__(self) -> 'Protocol':
        """Run the postponed analysis.

        Returns:
            Parsed payload.

        """
        return self.analyze(self.proto, self.payload)


class DeferredPacket:
    """Resolves a :class:`Deferred` ``packet`` field on first read.

    A reassembled datagram's ``packet`` is the parsed form of the payload it just
    reassembled, and both reassemblers can hand a :class:`Deferred` in its place.
    This carries the reading half of that arrangement, so the two ``Datagram``
    models share it rather than each declaring it.

    A subclass has to list ``packet`` in its ``__additional__``. That is what makes
    the field lazy at all: :class:`~pcapkit.corekit.infoclass.Info` stores a field
    whose name is a *builtin* name under a mangled key and maps it back on the way
    out, so ``packet`` never lands in :attr:`~object.__dict__` itself -- which
    routes reading it through :meth:`__getattr__`, where the deferred analysis can
    run, while ``dict(datagram)``, :meth:`to_dict` and iteration still report the
    field under its own name.

    """

    def __analyse__(self) -> 'Optional[Protocol]':
        """Resolve a deferred analysis, at most once.

        Returns:
            Parsed IP payload, or :data:`None` for an incomplete datagram.

        """
        key = self.__map__.get('packet', 'packet')
        value = self.__dict__[key]
        if isinstance(value, Deferred):
            value = value()
            self.__dict__[key] = value
        return value

    def __getattr__(self, name: 'str') -> 'Any':
        # NOTE: reached only for names absent from ``__dict__``, which ``packet``
        # always is -- see ``__additional__`` above. Everything else has to raise,
        # or a typo would silently answer with a parsed payload.
        if name != 'packet':
            raise AttributeError(f'{type(self).__name__!r} object has no attribute {name!r}')
        return self.__analyse__()

    def __getitem__(self, name: 'str') -> 'Any':
        if name == 'packet':
            return self.__analyse__()
        return super().__getitem__(name)

    def __contains__(self, name: 'object') -> 'bool':
        # NOTE: ``Mapping.__contains__`` answers by fetching the value, which
        # would run the deferred analysis merely to decide that the field exists.
        # ``packet`` is a declared field, so it is always there.
        return name == 'packet' or super().__contains__(name)

    def __str__(self) -> 'str':
        self.__analyse__()
        return super().__str__()

    def __repr__(self) -> 'str':
        self.__analyse__()
        return super().__repr__()

    def to_dict(self) -> 'dict[str, Any]':
        """Convert :class:`Datagram` into :obj:`dict`.

        Returns:
            The datagram's fields, with ``packet`` analysed if it had not been
            read yet -- a :obj:`dict` holding a :class:`Deferred` would leak an
            implementation detail into what is meant to be plain data.

        """
        self.__analyse__()
        return super().to_dict()


@info_final
class ReassemblyData(Info):
    """Data storage for reassembly."""

    #: IPv4 reassembled data.
    ipv4: 'tuple[IP_Datagram, ...]'
    #: IPv6 reassembled data.
    ipv6: 'tuple[IP_Datagram, ...]'
    #: TCP reassembled data.
    tcp: 'tuple[TCP_Datagram, ...]'

    if TYPE_CHECKING:
        def __init__(self, ipv4: 'Optional[tuple[IP_Datagram, ...]]', ipv6: 'Optional[tuple[IP_Datagram, ...]]', tcp: 'Optional[tuple[TCP_Datagram, ...]]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
