# -*- coding: utf-8 -*-
"""shared data models for reassembly"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

__all__ = ['ReassemblyData', 'Deferred']

if TYPE_CHECKING:
    from typing import Callable, Optional

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
