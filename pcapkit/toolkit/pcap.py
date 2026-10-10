# -*- coding: utf-8 -*-
"""PCAP Tools
================

.. module:: pcapkit.toolkit.pcap

:mod:`pcapkit.toolkit.pcap` contains the adapters for the PCAP format.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it. The TCP adapters here and in
:mod:`pcapkit.toolkit.pcapng` read the segment with
:func:`~pcapkit.toolkit.pcap.tcp_segment`.

"""
from typing import TYPE_CHECKING, NamedTuple, cast

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.internet.ip import IP as Protocol_IP
from pcapkit.protocols.misc.null import NoPayload
from pcapkit.protocols.misc.raw import Raw
from pcapkit.protocols.protocol import ProtocolBase
from pcapkit.protocols.transport.tcp import TCP

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Optional

    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.protocols.data.internet.ipv4 import IPv4 as Data_IPv4
    from pcapkit.protocols.data.internet.ipv6 import IPv6 as Data_IPv6
    from pcapkit.protocols.internet.ipv4 import IPv4
    from pcapkit.protocols.internet.ipv6 import IPv6
    from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
    from pcapkit.protocols.misc.pcap import Frame

__all__ = ['ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
           'tcp_segment', 'TCPSegment']


class TCPSegment(NamedTuple):
    """The fields of a TCP segment that the reassembly and flow tracing records take.

    :func:`tcp_segment` returns one.

    """

    #: Info of the IP layer carrying the segment, the innermost one in a tunnel.
    ip: 'Data_IPv4 | Data_IPv6'
    #: TCP source port.
    srcport: 'int'
    #: TCP destination port.
    dstport: 'int'
    #: TCP sequence number.
    seq: 'int'
    #: TCP acknowledgement number.
    ack: 'int'
    #: TCP synchronise (SYN) flag.
    syn: 'bool'
    #: TCP finish (FIN) flag.
    fin: 'bool'
    #: TCP reset (RST) flag.
    rst: 'bool'
    #: Raw TCP header, as captured.
    header: 'bytes'
    #: Raw TCP payload, as captured.
    payload: 'bytes'


def _carrier(frame: 'ProtocolBase') -> 'tuple[Optional[IPv4 | IPv6], Optional[TCP]]':
    """Fetch the TCP layer of a frame and the IP layer that carries it.

    Args:
        frame: PCAP frame or PCAP-NG block.

    Returns:
        The IPv4 or IPv6 layer nearest above the frame's TCP layer, and that TCP
        layer; with no TCP layer, the last IPv4 or IPv6 layer of the frame and
        :data:`None`. With no IP layer, neither.

    Note:
        The nearest IP layer is the innermost one of an IP-in-IP tunnel
        (:rfc:`2003`, :rfc:`2473`, :rfc:`4213`), whose addresses are the TCP
        endpoints', as in Wireshark's TCP conversations; the outermost, which
        ``frame['IP']`` finds, is the tunnel's (:issue:`1581`). It is found by
        walking down from the outermost, so the headers between them do not
        intervene: IPv6 dissects its own extension headers, and an AH or other
        header inside IPv4 is a layer of its own but not an IP layer.

    """
    if 'IP' not in frame:
        return None, None
    ip = cast('IPv4 | IPv6', frame['IP'])
    layer = ip.payload
    while isinstance(layer, ProtocolBase) and not isinstance(layer, (NoPayload, TCP)):
        if isinstance(layer, Protocol_IP):
            ip = cast('IPv4 | IPv6', layer)
        layer = layer.payload
    return ip, (cast('TCP', frame['TCP']) if 'TCP' in frame else None)


def tcp_segment(frame: 'ProtocolBase') -> 'Optional[TCPSegment]':
    """The TCP segment ``frame`` carries, or :data:`None` if it carries none.

    The TCP reassembly and flow tracing adapters of this module and of
    :mod:`pcapkit.toolkit.pcapng` all read the segment with this.

    Args:
        frame: PCAP frame or PCAP-NG block.

    Returns:
        The fields of the TCP layer if :mod:`pcapkit` parsed one, with those of
        the IP layer that carries it -- in a tunnel, the innermost
        (:issue:`1581`). Otherwise, the fields of the fixed 20-octet TCP header
        (:rfc:`9293#section-3.1`) if the payload of the innermost IP layer is a
        :class:`~pcapkit.protocols.misc.raw.Raw` the TCP parser rejected, of
        protocol TCP, from a datagram that is not a later fragment, with at
        least those 20 octets captured; else :data:`None`. A segment past
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` is kept raw
        without being parsed, not rejected, so it is not read (:issue:`1610`).

    Note:
        A capture snapped inside the TCP header leaves a Data Offset that runs
        past the captured octets, and the TCP parser rejects such a header by
        design (:issue:`1404`), so the segment arrives as
        :class:`~pcapkit.protocols.misc.raw.Raw`. The ports, numbers and flags
        are all in the fixed header, so the segment still belongs to its flow,
        as it does for :mod:`dpkt`, :mod:`scapy` and Wireshark (:issue:`1518`).
        The header and payload are then the captured octets either side of the
        Data Offset. Inside a tunnel, this holds of the IP layer carrying the
        segment, as it does without one.

    """
    ip, tcp = _carrier(frame)
    if ip is None:
        return None
    if tcp is not None:
        tcp_info = tcp.info
        return TCPSegment(
            ip=ip.info,
            srcport=tcp_info.srcport.port,
            dstport=tcp_info.dstport.port,
            seq=tcp_info.seq,
            ack=tcp_info.ack,
            syn=tcp_info.flags.syn,
            fin=tcp_info.flags.fin,
            rst=tcp_info.flags.rst,
            header=tcp.packet.header,
            payload=tcp.packet.payload,
        )

    ip_info = ip.info
    raw = ip.payload
    # NOTE: a Raw with no error is one the caller asked for, by stopping the
    # dissection at a ``layer`` or ``protocol``, not a segment TCP rejected.
    # Nor is one past FRAME_LAYER_LIMIT, which carries an error all the same:
    # the frame is not dissected past it, so its TCP is not read (#1610).
    if (not isinstance(raw, Raw) or raw.info.error is None
            or raw._past_layer_limit  # pylint: disable=protected-access
            or ip_info.protocol != Enum_TransType.TCP):
        return None

    # A later fragment's payload starts mid-datagram, with no TCP header in it.
    if ip_info.version == 4:
        offset = ip_info.offset
    else:
        frag = cast('IPv6', ip).extension_headers.get(Enum_ExtensionHeader.IPv6_Frag)  # type: ignore[call-overload]
        offset = 0 if frag is None else cast('IPv6_Frag', frag).info.offset
    if offset:
        return None

    octets = bytes(raw.packet.payload)
    hdr_len = (octets[12] >> 4) * 4 if len(octets) >= 20 else 0
    if hdr_len < 20:
        return None
    flags = octets[13]
    return TCPSegment(
        ip=ip_info,
        srcport=int.from_bytes(octets[0:2], 'big'),
        dstport=int.from_bytes(octets[2:4], 'big'),
        seq=int.from_bytes(octets[4:8], 'big'),
        ack=int.from_bytes(octets[8:12], 'big'),
        syn=bool(flags & 0x02),
        fin=bool(flags & 0x01),
        rst=bool(flags & 0x04),
        header=octets[:hdr_len],
        payload=octets[hdr_len:],
    )


def ipv4_reassembly(frame: 'Frame') -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        frame: PCAP frame.

    Returns:
       Data for IPv4 reassembly.

        * If the ``frame`` can be used for IPv4 reassembly. A frame can be reassembled
          if it contains IPv4 layer (:class:`~pcapkit.protocols.internet.ipv4.IPv4`) and
          the **DF** (:attr:`IPv4.flags.df <pcapkit.protocols.data.internet.ipv4.Flags.df>`)
          flag is :data:`False`.
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (c.f. :term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    if 'IPv4' in frame:
        ipv4 = cast('IPv4', frame['IPv4'])
        ipv4_info = ipv4.info
        if ipv4_info.flags.df:       # dismiss not fragmented frame
            return None

        data = IP_Packet(
            bufid=(
                ipv4_info.src,                       # source IP address
                ipv4_info.dst,                       # destination IP address
                ipv4_info.id,                        # identification
                ipv4_info.protocol,                  # payload protocol type
            ),
            num=frame.info.number,                   # original packet range number
            fo=ipv4_info.offset,                     # fragment offset
            ihl=ipv4_info.hdr_len,                   # internet header length
            mf=ipv4_info.flags.mf,                   # more fragment flag
            tl=ipv4_info.len,                        # total length, header includes
            header=ipv4.packet.header,               # raw bytes type header
            payload=bytearray(ipv4.packet.payload),  # raw bytearray type payload
            timestamp=float(frame.info.time_epoch),   # capture timestamp
        )
        return data
    return None


def ipv6_reassembly(frame: 'Frame') -> 'IP_Packet[IPv6Address] | None':
    """Make data for IPv6 reassembly.

    Args:
        frame: PCAP frame.

    Returns:
        A tuple of data for IPv6 reassembly.

        * If the ``frame`` can be used for IPv6 reassembly. A frame can be reassembled
          if it contains IPv6 layer (:class:`~pcapkit.protocols.internet.ipv6.IPv6`) and
          IPv6 Fragment header (:rfc:`2460#section-4.5`, i.e.,
          :class:`~pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    if 'IPv6' in frame:
        ipv6 = cast('IPv6', frame['IPv6'])
        ipv6_info = ipv6.info
        if (ipv6_frag := ipv6.extension_headers.get(  # type: ignore[call-overload]
            Enum_ExtensionHeader.IPv6_Frag
        )) is None:  # dismiss not fragmented frame
            return None
        ipv6_frag_info = cast('IPv6_Frag', ipv6_frag).info

        # NOTE: ``Data_IPv6.hdr_len`` counts the Fragment header, since
        # :meth:`IPv6._decode_next_layer <pcapkit.protocols.internet.ipv6.IPv6._decode_next_layer>`
        # adds each extension header's length before the Fragment-header check
        # breaks its loop. That is correct for a header length, but the
        # reassembled packet carries no Fragment header at all
        # (:rfc:`8200#section-4.5`), so the boundary wanted here is the one
        # *before* it -- which is that same length less the Fragment header's,
        # undoing the addition that included it.
        hdr_len = ipv6_info.hdr_len - cast('IPv6_Frag', ipv6_frag).length
        # NOTE: The reassembly machinery writes the payload into its datagram
        # buffer over the span ``tl - ihl``, so ``tl`` is derived from the
        # payload actually handed over rather than from ``raw_len``: the two
        # agree, but only the former cannot drift out of step with it.
        payload = bytearray(ipv6_info.fragment.payload)

        data = IP_Packet(
            bufid=(
                ipv6_info.src,                              # source IP address
                ipv6_info.dst,                              # destination IP address
                ipv6_frag_info.id,                          # identification
                ipv6_frag_info.next,                        # next header field in IPv6 Fragment Header
            ),
            num=frame.info.number,                          # original packet range number
            fo=ipv6_frag_info.offset,                       # fragment offset
            ihl=hdr_len,                                    # header length, only headers before IPv6-Frag
            mf=ipv6_frag_info.mf,                           # more fragment flag
            tl=hdr_len + len(payload),                      # total length, header includes
            header=ipv6_info.fragment.header[:hdr_len],     # raw bytes type header before IPv6-Frag
            payload=payload,                                # raw bytearray type payload after IPv6-Frag
            timestamp=float(frame.info.time_epoch),         # capture timestamp
        )
        return data
    return None


def tcp_reassembly(frame: 'Frame') -> 'TCP_Packet | None':
    """Make data for TCP reassembly.

    Args:
        frame: PCAP frame.

    Returns:
        A tuple of data for TCP reassembly.

        * If the ``frame`` can be used for TCP reassembly. A frame can be reassembled
          if it contains TCP layer (:class:`~pcapkit.protocols.transport.tcp.TCP`),
          or a TCP segment whose header the TCP parser rejected, as it does one the
          snapshot length cut short (:issue:`1518`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    if (segment := tcp_segment(frame)) is not None:
        raw_len = len(segment.payload)
        data = TCP_Packet(
            bufid=(
                segment.ip.src,                     # source IP address
                segment.srcport,                    # source port
                segment.ip.dst,                     # destination IP address
                segment.dstport,                    # destination port
            ),
            num=frame.info.number,                  # original packet range number
            ack=segment.ack,                        # acknowledgement
            dsn=segment.seq,                        # data sequence number
            syn=segment.syn,                        # synchronise flag
            fin=segment.fin,                        # finish flag
            rst=segment.rst,                        # reset connection flag
            header=segment.header,                  # raw bytes type header
            payload=bytearray(segment.payload),     # raw bytearray type payload
            first=segment.seq,                      # first sequence number of payload
            last=segment.seq + raw_len - 1,         # last sequence number of payload
            len=raw_len,                            # payload length, header excludes
            timestamp=float(frame.info.time_epoch),  # capture timestamp
        )
        return data
    return None


def tcp_traceflow(frame: 'Frame', *, data_link: 'LinkType') -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        frame: PCAP frame.
        data_link: Data link layer protocol (from global header).

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A frame can be reassembled
          if it contains TCP layer (:class:`~pcapkit.protocols.transport.tcp.TCP`),
          or a TCP segment whose header the TCP parser rejected, as it does one the
          snapshot length cut short (:issue:`1518`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if (segment := tcp_segment(frame)) is not None:
        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=data_link,                      # data link type from global header
            index=frame.info.number,                 # frame number
            frame=frame.info,                        # extracted frame info
            syn=segment.syn,                         # TCP synchronise (SYN) flag
            fin=segment.fin,                         # TCP finish (FIN) flag
            rst=segment.rst,                         # TCP reset (RST) flag
            src=segment.ip.src,                      # source IP
            dst=segment.ip.dst,                      # destination IP
            srcport=segment.srcport,                 # TCP source port
            dstport=segment.dstport,                 # TCP destination port
            timestamp=float(frame.info.time_epoch),  # frame timestamp
            seq=segment.seq,                         # TCP sequence number
            ack=segment.ack,                         # TCP acknowledgement number
            header=segment.header,                   # raw bytes type header
            payload=bytearray(segment.payload),      # raw bytearray type payload
        )
        return data
    return None
