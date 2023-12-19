# -*- coding: utf-8 -*-
"""PCAP Tools
================

.. module:: pcapkit.toolkit.pcap

:mod:`pcapkit.toolkit.pcap` contains all you need for
:mod:`pcapkit` handy usage of PCAP file format. All
functions returns with a flag to indicate if usable
for its caller.

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.protocols.internet.ipv4 import IPv4
    from pcapkit.protocols.internet.ipv6 import IPv6
    from pcapkit.protocols.internet.ipv6_frag import IPv6_Frag
    from pcapkit.protocols.misc.pcap import Frame
    from pcapkit.protocols.transport.tcp import TCP

__all__ = ['ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow']


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

        data = IP_Packet(
            bufid=(
                ipv6_info.src,                              # source IP address
                ipv6_info.dst,                              # destination IP address
                ipv6_info.label,                            # label
                ipv6_frag_info.next,                        # next header field in IPv6 Fragment Header
            ),
            num=frame.info.number,                          # original packet range number
            fo=ipv6_frag_info.offset,                       # fragment offset
            ihl=ipv6_info.hdr_len,                          # header length, only headers before IPv6-Frag
            mf=ipv6_frag_info.mf,                           # more fragment flag
            tl=ipv6_info.hdr_len + ipv6_info.raw_len,       # total length, header includes
            header=ipv6_info.fragment.header,               # raw bytearray type header before IPv6-Frag
            payload=bytearray(ipv6_info.fragment.payload),  # raw bytearray type payload after IPv6-Frag
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
          if it contains TCP layer (:class:`~pcapkit.protocols.transport.tcp.TCP`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    if 'TCP' in frame:
        ip = cast('IPv4 | IPv6', frame['IP'])
        ip_info = ip.info
        tcp = cast('TCP', frame['TCP'])
        tcp_info = tcp.info

        raw_len = len(tcp.packet.payload)
        data = TCP_Packet(
            bufid=(
                ip_info.src,                        # source IP address
                tcp_info.srcport.port,              # source port
                ip_info.dst,                        # destination IP address
                tcp_info.dstport.port,              # destination port
            ),
            num=frame.info.number,                  # original packet range number
            ack=tcp_info.ack,                       # acknowledgement
            dsn=tcp_info.seq,                       # data sequence number
            syn=tcp_info.flags.syn,                 # synchronise flag
            fin=tcp_info.flags.fin,                 # finish flag
            rst=tcp_info.flags.rst,                 # reset connection flag
            header=tcp.packet.header,               # raw bytes type header
            payload=bytearray(tcp.packet.payload),  # raw bytearray type payload
            first=tcp_info.seq,                     # this sequence number
            last=tcp_info.seq + raw_len,            # next (wanted) sequence number
            len=raw_len,                            # payload length, header excludes
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
          if it contains TCP layer (:class:`~pcapkit.protocols.transport.tcp.TCP`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if 'TCP' in frame:
        ip = cast('IPv4 | IPv6', frame['IP'])
        ip_info = ip.info
        tcp = cast('TCP', frame['TCP'])
        tcp_info = tcp.info

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=data_link,                      # data link type from global header
            index=frame.info.number,                 # frame number
            frame=frame.info,                        # extracted frame info
            syn=tcp_info.flags.syn,                  # TCP synchronise (SYN) flag
            fin=tcp_info.flags.fin,                  # TCP finish (FIN) flag
            src=ip_info.src,                         # source IP
            dst=ip_info.dst,                         # destination IP
            srcport=tcp_info.srcport.port,           # TCP source port
            dstport=tcp_info.dstport.port,           # TCP destination port
            timestamp=float(frame.info.time_epoch),  # frame timestamp
        )
        return data
    return None
