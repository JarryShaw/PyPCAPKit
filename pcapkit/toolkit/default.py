# -*- coding: utf-8 -*-
"""default tools

:mod:`pcapkit.toolkit.default` contains all you need for
:mod:`pcapkit` handy usage. All functions returns with a
flag to indicate if usable for its caller.

"""
__all__ = ['ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow']


def ipv4_reassembly(frame):
    """Make data for IPv4 reassembly.

    Args:
        frame (pcapkit.protocols.pcap.frame.Frame): PCAP frame.

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for IPv4 reassembly.

        * If the ``frame`` can be used for IPv4 reassembly. A frame can be reassembled
          if it contains IPv4 layer (:class:`pcapkit.protocols.internet.ipv4.IPv4`) and
          the **DF** (:attr:`IPv4.flags.df <pcapkit.protocols.internet.ipv4.DataType_IPv4_Flags.df>`)
          flag is :data:`False`.
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (c.f. :term:`ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`~pcapkit.reassembly.ipv4.IPv4Reassembly`

    """
    if 'IPv4' in frame:
        ipv4 = frame['IPv4'].info
        if ipv4.flags.df:       # dismiss not fragmented frame
            return False, None
        data = dict(
            bufid=(
                ipv4.src,                                   # source IP address
                ipv4.dst,                                   # destination IP address
                ipv4.id,                                    # identification
                ipv4.proto.name,                            # payload protocol type
            ),
            num=frame.info.number,                          # original packet range number
            fo=ipv4.frag_offset,                            # fragment offset
            ihl=ipv4.hdr_len,                               # internet header length
            mf=ipv4.flags.mf,                               # more fragment flag
            tl=ipv4.len,                                    # total length, header includes
            header=bytearray(ipv4.packet.header),           # raw bytearray type header
            payload=bytearray(ipv4.packet.payload or b''),  # raw bytearray type payload
        )
        return True, data
    return False, None


def ipv6_reassembly(frame):
    """Make data for IPv6 reassembly.

    Args:
        frame (pcapkit.protocols.pcap.frame.Frame): PCAP frame.

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for IPv6 reassembly.

        * If the ``frame`` can be used for IPv6 reassembly. A frame can be reassembled
          if it contains IPv6 layer (:class:`pcapkit.protocols.internet.ipv6.IPv6`) and
          IPv6 Fragment header (:rfc:`2460#section-4.5`,
          :class:`pcapkit.protocols.internet.ipv6_frag.IPv6_Frag`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`~pcapkit.reassembly.ipv6.IPv6Reassembly`

    """
    if 'IPv6' in frame:
        ipv6 = frame['IPv6'].info
        if 'frag' not in ipv6:      # dismiss not fragmented frame
            return False, None
        data = dict(
            bufid=(
                ipv6.src,                                       # source IP address
                ipv6.dst,                                       # destination IP address
                ipv6.label,                                     # label
                ipv6.ipv6_frag.next.name,                       # next header field in IPv6 Fragment Header
            ),
            num=frame.info.number,                              # original packet range number
            fo=ipv6.ipv6_frag.offset,                           # fragment offset
            ihl=ipv6.hdr_len,                                   # header length, only headers before IPv6-Frag
            mf=ipv6.ipv6_frag.mf,                               # more fragment flag
            tl=ipv6.hdr_len + ipv6.raw_len,                     # total length, header includes
            header=bytearray(ipv6.fragment.header),             # raw bytearray type header before IPv6-Frag
            payload=bytearray(ipv6.fragment.payload or b''),    # raw bytearray type payload after IPv6-Frag
        )
        return True, data
    return False, None


def tcp_reassembly(frame):
    """Make data for TCP reassembly.

    Args:
        frame (pcapkit.protocols.pcap.frame.Frame): PCAP frame.

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for TCP reassembly.

        * If the ``frame`` can be used for TCP reassembly. A frame can be reassembled
          if it contains TCP layer (:class:`pcapkit.protocols.transport.tcp.TCP`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`~pcapkit.reassembly.tcp.TCPReassembly`

    """
    if 'TCP' in frame:
        ip = (frame['IPv4'] if 'IPv4' in frame else frame['IPv6']).info
        tcp = frame['TCP'].info
        data = dict(
            bufid=(
                ip.src,                                     # source IP address
                ip.dst,                                     # destination IP address
                tcp.srcport,                                # source port
                tcp.dstport,                                # destination port
            ),
            num=frame.info.number,                          # original packet range number
            ack=tcp.ack,                                    # acknowledgement
            dsn=tcp.seq,                                    # data sequence number
            syn=tcp.flags.syn,                              # synchronise flag
            fin=tcp.flags.fin,                              # finish flag
            rst=tcp.flags.rst,                              # reset connection flag
            payload=bytearray(tcp.packet.payload or b''),   # raw bytearray type payload
        )
        raw_len = len(data['payload'])                      # payload length, header excludes
        data['first'] = tcp.seq                             # this sequence number
        data['last'] = tcp.seq + raw_len                    # next (wanted) sequence number
        data['len'] = raw_len                               # payload length, header excludes
        return True, data
    return False, None


def tcp_traceflow(frame, *, data_link):
    """Trace packet flow for TCP.

    Args:
        frame (pcapkit.protocols.pcap.frame.Frame): PCAP frame.

    Keyword Args:
        data_link (str): Data link layer protocol (from global header).

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A frame can be reassembled
          if it contains TCP layer (:class:`pcapkit.protocols.transport.tcp.TCP`).
        * If the ``frame`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`~pcapkit.foundation.traceflow.TraceFlow`

    """
    if 'TCP' in frame:
        ip = (frame['IPv4'] if 'IPv4' in frame else frame['IPv6']).info
        tcp = frame['TCP'].info
        data = dict(
            protocol=data_link,                     # data link type from global header
            index=frame.info.number,                # frame number
            frame=frame.info,                       # extracted frame info
            syn=tcp.flags.syn,                      # TCP synchronise (SYN) flag
            fin=tcp.flags.fin,                      # TCP finish (FIN) flag
            src=ip.src,                             # source IP
            dst=ip.dst,                             # destination IP
            srcport=tcp.srcport,                    # TCP source port
            dstport=tcp.dstport,                    # TCP destination port
            timestamp=frame.info.time_epoch,        # frame timestamp
        )
        return True, data
    return False, None
