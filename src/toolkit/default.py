# -*- coding: utf-8 -*-
"""

"""
__all__ = ['ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow']


def ipv4_reassembly(self, frame):
    """Make data for IPv4 reassembly."""
    if 'IPv4' in frame:
        ipv4 = frame['IPv4']
        if ipv4.flags.df:   return False, None      # dismiss not fragmented frame
        data = dict(
            bufid = (
                ipv4.src,                           # source IP address
                ipv4.dst,                           # destination IP address
                ipv4.id,                            # identification
                ipv4.proto,                         # payload protocol type
            ),
            num = frame.info.number,                # original packet range number
            fo = ipv4.frag_offset,                  # fragment offset
            ihl = ipv4.hdr_len,                     # internet header length
            mf = ipv4.flags.mf,                     # more fragment flag
            tl = ipv4.len,                          # total length, header includes
            header = bytearray(ipv4.packet.header), # raw bytearray type header
            payload = bytearray(ipv4.packet.payload or b''),
                                                    # raw bytearray type payload
        )
        return True, data
    return False, None


def ipv6_reassembly(self, frame):
    """Make data for IPv6 reassembly."""
    if 'IPv6' in frame:
        ipv6 = frame['IPv6']
        if 'frag' not in ipv6:  return False, None  # dismiss not fragmented frame
        data = dict(
            bufid = (
                ipv6.src,                           # source IP address
                ipv6.dst,                           # destination IP address
                ipv6.label,                         # label
                ipv6.ipv6_frag.next,                # next header field in IPv6 Fragment Header
            ),
            num = frame.info.number,                # original packet range number
            fo = ipv6.ipv6_frag.offset,             # fragment offset
            ihl = ipv6.hdr_len,                     # header length, only headers before IPv6-Frag
            mf = ipv6.ipv6_frag.mf,                 # more fragment flag
            tl = ipv6.hdr_len + ipv6.raw_len,       # total length, header includes
            header = bytearray(ipv6.fragment.header),
                                                    # raw bytearray type header before IPv6-Frag
            payload = bytearray(ipv6.fragment.payload or b''),
                                                    # raw bytearray type payload after IPv6-Frag
        )
        return True, data
    return False, None


def tcp_reassembly(self, frame):
    """Make data for TCP reassembly."""
    if 'TCP' in frame:
        ip = frame['IPv4'] if 'IPv4' in frame else frame['IPv6']
        tcp = frame['TCP']
        data = dict(
            bufid = (
                ip.src,                             # source IP address
                ip.dst,                             # destination IP address
                tcp.srcport,                        # source port
                tcp.dstport,                        # destination port
            ),
            num = frame.info.number,                # original packet range number
            ack = tcp.ack,                          # acknowledgement
            dsn = tcp.seq,                          # data sequence number
            syn = tcp.flags.syn,                    # synchronise flag
            fin = tcp.flags.fin,                    # finish flag
            payload = bytearray(tcp.packet.payload or b''),
                                                    # raw bytearray type payload
        )
        raw_len = len(data['payload'])              # payload length, header excludes
        data['first'] = tcp.seq                     # this sequence number
        data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
        data['len'] = raw_len                       # payload length, header excludes
        return True, data
    return False, None


def tcp_traceflow(self, frame, *, data_link):
    """Trace packet flow for TCP."""
    if 'TCP' in frame:
        ip = frame['IPv4'] if 'IPv4' in frame else frame['IPv6']
        tcp = frame['TCP']
        data = dict(
            protocol = data_link,                   # data link type from global header
            index = frame.info.number,              # frame number
            frame = frame.info,                     # extracted frame info
            syn = tcp.flags.syn,                    # TCP synchronise (SYN) flag
            fin = tcp.flags.fin,                    # TCP finish (FIN) flag
            src = ip.src,                           # source IP
            dst = ip.dst,                           # destination IP
            srcport = tcp.srcport,                  # TCP source port
            dstport = tcp.dstport,                  # TCP destination port
            timestamp = frame.info.time_epoch,      # frame timestamp
        )
        return True, data
    return False, None
