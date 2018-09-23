# -*- coding: utf-8 -*-
"""DPKT tools

`pcapkit.toolkit.dpkt` contains all you need for
`PyPCAPKit` handy usage with `DPKT` engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

"""
import ipaddress

from pcapkit.protocols.transport.transport import TP_PROTO

__all__ = [
    'ipv6_hdr_len', 'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]


def ipv6_hdr_len(ipv6):
    """Calculate length of headers before IPv6-Frag"""
    hdr_len = ipv6.__hdr_len__
    for code in (0, 60, 43):
        ext_hdr = ipv6.extension_hdrs.get(code)
        if ext_hdr is not None:
            hdr_len += ext_hdr.length
    return hdr_len


def packet2chain(packet):
    """Fetch DPKT packet protocol chain."""
    chain = [type(packet).__name__]
    payload = packet.data
    while not isinstance(payload, bytes):
        chain.append(type(payload).__name__)
        payload = payload.data
    return ':'.join(chain)


def packet2dict(packet, timestamp, *, data_link):
    """Convert DPKT packet into dict."""
    def wrapper(packet):
        dict_ = dict()
        for field in packet.__hdr_fields__:
            dict_[field] = getattr(packet, field, None)
        payload = packet.data
        if not isinstance(payload, bytes):
            dict_[type(payload).__name__] = wrapper(payload)
        return dict_
    return {
        'timestamp': timestamp,
        'packet': packet.pack(),
        data_link.name: wrapper(packet),
    }


def ipv4_reassembly(packet, *, count=NotImplemented):
    """Make data for IPv4 reassembly."""
    ipv4 = getattr(packet, 'ip', None)
    if ipv4 is not None:
        if ipv4.df:     # dismiss not fragmented packet
            return False, None
        data = dict(
            bufid=(
                ipaddress.ip_address(ipv4.src),                 # source IP address
                ipaddress.ip_address(ipv4.dst),                 # destination IP address
                ipv4.id,                                        # identification
                TP_PROTO.get(ipv4.p).name,                      # payload protocol type
            ),
            num=count,                                          # original packet range number
            fo=ipv4.off,                                        # fragment offset
            ihl=ipv4.__hdr_len__,                               # internet header length
            mf=bool(ipv4.mf),                                   # more fragment flag
            tl=ipv4.len,                                        # total length, header includes
            header=bytearray(ipv4.pack()[:ipv4.__hdr_len__]),   # raw bytearray type header
            payload=bytearray(ipv4.pack()[ipv4.__hdr_len__:]),  # raw bytearray type payload
        )
        return True, data
    return False, None


def ipv6_reassembly(packet, *, count=NotImplemented):
    """Make data for IPv6 reassembly."""
    ipv6 = getattr(packet, 'ip6', None)
    if ipv6 is not None:
        ipv6_frag = ipv6.extension_hdrs.get(44)
        if ipv6_frag is None:       # dismiss not fragmented packet
            return False, None
        hdr_len = ipv6_hdr_len(ipv6)
        data = dict(
            bufid=(
                ipaddress.ip_address(ipv6.src),                     # source IP address
                ipaddress.ip_address(ipv6.dst),                     # destination IP address
                ipv6.flow,                                          # label
                TP_PROTO.get(ipv6_frag.nh).name,                    # next header field in IPv6 Fragment Header
            ),
            num=count,                                              # original packet range number
            fo=ipv6_frag.nxt,                                       # fragment offset
            ihl=hdr_len,                                            # header length, only headers before IPv6-Frag
            mf=bool(ipv6_frag.m_flag),                              # more fragment flag
            tl=len(ipv6),                                           # total length, header includes
            header=bytearray(ipv6.pack()[:hdr_len]),                # raw bytearray type header before IPv6-Frag
            payload=bytearray(ipv6.pack()[hdr_len+ipv6_frag:]),     # raw bytearray type payload after IPv6-Frag
        )
        return True, data
    return False, None


def tcp_reassembly(packet, *, count=NotImplemented):
    """Make data for TCP reassembly."""
    if getattr(packet, 'ip', None):
        ip = packet['ip']
    elif getattr(packet, 'ip6', None):
        ip = packet['ip6']
    else:
        return False, None
    tcp = getattr(ip, 'tcp', None)
    if tcp is not None:
        flags = bin(tcp.flags)[2:].zfill(8)
        data = dict(
            bufid=(
                ipaddress.ip_address(ip.src),                   # source IP address
                ipaddress.ip_address(ip.dst),                   # destination IP address
                tcp.sport,                                      # source port
                tcp.dport,                                      # destination port
            ),
            num=count,                                          # original packet range number
            ack=tcp.ack,                                        # acknowledgement
            dsn=tcp.seq,                                        # data sequence number
            syn=bool(int(flags[6])),                            # synchronise flag
            fin=bool(int(flags[7])),                            # finish flag
            payload=bytearray(tcp.pack()[tcp.__hdr_len__:]),    # raw bytearray type payload
        )
        raw_len = len(tcp.data)                                 # payload length, header excludes
        data['first'] = tcp.seq                                 # this sequence number
        data['last'] = tcp.seq + raw_len                        # next (wanted) sequence number
        data['len'] = raw_len                                   # payload length, header excludes
        return True, data
    return False, None


def tcp_traceflow(packet, timestamp, *, data_link, count=NotImplemented):
    """Trace packet flow for TCP."""
    if getattr(packet, 'ip', None):
        ip = packet['ip']
    elif getattr(packet, 'ip6', None):
        ip = packet['ip6']
    else:
        return False, None
    tcp = getattr(ip, 'tcp', None)
    if tcp is not None:
        flags = bin(tcp.flags)[2:].zfill(8)
        data = dict(
            protocol=data_link,                                         # data link type from global header
            index=count,                                                # frame number
            frame=packet2dict(packet, timestamp, data_link=data_link),  # extracted packet
            syn=bool(int(flags[6])),                                    # TCP synchronise (SYN) flag
            fin=bool(int(flags[7])),                                    # TCP finish (FIN) flag
            src=ipaddress.ip_address(ip.src),                           # source IP
            dst=ipaddress.ip_address(ip.dst),                           # destination IP
            srcport=tcp.sport,                                          # TCP source port
            dstport=tcp.dport,                                          # TCP destination port
            timestamp=timestamp,                                        # timestamp
        )
        return True, data
    return False, None
