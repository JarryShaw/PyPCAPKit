# -*- coding: utf-8 -*-
"""Scapy tools

`pcapkit.toolkit.scapy` contains all you need for
`PyPCAPKit` handy usage with `Scapy` engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

"""
import ipaddress
import time
import warnings

from pcapkit.protocols.link.link import LINKTYPE
from pcapkit.protocols.transport.transport import TP_PROTO
from pcapkit.utilities.exceptions import ModuleNotFound, stacklevel
from pcapkit.utilities.warnings import ScapyWarning

###############################################################################
# import scapy.all
###############################################################################

try:
    import scapy.all as scapy_all
except ImportError:
    scapy_all = None
    warnings.warn("dependency package 'Scapy' not found",
                  ScapyWarning, stacklevel=stacklevel())

__all__ = [
    'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]


def packet2chain(packet):
    """Fetch Scapy packet protocol chain."""
    if scapy_all is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    chain = [packet.name]
    payload = packet.payload
    while not isinstance(payload, scapy_all.packet.NoPayload):
        chain.append(payload.name)
        payload = payload.payload
    return ':'.join(chain)


def packet2dict(packet, *, count=NotImplemented):
    """Convert Scapy packet into dict."""
    if scapy_all is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')

    def wrapper(packet):
        dict_ = packet.fields
        payload = packet.payload
        if not isinstance(payload, scapy_all.packet.NoPayload):
            dict_[payload.name] = wrapper(payload)
        return dict_

    return {
        'packet': bytes(packet),
        packet.name: wrapper(packet),
    }


def ipv4_reassembly(packet, *, count=NotImplemented):
    """Make data for IPv4 reassembly."""
    if 'IP' in packet:
        ipv4 = packet['IP']
        if ipv4.flags.DF:       # dismiss not fragmented packet
            return False, None
        data = dict(
            bufid=(
                ipaddress.ip_address(ipv4.src),         # source IP address
                ipaddress.ip_address(ipv4.dst),         # destination IP address
                ipv4.id,                                # identification
                TP_PROTO.get(ipv4.proto).name,          # payload protocol type
            ),
            num=count,                                  # original packet range number
            fo=ipv4.frag,                               # fragment offset
            ihl=ipv4.ihl,                               # internet header length
            mf=bool(ipv4.flags.MF),                     # more fragment flag
            tl=ipv4.len,                                # total length, header includes
            header=bytearray(ipv4.raw_packet_cache),    # raw bytearray type header
            payload=bytearray(bytes(ipv4.payload)),     # raw bytearray type payload
        )
        return True, data
    return False, None


def ipv6_reassembly(packet, *, count=NotImplemented):
    """Make data for IPv6 reassembly."""
    if scapy_all is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    if 'IPv6' in packet:
        ipv6 = packet['IPv6']
        if scapy_all.IPv6ExtHdrFragment not in ipv6:
            return False, None                      # dismiss not fragmented packet
        ipv6_frag = ipv6['IPv6ExtHdrFragment']
        data = dict(
            bufid=(
                ipaddress.ip_address(ipv6.src),                 # source IP address
                ipaddress.ip_address(ipv6.dst),                 # destination IP address
                ipv6.fl,                                        # label
                TP_PROTO.get(ipv6_frag.nh).name,                # next header field in IPv6 Fragment Header
            ),
            num=count,                                          # original packet range number
            fo=ipv6_frag.offset,                                # fragment offset
            ihl=len(ipv6) - len(ipv6_frag),                     # header length, only headers before IPv6-Frag
            mf=bool(ipv6_frag.m),                               # more fragment flag
            tl=len(ipv6),                                       # total length, header includes
            header=bytearray(bytes(ipv6)[:-len(ipv6_frag)]),    # raw bytearray type header before IPv6-Frag
            payload=bytearray(bytes(ipv6_frag.payload)),        # raw bytearray type payload after IPv6-Frag
        )
        return True, data
    return False, None


def tcp_reassembly(packet, *, count=NotImplemented):
    """Store data for TCP reassembly."""
    if 'TCP' in packet:
        ip = packet['IP'] if 'IP' in packet else packet['IPv6']
        tcp = packet['TCP']
        data = dict(
            bufid=(
                ipaddress.ip_address(ip.src),       # source IP address
                ipaddress.ip_address(ip.dst),       # destination IP address
                tcp.sport,                          # source port
                tcp.dport,                          # destination port
            ),
            num=count,                              # original packet range number
            ack=tcp.ack,                            # acknowledgement
            dsn=tcp.seq,                            # data sequence number
            syn=bool(tcp.flags.S),                  # synchronise flag
            fin=bool(tcp.flags.F),                  # finish flag
            payload=bytearray(bytes(tcp.payload)),  # raw bytearray type payload
        )
        raw_len = len(tcp.payload)                  # payload length, header excludes
        data['first'] = tcp.seq                     # this sequence number
        data['last'] = tcp.seq + raw_len            # next (wanted) sequence number
        data['len'] = raw_len                       # payload length, header excludes
        return True, data
    return False, None


def tcp_traceflow(packet, *, count=NotImplemented):
    """Trace packet flow for TCP."""
    if 'TCP' in packet:
        ip = packet['IP'] if 'IP' in packet else packet['IPv6']
        tcp = packet['TCP']
        data = dict(
            protocol=LINKTYPE.get(packet.name.upper()),     # data link type from global header
            index=count,                                    # frame number
            frame=packet2dict(packet),                      # extracted packet
            syn=bool(tcp.flags.S),                          # TCP synchronise (SYN) flag
            fin=bool(tcp.flags.F),                          # TCP finish (FIN) flag
            src=ipaddress.ip_address(ip.src),               # source IP
            dst=ipaddress.ip_address(ip.dst),               # destination IP
            srcport=tcp.sport,                              # TCP source port
            dstport=tcp.dport,                              # TCP destination port
            timestamp=time.time(),                          # timestamp
        )
        return True, data
    return False, None
