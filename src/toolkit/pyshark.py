# -*- coding: utf-8 -*-
"""PyShark tools

`pcapkit.toolkit.pyshark` contains all you need for
`PyPCAPKit` handy usage with `PyShark` engine. All
reforming functions returns with a flag to indicate if
usable for its caller.

"""
import ipaddress

from pcapkit.protocols.link.link import LINKTYPE

__all__ = ['packet2dict', 'tcp_traceflow']


def packet2dict(packet):
    """Convert PyShark packet into dict."""
    dict_ = dict()
    frame = packet.frame_info
    for field in frame.field_names:
        dict_[field] = getattr(frame, field)

    tempdict = dict_
    for layer in packet.layers:
        tempdict[layer.layer_name.upper()] = dict()
        tempdict = tempdict[layer.layer_name.upper()]
        for field in layer.field_names:
            tempdict[field] = getattr(layer, field)

    return dict_


def tcp_traceflow(packet):
    """Trace packet flow for TCP."""
    if 'TCP' in packet:
        ip = packet.ip if 'IP' in packet else packet.ipv6
        tcp = packet.tcp
        data = dict(
            protocol=LINKTYPE.get(packet.layers[0].layer_name.upper()),     # data link type from global header
            index=int(packet.number),                                       # frame number
            frame=packet2dict(packet),                                      # extracted packet
            syn=bool(int(tcp.flags_syn)),                                   # TCP synchronise (SYN) flag
            fin=bool(int(tcp.flags_fin)),                                   # TCP finish (FIN) flag
            src=ipaddress.ip_address(ip.src),                               # source IP
            dst=ipaddress.ip_address(ip.dst),                               # destination IP
            srcport=int(tcp.srcport),                                       # TCP source port
            dstport=int(tcp.dstport),                                       # TCP destination port
            timestamp=packet.frame_info.time_epoch,                         # timestamp
        )
        return True, data
    return False, None
