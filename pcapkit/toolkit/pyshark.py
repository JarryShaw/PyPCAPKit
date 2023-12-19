# -*- coding: utf-8 -*-
"""PyShark Tools
===================

:mod:`pcapkit.toolkit.pyshark` contains all you need for
:mod:`pcapkit` handy usage with `PyShark`_ engine. All
reforming functions returns with a flag to indicate if
usable for its caller.

.. _PyShark: https://kiminewt.github.io/pyshark

.. note::

   Due to the lack of functionality of `PyShark`_, some
   functions of :mod:`pcapkit` may not be available with
   the `PyShark`_ engine.

"""
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet

if TYPE_CHECKING:
    from typing import Any

    from pyshark.packet.packet import Packet

__all__ = ['packet2dict', 'tcp_traceflow']


def packet2dict(packet: 'Packet') -> 'dict[str, Any]':
    """Convert PyShark packet into :obj:`dict`.

    Args:
        packet: Scapy packet.

    Returns:
        A :obj:`dict` mapping of packet data.

    """
    dict_ = {}  # type: dict[str, Any]
    frame = packet.frame_info
    for field in frame.field_names:
        dict_[field] = getattr(frame, field)

    tempdict = dict_
    for layer in packet.layers:
        tempdict[layer.layer_name.upper()] = {}
        tempdict = tempdict[layer.layer_name.upper()]
        for field in layer.field_names:
            tempdict[field] = getattr(layer, field)

    return dict_


def tcp_traceflow(packet: 'Packet') -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: Scapy packet.

    Returns:
        Tuple[bool, Dict[str, Any]]: A tuple of data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if 'IP' in packet:
        ip = cast('Packet', packet.ip)
    elif 'IPv6' in packet:
        ip = cast('Packet', packet.ipv6)
    else:
        return None

    if 'TCP' in packet:
        tcp = cast('Packet', packet.tcp)

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=Enum_LinkType.get(packet.layers[0].layer_name.upper()),  # data link type from global header
            index=int(packet.number),                                            # frame number
            frame=packet2dict(packet),                                           # extracted packet
            syn=bool(int(tcp.flags_syn)),                                        # TCP synchronise (SYN) flag
            fin=bool(int(tcp.flags_fin)),                                        # TCP finish (FIN) flag
            src=ipaddress.ip_address(ip.src),                                    # source IP
            dst=ipaddress.ip_address(ip.dst),                                    # destination IP
            srcport=int(tcp.srcport),                                            # TCP source port
            dstport=int(tcp.dstport),                                            # TCP destination port
            timestamp=packet.frame_info.time_epoch,                              # timestamp
        )
        return data
    return None
