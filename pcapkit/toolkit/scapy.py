# -*- coding: utf-8 -*-
"""Scapy Tools
=================

.. module:: pcapkit.toolkit.scapy

:mod:`pcapkit.toolkit.scapy` contains all you need for
:mod:`pcapkit` handy usage with `Scapy`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _Scapy: https://scapy.net

.. warning::

   This module requires installed `Scapy`_ engine.

.. note::

   Several functions here import a `Scapy`_ layer module lazily, inside the
   function body -- :func:`ipv6_reassembly` needs
   :class:`scapy.layers.inet6.IPv6ExtHdrFragment`, for instance. Those imports are
   for the *classes* they name and nothing more. They must not be mistaken for how
   `Scapy`_'s layer registries get populated, even though they do populate them as
   a side effect, because by the time any of these functions runs the engine has
   already called ``sniff`` and every frame has already been dissected -- or not.

   That distinction is what made #406 hard to see. Reaching
   :func:`ipv6_reassembly` repaired ``conf.l2types`` mid-run, one call too late to
   affect the frames being reassembled, so whether a process dissected correctly
   depended on what had imported `Scapy`_ earlier. Populating the registries before
   ``sniff`` is
   :class:`~pcapkit.foundation.engines.scapy.Scapy`'s job, and it does it by
   importing :mod:`scapy.all` in its constructor.

"""
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.exceptions import ModuleNotFound, stacklevel
from pcapkit.utilities.warnings import ScapyWarning, warn

try:
    import scapy
except ModuleNotFoundError:
    scapy = None
    warn("dependency package 'Scapy' not found",
         ScapyWarning, stacklevel=stacklevel())

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any

    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet

__all__ = [
    'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]


def packet2chain(packet: 'Packet') -> 'str':
    """Fetch Scapy packet protocol chain.

    Args:
        packet: Scapy packet.

    Returns:
        Colon (``:``) separated list of protocol chain.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    from scapy.packet import NoPayload

    chain = [packet.name]
    payload = packet.payload
    while not isinstance(payload, NoPayload):
        chain.append(payload.name)
        payload = payload.payload
    return ':'.join(chain)


def packet2dict(packet: 'Packet') -> 'dict[str, Any]':
    """Convert Scapy packet into :obj:`dict`.

    Args:
        packet: Scapy packet.

    Returns:
        A :obj:`dict` mapping of packet data.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    from scapy.packet import NoPayload

    def wrapper(packet: 'Packet') -> 'dict[str, Any]':
        dict_ = packet.fields
        payload = packet.payload
        if not isinstance(payload, NoPayload):
            dict_[payload.name] = wrapper(payload)
        return dict_

    return {
        'packet': bytes(packet),
        packet.name: wrapper(packet),
    }


def ipv4_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        packet: Scapy packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv4 reassembly.

        * If the ``packet`` can be used for IPv4 reassembly. A packet can be reassembled
          if it contains IPv4 layer (:class:`scapy.layers.inet.IP`) and the **DF**
          (:attr:`scapy.layers.inet.IP.flags.DF`) flag is :data:`False`.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    if 'IP' in packet:
        ipv4 = cast('IP', packet['IP'])
        if ipv4.flags.DF:       # dismiss not fragmented packet
            return None

        data = IP_Packet(
            bufid=(
                cast('IPv4Address',
                     ipaddress.ip_address(ipv4.src)),  # source IP address
                cast('IPv4Address',
                     ipaddress.ip_address(ipv4.dst)),  # destination IP address
                ipv4.id,                               # identification
                Enum_TransType.get(ipv4.proto),        # payload protocol type
            ),
            num=count,                                 # original packet range number
            fo=ipv4.frag,                              # fragment offset
            ihl=ipv4.ihl * 4,                          # internet header length
            mf=bool(ipv4.flags.MF),                    # more fragment flag
            tl=ipv4.len,                               # total length, header includes
            header=bytes(ipv4)[:ipv4.ihl * 4],         # raw bytes type header
            payload=bytearray(bytes(ipv4.payload)),    # raw bytearray type payload
            timestamp=float(packet.time),              # capture timestamp
        )
        return data
    return None


def ipv6_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'IP_Packet[IPv6Address] | None':
    """Make data for IPv6 reassembly.

    Args:
        packet: Scapy packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv6 reassembly.

        * If the ``packet`` can be used for IPv6 reassembly. A packet can be reassembled
          if it contains IPv6 layer (:class:`scapy.layers.inet6.IPv6`) and IPv6 Fragment
          header (:rfc:`2460#section-4.5`, i.e., :class:`scapy.layers.inet6.IPv6ExtHdrFragment`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    from scapy.layers.inet6 import IPv6ExtHdrFragment

    if 'IPv6' in packet:
        ipv6 = cast('IPv6', packet['IPv6'])
        if IPv6ExtHdrFragment not in ipv6:  # pylint: disable=E1101
            return None                        # dismiss not fragmented packet
        ipv6_frag = cast('IPv6ExtHdrFragment', ipv6['IPv6ExtHdrFragment'])

        # NOTE: ``len()`` of a Scapy layer spans that layer and everything after
        # it, so the difference is the unfragmentable part -- every octet before
        # the Fragment header, which is the only part of the header the
        # reassembled packet keeps (:rfc:`8200#section-4.5`).
        hdr_len = len(ipv6) - len(ipv6_frag)
        payload = bytearray(bytes(ipv6_frag.payload))

        data = IP_Packet(
            bufid=(
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.src)),     # source IP address
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.dst)),     # destination IP address
                ipv6_frag.id,                             # identification
                Enum_TransType.get(ipv6_frag.nh),         # next header field in IPv6 Fragment Header
            ),
            num=count,                                    # original packet range number
            # NOTE: Scapy reports ``IPv6ExtHdrFragment.offset`` in on-wire 8-octet
            # units (:rfc:`8200#section-4.5`), but the reassembly machinery indexes
            # the datagram buffer with ``fo``, so it must be scaled into octets.
            fo=ipv6_frag.offset * 8,                      # fragment offset
            ihl=hdr_len,                                  # header length, only headers before IPv6-Frag
            mf=bool(ipv6_frag.m),                         # more fragment flag
            # NOTE: ``len(ipv6)`` counts the Fragment header, so it overstates
            # this by 8 -- and the reassembly machinery writes the payload over
            # the span ``tl - ihl``, so those 8 octets became 8 octets of stray
            # zeroes in every reassembled datagram.
            tl=hdr_len + len(payload),                    # total length, header includes
            header=bytes(ipv6)[:hdr_len],                 # raw bytes type header before IPv6-Frag
            payload=payload,                              # raw bytearray type payload after IPv6-Frag
            timestamp=float(packet.time),                 # capture timestamp
        )
        return data
    return None


def tcp_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'TCP_Packet | None':
    """Store data for TCP reassembly.

    Args:
        packet: Scapy packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP reassembly. A packet can be reassembled
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    if 'IP' in packet:
        ip = cast('IP', packet['IP'])
    elif 'IPv6' in packet:
        ip = cast('IPv6', packet['IPv6'])
    else:
        return None

    if 'TCP' in packet:
        tcp = cast('TCP', packet['TCP'])

        raw_len = len(tcp.payload)                  # payload length, header excludes
        data = TCP_Packet(
            bufid=(
                ipaddress.ip_address(ip.src),       # source IP address
                tcp.sport,                          # source port
                ipaddress.ip_address(ip.dst),       # destination IP address
                tcp.dport,                          # destination port
            ),
            num=count,                              # original packet range number
            ack=tcp.ack,                            # acknowledgement
            dsn=tcp.seq,                            # data sequence number
            syn=bool(tcp.flags.S),                  # synchronise flag
            fin=bool(tcp.flags.F),                  # finish flag
            rst=bool(tcp.flags.R),                  # reset connection flag
            header=bytes(tcp)[:tcp.dataofs * 4],    # raw bytes type header
            payload=bytearray(bytes(tcp.payload)),  # raw bytearray type payload
            first=tcp.seq,                          # first sequence number of payload
            last=tcp.seq + raw_len - 1,             # last sequence number of payload
            len=raw_len,                            # payload length, header excludes
            timestamp=float(packet.time),           # capture timestamp
        )
        return data
    return None


def tcp_traceflow(packet: 'Packet', *, count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: Scapy packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if 'TCP' in packet:
        ip = cast('IP', packet['IP']) if 'IP' in packet else cast('IPv6', packet['IPv6'])
        tcp = cast('TCP', packet['TCP'])

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=Enum_LinkType.get(packet.name.upper()),     # data link type from global header
            index=count,                                         # frame number
            frame=packet2dict(packet),                           # extracted packet
            syn=bool(tcp.flags.S),                               # TCP synchronise (SYN) flag
            fin=bool(tcp.flags.F),                               # TCP finish (FIN) flag
            rst=bool(tcp.flags.R),                               # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                    # source IP
            dst=ipaddress.ip_address(ip.dst),                    # destination IP
            srcport=tcp.sport,                                   # TCP source port
            dstport=tcp.dport,                                   # TCP destination port
            # NOTE: the *capture's* clock, not the host's. This read
            # ``time.time()``, which put the moment of parsing into every flow
            # label -- so the same capture traced twice produced different label
            # strings and different output filenames. Scapy carries the record's
            # own timestamp on ``Packet.time``, which is what every other
            # engine's adapter reports.
            timestamp=float(packet.time),                        # capture timestamp
        )
        return data
    return None
