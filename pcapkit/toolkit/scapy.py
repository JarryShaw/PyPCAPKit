# -*- coding: utf-8 -*-
"""Scapy Tools
=================

.. module:: pcapkit.toolkit.scapy

:mod:`pcapkit.toolkit.scapy` contains the adapters for the `Scapy`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

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

   That distinction is what makes :issue:`406` hard to see. Reaching
   :func:`ipv6_reassembly` populates ``conf.l2types`` mid-run, one call too late to
   affect the frames being reassembled, so relying on it would make whether a
   process dissects correctly depend on what had imported `Scapy`_ earlier.
   Populating the registries before
   ``sniff`` is
   :class:`~pcapkit.foundation.engines.scapy.Scapy`'s job, and it does it by
   importing :mod:`scapy.all` in its constructor.

"""
import decimal
import ipaddress
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.data import FrameRecord
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.utilities.compat import ModuleNotFoundError  # pylint: disable=redefined-builtin
from pcapkit.utilities.exceptions import MissingKeyError, ModuleNotFound, stacklevel
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
    'attach_resolution', 'packet2chain', 'packet2dict', 'packet2frame',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]


#: Attribute a packet's timestamp resolution is stashed under, in units per
#: second, by :func:`attach_resolution`.
RESOLUTION_ATTR = '__pcapkit_resolution__'


def attach_resolution(packet: 'Packet', resolution: 'int') -> 'None':
    """Stash the timestamp resolution of a packet's capture on the packet.

    Args:
        packet: Scapy packet.
        resolution: Timestamp resolution, in units per second: the PCAP global
            header's, or the PCAP-NG interface's the packet was captured on.

    """
    setattr(packet, RESOLUTION_ATTR, resolution)


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
        A :obj:`dict` mapping of packet data. Each layer carries only the fields
        set on it (for a dissected packet, those read from the wire, with no
        defaults filled in). Field values that are themselves
        Scapy packets (e.g. IP options, DNS records), including those inside
        lists, are converted recursively. The ``packet`` itself is not modified.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    from scapy.packet import NoPayload, Packet

    def convert(value: 'Any') -> 'Any':
        if isinstance(value, Packet):
            return wrapper(value)
        if isinstance(value, list):
            return [convert(item) for item in value]
        if isinstance(value, tuple):
            return tuple(convert(item) for item in value)
        return value

    def wrapper(packet: 'Packet') -> 'dict[str, Any]':
        # copy, so the payload names are not written into ``packet.fields``
        dict_ = {key: convert(val) for key, val in packet.fields.items()}
        payload = packet.payload
        if not isinstance(payload, NoPayload):
            dict_[payload.name] = wrapper(payload)
        return dict_

    return {
        'packet': bytes(packet),
        packet.name: wrapper(packet),
    }


def packet2frame(packet: 'Packet') -> 'FrameRecord':
    """Report a Scapy packet to the flow tracer, with its PCAP frame record.

    Args:
        packet: Scapy packet.

    Returns:
        The :func:`packet2dict` mapping of the packet, which every trace format
        but PCAP writes as it always has, carrying the octets `Scapy`_ dissected
        the packet from, the PCAP record header the PCAP trace dumper writes, and
        the exact timestamp it reads the header's resolution from.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    Note:
        The octets are ``packet.original``, which `Scapy`_'s readers keep as read,
        rather than ``bytes(packet)``, which rebuilds them. ``orig_len`` is
        ``packet.wirelen``, the record's original length.

        The fraction in ``frame_info.ts_usec`` is in the capture's own resolution,
        as the default engine's is. That resolution is the one
        :class:`~pcapkit.foundation.engines.scapy.Scapy` attaches with
        :func:`attach_resolution`, never one guessed from the value: a
        nanosecond count that is a whole number of microseconds has the same
        digits as the microsecond count. A packet that carries none, e.g. one
        built by hand, is taken to count microseconds.

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    mapping = packet2dict(packet)

    original = getattr(packet, 'original', None)
    octets = bytes(original) if isinstance(original, (bytes, bytearray)) else bytes(packet)
    wirelen = getattr(packet, 'wirelen', None)
    orig_len = len(octets) if wirelen is None else int(wirelen)

    nanosecond = getattr(packet, RESOLUTION_ATTR, 1_000_000) > 1_000_000
    stamp = packet.time
    epoch = (decimal.Decimal(stamp) if isinstance(stamp, decimal.Decimal)
             else round(decimal.Decimal(stamp), 9 if nanosecond else 6))
    ts_sec = int(epoch)
    ts_usec = int((epoch - ts_sec) * (1_000_000_000 if nanosecond else 1_000_000))

    return FrameRecord(mapping, packet=octets, frame_info=Data_FrameInfo(
        ts_sec=ts_sec,
        ts_usec=ts_usec,
        incl_len=len(octets),
        orig_len=orig_len,
    ), time_epoch=decimal.Decimal(epoch))


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
            # NOTE: Scapy reports ``IP.frag`` in on-wire 8-octet units
            # (:rfc:`791#section-3.1`), but the reassembly machinery indexes the
            # datagram buffer with ``fo`` in octets, so it must be scaled -- the
            # same scaling this module's own IPv6 path already applies to
            # ``IPv6ExtHdrFragment.offset`` below.
            fo=ipv4.frag * 8,                          # fragment offset
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
            # the span ``tl - ihl``, so using it would leave 8 octets of stray
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

        # NOTE: no default here, deliberately. ``get()`` with no default
        # raises on an unresolvable name rather than minting one (#775).
        # NULL and RAW are genuine DLTs -- BSD loopback and raw IP
        # framing, respectively -- each meant to go with its own handler
        # protocol class, so neither is an honest stand-in for "unknown link
        # type" and this must not paper over the miss with either. An
        # IP-rooted Scapy packet's ``(IP()/TCP()).name`` is ``'IP'``, which is
        # not a LinkType member name, and raises. Note the asymmetry, which
        # is not a choice made here: an IPv6-rooted packet's name uppercases to
        # ``'IPV6'``, which *is* a member (``LinkType.IPV6``, 229), so it
        # resolves silently -- to a DLT the caller never chose. Only the v4 name
        # happens to miss. The ``KeyError``
        # from :meth:`LinkType.get` is caught and re-raised as
        # :exc:`~pcapkit.utilities.exceptions.MissingKeyError` -- this
        # package's own house exception for a lookup miss -- rather than
        # letting it escape this public function.
        name = packet.name.upper()
        try:
            protocol = Enum_LinkType.get(name)
        except KeyError:
            raise MissingKeyError(name) from None

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=protocol,                                   # data link type
            index=count,                                         # frame number
            frame=packet2frame(packet),                          # extracted packet
            syn=bool(tcp.flags.S),                               # TCP synchronise (SYN) flag
            fin=bool(tcp.flags.F),                               # TCP finish (FIN) flag
            rst=bool(tcp.flags.R),                               # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                    # source IP
            dst=ipaddress.ip_address(ip.dst),                    # destination IP
            srcport=tcp.sport,                                   # TCP source port
            dstport=tcp.dport,                                   # TCP destination port
            # NOTE: the *capture's* clock, not the host's. ``time.time()`` would
            # put the moment of parsing into every flow label -- so the same
            # capture traced twice would produce different label strings and
            # different output filenames. Scapy carries the record's
            # own timestamp on ``Packet.time``, which is what every other
            # engine's adapter reports.
            timestamp=float(packet.time),                        # capture timestamp
            seq=tcp.seq,                                         # TCP sequence number
            ack=tcp.ack,                                         # TCP acknowledgement number
            header=bytes(tcp)[:tcp.dataofs * 4],                 # raw bytes type header
            payload=bytearray(bytes(tcp.payload)),               # raw bytearray type payload
        )
        return data
    return None
