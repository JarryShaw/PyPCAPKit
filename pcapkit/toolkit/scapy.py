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
   :class:`scapy.layers.inet6.IPv6`, for instance. Those imports are
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
import struct
from typing import TYPE_CHECKING, NamedTuple, cast

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.data import FrameRecord
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.protocols.internet.internet import EXTENSION_HEADER_LIMIT
from pcapkit.protocols.protocol import FRAME_LAYER_LIMIT
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.toolkit.pypcapfile import (IP_TUNNELS, IPV4_EXTENSION_HEADERS, IPV4_HEADER_LEN,
                                        IPV6_EXTENSION_HEADERS, IPV6_HEADER_LEN, TCP_MIN_HEADER_LEN,
                                        _default_accepts, _walk_extension_headers)
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
    from typing import Any, Iterator, Optional

    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import Packet

__all__ = [
    'attach_linktype', 'attach_resolution', 'packet2chain', 'packet2dict', 'packet2frame',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]


#: Attribute a packet's timestamp resolution is stashed under, in units per
#: second, by :func:`attach_resolution`.
RESOLUTION_ATTR = '__pcapkit_resolution__'

#: Attribute a packet's data link type is stashed under, as the capture's
#: ``LINKTYPE_*`` number, by :func:`attach_linktype`.
LINKTYPE_ATTR = '__pcapkit_linktype__'

#: The BSD loopback address families the default engine dissects IP behind,
#: each mapped to the IP version it carries, as
#: :class:`~pcapkit.protocols.link.loopback.Loopback` reads them (:issue:`1574`):
#: ``AF_INET``, and the ``AF_INET6`` of each of the BSDs.
LOOPBACK_FAMILIES = {2: 4, 24: 6, 28: 6, 30: 6}


def attach_resolution(packet: 'Packet', resolution: 'int') -> 'None':
    """Stash the timestamp resolution of a packet's capture on the packet.

    Args:
        packet: Scapy packet.
        resolution: Timestamp resolution, in units per second: the PCAP global
            header's, or the PCAP-NG interface's the packet was captured on.

    """
    setattr(packet, RESOLUTION_ATTR, resolution)


def attach_linktype(packet: 'Packet', linktype: 'int') -> 'None':
    """Stash the data link type of a packet's capture on the packet.

    Args:
        packet: Scapy packet.
        linktype: ``LINKTYPE_*`` number: the PCAP global header's, or the
            PCAP-NG interface's the packet was captured on.

    """
    setattr(packet, LINKTYPE_ATTR, linktype)


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
        A :obj:`dict` mapping of packet data. Its ``packet`` is the octets of
        the frame (see :func:`_frame`), none for a zero-length one. Each layer
        carries only the fields
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
        'packet': _frame(packet),
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
        rather than ``bytes(packet)``, which rebuilds them; for a packet not read
        from a capture, such as one built by hand, they are the octets it builds
        into (see :func:`_frame`). ``orig_len`` is ``packet.wirelen``, the
        record's original length.

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

    octets = _frame(packet)
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


def _frame(packet: 'Packet') -> 'bytes':
    """Return the octets of the frame a Scapy packet stands for.

    Args:
        packet: Scapy packet.

    Returns:
        For a packet read from a capture, which every `Scapy`_ reader gives a
        ``wirelen``, the record's original length, ``packet.original``: the
        octets of the record, which the readers keep as read. For any other,
        such as one built by hand, ``bytes(packet)``: the octets it builds into.

    Note:
        `Scapy`_ dissects a packet only from a non-empty string, so a
        zero-length frame comes back as the first layer its link type names,
        every field left to its default, as one built by hand with no fields
        would be. ``bytes()`` of it builds a header out of nothing -- 20 octets
        at ``RAW`` and ``IPV4``, of an IPv4 layer whose ``ihl``, ``len`` and
        ``chksum`` are :data:`None` until then -- where the record has none
        (:issue:`1676`).

    """
    original = getattr(packet, 'original', None)
    if getattr(packet, 'wirelen', None) is not None and isinstance(original, (bytes, bytearray)):
        return bytes(original)
    return bytes(packet)


def _within_datagrams(layer: 'Packet') -> 'bytes':
    """Return the octets from ``layer`` on that lie inside every IP datagram carrying it.

    Args:
        layer: A layer of a dissected Scapy packet.

    Returns:
        The octets of ``layer`` and everything after it, up to the nearest end
        that the Total Length or Payload Length of an IP layer above it declares.

    Note:
        When `Scapy`_ dissects an IP layer, it files whatever follows the
        datagram's declared length as a :class:`~scapy.packet.Padding` layer --
        an Ethernet frame's padding up to its 60-octet minimum, or a trailer
        such as an FCS -- and ``bytes()`` of *any* layer above that one ends
        with it. Those octets are no part of the datagram, and the default
        engine never hands them over (:issue:`1584`), so they are cut off here
        by the default engine's rules: an IPv4 Total Length of zero, as TCP
        segmentation offload leaves, runs the datagram to the end of the frame
        (:issue:`1547`), and an IPv6 Payload Length of zero gives way to a
        Jumbo Payload option (:issue:`1434`). The latter is not left to Scapy,
        which reads that option's length in host byte order and adds the
        Hop-by-Hop Options header to it a second time.

        Every IP layer above ``layer`` bounds it, not only the nearest, as each
        bounds what the default engine hands the next: a datagram tunnelled in
        IP may declare more than the one carrying it holds, or nothing at all.

    """
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    data = bytes(layer)
    end = len(data)
    carrier = layer.underlayer if data else None
    while carrier is not None:
        length = None
        if isinstance(carrier, IPv6):
            if carrier.plen is not None:    # it is until a packet built by hand is built
                # a zero is a jumbogram's, or else it declares nothing
                length = carrier.plen or jumbo_payload_length(carrier.nh, bytes(carrier.payload)) or 0
        elif isinstance(carrier, IP) and carrier.len:   # a zero is TSO's
            ihl = carrier.ihl
            if ihl is None:     # on a layer built by hand, given a Total Length but no IHL
                ihl = bytes(carrier)[0] & 0x0F
            length = max(carrier.len - ihl * 4, 0)
        if length is not None:
            # ``bytes()`` of a layer spans it and every layer after it, padding
            # included, so the difference is the octets between the end of the
            # IP header and ``layer``
            end = min(end, max(length - (len(carrier.payload) - len(data)), 0))
        carrier = carrier.underlayer
    return data[:end]


def _tcp_segment(tcp: 'TCP') -> 'tuple[bytes, bytes] | None':
    """Split the TCP segment ``tcp`` heads into its header and its payload.

    Args:
        tcp: TCP layer of a dissected Scapy packet.

    Returns:
        The header, as many octets as the Data Offset counts, and the payload
        after it, up to the end of the datagrams that carry the segment, c.f.
        ``_within_datagrams()``; or :data:`None` if the datagrams hold fewer
        than the 20 octets of the fixed header, or the Data Offset counts fewer
        (:rfc:`9293#section-3.1`), since the default engine then reads no
        segment at all.

    Note:
        The Data Offset is read off the octets, which for a dissected layer
        carry the ``dataofs`` `Scapy`_ read, and for a layer built by hand the
        one it builds, as it leaves ``dataofs`` :data:`None` until then
        (:issue:`1676`).

    """
    segment = _within_datagrams(tcp)
    hdr_len = (segment[12] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
    if hdr_len < TCP_MIN_HEADER_LEN:
        return None
    return segment[:hdr_len], segment[hdr_len:]


def _ipv4_accepted(ipv4: 'IP') -> 'bool':
    """Test if the default engine reads a Scapy IPv4 layer as an IPv4 layer.

    Args:
        ipv4: IPv4 layer of a dissected Scapy packet.

    Returns:
        :data:`False` if the default engine's IPv4 parser rejects its header --
        its version is not 4, its IHL is below 5 or runs past the captured
        octets, or its options are ones the parser rejects (:issue:`1607`) --
        as the default engine then dissects nothing past it; else :data:`True`.

    Note:
        `Scapy`_ dissects what an IPv4 EtherType or tunnel carries as IPv4
        whatever its version or IHL, and never checks its options, so the
        header is asked of the parser itself, as the pypcapfile engine asks it
        (see :func:`pcapkit.toolkit.pypcapfile._default_accepts`). Its octets
        are those `Scapy`_ dissected the layer from, which ``bytes()`` gives
        back as they were, as far as the IHL goes, and no fewer than the 20 of
        the fixed header, as the default engine reads at least those. A header
        of version 4 with an IHL of 5 is not parsed: `Scapy`_ dissects none
        shorter than 20 octets, and the parser checks nothing else of one.

    """
    if ipv4.version == 4 and ipv4.ihl == 5:
        return True
    octets = bytes(ipv4)
    return _default_accepts('IPv4', octets[:max((octets[0] & 0x0F) * 4, 20)])


def _quoted(layer: 'Packet') -> 'bool':
    """Test if a Scapy layer heads the datagram an ICMP or ICMPv6 error quotes.

    Args:
        layer: A layer of a dissected Scapy packet.

    Returns:
        :data:`True` if ``layer`` is a :class:`~scapy.layers.inet.IPerror` or
        :class:`~scapy.layers.inet6.IPerror6`; else :data:`False`.

    Note:
        The default engine has no ICMP or ICMPv6 parser, so it dissects nothing
        an ICMP message carries. `Scapy`_ dissects the datagram an error quotes
        (:rfc:`792`, :rfc:`4443#section-3`) as ``IPerror`` or ``IPerror6``,
        subclasses of :class:`~scapy.layers.inet.IP` and
        :class:`~scapy.layers.inet6.IPv6`, and those bind the full layers of an
        IP-in-IP tunnel: ``IPerror`` with protocol 41 binds an ``IPv6``, and
        ``IPerror6`` with next header 4 or 41 an ``IP`` or an ``IPv6``, each of
        which carries a real ``TCP`` (:issue:`1627`). Everything from such a
        layer on is out of the default engine's reach.

    """
    from scapy.layers.inet import IPerror
    from scapy.layers.inet6 import IPerror6

    return isinstance(layer, (IPerror, IPerror6))


def _linktype(packet: 'Packet') -> 'Optional[int]':
    """The data link type of the capture a Scapy packet was read from.

    Args:
        packet: Scapy packet.

    Returns:
        The ``LINKTYPE_*`` number :class:`~pcapkit.foundation.engines.scapy.Scapy`
        attached with :func:`attach_linktype`. A packet built by hand carries
        none, so its first layer stands in for it: ``ETHERNET`` for an Ethernet
        II or 802.3 frame, ``LOOP`` and ``NULL`` for the two kinds of BSD
        loopback header `Scapy`_ has, and ``IPV4`` or ``IPV6`` for an IP
        packet; and :data:`None` for any other, which no link type the default
        engine dissects selects.

    """
    linktype = getattr(packet, LINKTYPE_ATTR, None)
    if linktype is not None:
        return int(linktype)

    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Dot3, Ether, Loopback, LoopbackOpenBSD

    if isinstance(packet, (Ether, Dot3)):
        return Enum_LinkType.ETHERNET
    if isinstance(packet, LoopbackOpenBSD):
        return Enum_LinkType.LOOP
    if isinstance(packet, Loopback):
        return Enum_LinkType.NULL
    if isinstance(packet, IP):
        return Enum_LinkType.IPV4
    if isinstance(packet, IPv6):
        return Enum_LinkType.IPV6
    return None


def _network(packet: 'Packet') -> 'Optional[tuple[Packet, int]]':
    """Fetch the layer of a Scapy packet the default engine dissects behind its link layer.

    Args:
        packet: Scapy packet.

    Returns:
        That layer and its place in the frame, the first layer being ``1`` (c.f.
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`), by the
        packet's link type (see :func:`_linktype`): the payload of an Ethernet
        frame, which may be anything `Scapy`_ dissects there; the packet itself
        for a raw IP link type; and for a BSD loopback header the IPv4 or IPv6
        packet its address family names, as the default engine reads it (see
        :data:`LOOPBACK_FAMILIES`). :data:`None` for any other link type, whose
        frames the default engine leaves raw (:issue:`1650`), a loopback
        family it dissects nothing behind, or a zero-length frame, of which it
        dissects nothing at all (:issue:`1676`).

    Note:
        The default engine dissects the first layer of the ``NULL``,
        ``ETHERNET``, ``LOOP``, ``RAW``, ``IPV4`` and ``IPV6`` link types alone
        (:attr:`Frame.__proto__ <pcapkit.protocols.misc.pcap.frame.Frame.__proto__>`),
        and ``RAW`` as IPv4 or IPv6 by its version nibble, as `Scapy`_ does.
        `Scapy`_ dissects IP straight behind the headers of many others, such as
        ``LINUX_SLL``, ``LINUX_SLL2``, ``PPP`` and the ``DLT_RAW`` of 12.

        `Scapy`_ hands a zero-length frame back as a layer of defaults, which
        at ``RAW`` and ``IPV4`` is an IPv4 header with no IHL (see
        :func:`_frame`), so it is told by the frame's octets, not its layers.

        A loopback header's family is read as
        :func:`~pcapkit.protocols.link.loopback.family_byteorder` reads it --
        ``LOOP``'s in network byte order, ``NULL``'s in the byte order its
        octets show -- and the packet behind it is dissected from the octets
        wherever `Scapy`_ dissects otherwise. `Scapy`_ binds IPv6 to the
        ``AF_INET6`` of the host it runs on, and IPv4 to family ``0`` too, so
        what it dissects there depends on the host.

    """
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6

    linktype = _linktype(packet)
    if linktype not in (Enum_LinkType.NULL, Enum_LinkType.ETHERNET, Enum_LinkType.LOOP,
                        Enum_LinkType.RAW, Enum_LinkType.IPV4, Enum_LinkType.IPV6):
        return None
    octets = _frame(packet)
    if not octets:
        return None
    if linktype == Enum_LinkType.ETHERNET:
        return packet.payload, 2
    if linktype in (Enum_LinkType.RAW, Enum_LinkType.IPV4, Enum_LinkType.IPV6):
        return packet, 1

    from pcapkit.protocols.link.loopback import family_byteorder  # isort:skip

    if len(octets) < 4:
        return None
    version = LOOPBACK_FAMILIES.get(int.from_bytes(octets[:4], family_byteorder(octets[:4], linktype)))
    if version is None:
        return None
    layer = packet.payload  # type: Packet
    if not isinstance(layer, IP if version == 4 else IPv6):
        data = octets[4:]
        if len(data) < (IPV4_HEADER_LEN if version == 4 else IPV6_HEADER_LEN):
            return None
        layer = IP(data) if version == 4 else IPv6(data)
    return layer, 2


class _Chain(NamedTuple):
    """The extension header chain of a Scapy IPv6 layer, as the default engine walks it."""

    #: The octets of the IPv6 packet's payload, as far as its Payload Length and
    #: every IP layer above it goes (see :func:`_within_datagrams`).
    payload: 'bytes'
    #: How many extension headers the default engine walks.
    headers: 'int'
    #: Where the first Fragment header it walks starts in :attr:`payload`, or
    #: :data:`None` if it walks none.
    fragment: 'Optional[int]'
    #: The upper layer it dissects behind the chain: the `Scapy`_ layer, or one
    #: dissected here from :attr:`payload`; or :data:`None` if it dissects no
    #: TCP, IPv4 or IPv6 there.
    upper: 'Optional[Packet]'


def _ipv6_chain(ipv6: 'IPv6', depth: 'int') -> '_Chain':
    """Walk the extension header chain of a Scapy IPv6 layer as the default engine walks it.

    Args:
        ipv6: IPv6 layer of a dissected Scapy packet.
        depth: Its place in the frame (see :func:`_network`).

    Returns:
        The chain, walked over the octets by the default engine's rules, as
        :func:`pcapkit.toolkit.pypcapfile._upper_layer` walks it: the
        :data:`~pcapkit.toolkit.pypcapfile.IPV6_EXTENSION_HEADERS`, each sized
        by its own length field, up to
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` of
        them (:issue:`1604`) and as far as
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`, each header being
        one layer of the frame (:issue:`1610`), and no further than a later
        fragment's Fragment header (:rfc:`8200#section-4.5`) or a header cut
        short. The upper layer is a TCP, IPv4 or IPv6 one inside the frame
        bound, dissected from the octets where `Scapy`_ dissected something
        else there.

    Note:
        `Scapy`_ dissects the Hop-by-Hop Options, Routing, Fragment and
        Destination Options headers, and AH, but no TCP and no IPv4 behind an
        AH, and IPv4 where the Next Header is ``0``; the Mobility header but
        nothing behind it; and neither HIP nor Shim6 (:issue:`1626`). Nor does
        it stop at either bound (:issue:`1609`). Its layers are kept as far as
        they are the ones the walk steps over, so the upper layer is its own
        wherever it dissected the chain as the default engine does.

    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6, _IPv6ExtHdr
    from scapy.layers.ipsec import AH

    head = bytes(ipv6)[:IPV6_HEADER_LEN]
    payload = _within_datagrams(ipv6.payload)
    nxt = head[6] if len(head) == IPV6_HEADER_LEN else None
    offset, headers, fragment = 0, 0, None  # type: int, int, Optional[int]
    bound = min(EXTENSION_HEADER_LIMIT, FRAME_LAYER_LIMIT - depth)
    # the headers Scapy dissects, as AH or one of its ``_IPv6ExtHdr`` layers
    dissects = (Enum_ExtensionHeader.HOPOPT, Enum_ExtensionHeader.IPv6_Route, Enum_ExtensionHeader.IPv6_Frag,
                Enum_ExtensionHeader.IPv6_Opts, Enum_ExtensionHeader.AH)
    layer = ipv6.payload  # type: Optional[Packet] # Scapy's, while it walks the chain alike
    while nxt in IPV6_EXTENSION_HEADERS:
        if headers == bound or len(payload) < offset + 8:
            return _Chain(payload, headers, fragment, None)
        headers += 1
        if nxt in dissects and isinstance(layer, AH if nxt == Enum_ExtensionHeader.AH else _IPv6ExtHdr):
            layer = layer.payload
        else:
            layer = None
        if nxt == Enum_ExtensionHeader.IPv6_Frag:  # fixed length, second octet reserved
            if fragment is None:
                fragment = offset
            if struct.unpack_from('!H', payload, offset + 2)[0] >> 3:  # a later fragment
                return _Chain(payload, headers, fragment, None)
            length = 8
        elif nxt == Enum_ExtensionHeader.AH:  # length in 4-octet units, less two
            length = (payload[offset + 1] + 2) * 4
        else:  # length in 8-octet units, less one
            length = (payload[offset + 1] + 1) * 8
        nxt, offset = payload[offset], offset + length

    upper = None  # type: Optional[Packet]
    data = payload[offset:]
    if depth + headers + 1 > FRAME_LAYER_LIMIT or len(payload) < offset:
        pass
    elif nxt == Enum_TransType.TCP:
        if isinstance(layer, TCP):
            upper = layer
        elif len(data) >= TCP_MIN_HEADER_LEN:
            upper = TCP(data)
    elif nxt in IP_TUNNELS:
        version = IP_TUNNELS[nxt]
        if isinstance(layer, IP if version == 4 else IPv6) and not _quoted(layer):
            upper = layer
        elif len(data) >= (IPV4_HEADER_LEN if version == 4 else IPV6_HEADER_LEN):
            upper = IP(data) if version == 4 else IPv6(data)
    return _Chain(payload, headers, fragment, upper)


class _Layer(NamedTuple):
    """A layer of a Scapy packet that the default engine dissects too."""

    #: The `Scapy`_ layer, or one dissected here from the octets.
    layer: 'Packet'
    #: Its place in the frame, the first layer being ``1`` (c.f.
    #: :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`).
    depth: 'int'
    #: For a TCP layer the default engine reads behind an AH or IPv6 extension
    #: header in IPv4, its header and payload as that engine splits them (see
    #: :func:`_tcp_behind_extension_headers`); else :data:`None`.
    segment: 'Optional[tuple[bytes, bytes]]' = None


def _dissected(packet: 'Packet') -> 'Iterator[_Layer]':
    """Walk the layers of a Scapy packet that the default engine dissects too.

    Args:
        packet: Scapy packet.

    Yields:
        The layer the default engine dissects behind the link layer (see
        :func:`_network`), and each one on from it that it dissects as well,
        up to the first that carries nothing it dissects: anything but an
        802.1Q or 802.1ad tag, IPv4 or IPv6; an IPv4 layer that is a later
        fragment, whose data is a slice of the datagram's payload with no
        upper-layer header in it (:rfc:`791#section-3.2`, :issue:`1617`). It
        stops short of an IPv4 layer whose header the default engine rejects
        (see :func:`_ipv4_accepted`), of the datagram an ICMP or ICMPv6 error
        quotes (see :func:`_quoted`), and of
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`, past which the
        default engine dissects nothing (:issue:`1609`).

        An IPv6 layer is followed by the upper layer behind its extension
        headers (see :func:`_ipv6_chain`), which are not yielded. An IPv4 layer
        whose protocol names an AH or IPv6 extension header carries what the
        default engine reads past those headers, by its own rules and up to
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` of
        them in a row (see
        :func:`~pcapkit.toolkit.pypcapfile._walk_extension_headers`): a tunnel,
        or a TCP segment, each dissected from the octets (:issue:`1606`).

    Note:
        The default engine dissects IP only where its dispatch tables send it:
        a link type, an EtherType of the link layer or of a VLAN tag
        (:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`),
        and a protocol number of IP or of an extension header
        (:attr:`Internet.__proto__
        <pcapkit.protocols.internet.internet.Internet.__proto__>`). It leaves
        raw the other layers `Scapy`_ dissects IP inside -- GRE, PPPoE, an
        802.3 frame's LLC/SNAP header, VXLAN, the PPP frame L2TPv2 carries,
        and ICMP -- so it reads no IP, and no TCP, past one (:issue:`1636`).

        Inside IPv4, `Scapy`_ dissects an AH alone of those headers, and behind
        one only IPv6 and, for a Next Header of ``0``, IPv4, so the default
        engine's rules are applied to the octets instead. It also dissects IPv6
        and AH inside a later fragment, binding neither to a zero fragment
        offset as it binds TCP.

        The payloads are walked, not ``getlayer()``, which searches the
        packets a field holds as well, such as the IPv6 packet a Redirected
        Header option carries (:rfc:`4861#section-4.6.3`).

    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Dot1AD, Dot1Q
    from scapy.packet import NoPayload

    if (network := _network(packet)) is None:
        return
    layer, depth = network
    while depth <= FRAME_LAYER_LIMIT and not isinstance(layer, NoPayload) and not _quoted(layer):
        if isinstance(layer, IP):
            if not _ipv4_accepted(layer):
                return
            yield _Layer(layer, depth)
            if layer.frag:
                return
            if layer.proto not in IPV4_EXTENSION_HEADERS:
                layer, depth = layer.payload, depth + 1
                continue
            if (walked := _walk_extension_headers(layer.proto, _within_datagrams(layer.payload))) is None:
                return
            proto, data, hops = walked
            depth += hops + 1
            if depth > FRAME_LAYER_LIMIT:
                return
            if proto == Enum_TransType.TCP:
                if (segment := _tcp_behind_extension_headers(data)) is not None:
                    yield _Layer(TCP(data), depth, segment)
                return
            if proto not in IP_TUNNELS:
                return
            version = IP_TUNNELS[proto]
            if len(data) < (IPV4_HEADER_LEN if version == 4 else IPV6_HEADER_LEN):
                return
            layer = IP(data) if version == 4 else IPv6(data)
        elif isinstance(layer, IPv6):
            yield _Layer(layer, depth)
            chain = _ipv6_chain(layer, depth)
            if chain.upper is None:
                return
            layer, depth = chain.upper, depth + chain.headers + 1
        else:
            yield _Layer(layer, depth)
            if not isinstance(layer, (Dot1Q, Dot1AD)):
                return
            layer, depth = layer.payload, depth + 1


def _first_ipv4(packet: 'Packet') -> 'IP | None':
    """Fetch the first IPv4 layer of a Scapy packet, as the default engine dissects it.

    Args:
        packet: Scapy packet.

    Returns:
        The first :class:`~scapy.layers.inet.IP` layer of the packet the default
        engine dissects too, however deep -- e.g. one carried in IPv6
        (:rfc:`2473`) -- or :data:`None` if there is none (see
        :func:`_dissected`).

    Note:
        The default engine takes ``frame['IPv4']``
        (:func:`pcapkit.toolkit.pcap.ipv4_reassembly`). ``packet['IP']`` finds
        the same layer but for one inside an ICMPv6 error's quote, which it
        reaches through the ``IPerror6`` there, or inside a layer the default
        engine leaves raw, such as GRE (:issue:`1636`), or one past the frame's
        layer bound (:issue:`1609`).

    """
    from scapy.layers.inet import IP

    for found in _dissected(packet):
        if isinstance(found.layer, IP):
            return found.layer
    return None


def _first_ipv6(packet: 'Packet') -> 'Optional[_Layer]':
    """Fetch the first IPv6 layer of a Scapy packet, as the default engine dissects it.

    Args:
        packet: Scapy packet.

    Returns:
        The first :class:`~scapy.layers.inet6.IPv6` layer of the packet the
        default engine dissects too, however deep -- e.g. one carried in IPv4
        (:rfc:`4213`) -- with its place in the frame, or :data:`None` if there
        is none (see :func:`_dissected`).

    Note:
        The default engine takes ``frame['IPv6']``
        (:func:`pcapkit.toolkit.pcap.ipv6_reassembly`). ``packet['IPv6']``
        finds the same layer but for one inside an ICMP or ICMPv6 error's
        quote, a later IPv4 fragment, or a layer the default engine leaves
        raw, such as GRE (:issue:`1635`), or one past the frame's layer bound
        (:issue:`1609`).

    """
    from scapy.layers.inet6 import IPv6

    for found in _dissected(packet):
        if isinstance(found.layer, IPv6):
            return found
    return None


def _tcp_behind_extension_headers(segment: 'bytes') -> 'tuple[bytes, bytes] | None':
    """Split a TCP segment the default engine reads behind an AH or IPv6 extension header in IPv4.

    Args:
        segment: Raw octets from the TCP header on, as far as the IPv4 layer
            carrying it goes (see :func:`_dissected`).

    Returns:
        The header, as many octets as the Data Offset counts, and the payload
        after it; or :data:`None` if the default engine reads no TCP there:
        fewer than :data:`TCP_MIN_HEADER_LEN
        <pcapkit.toolkit.pypcapfile.TCP_MIN_HEADER_LEN>` octets, a Data Offset
        counting fewer or more than were captured, or options its TCP parser
        rejects (see :func:`~pcapkit.toolkit.pypcapfile._default_accepts`).

    Note:
        Directly over IP, the default engine reads a TCP header its parser
        rejects out of the raw octets left behind
        (:func:`pcapkit.toolkit.pcap.tcp_segment`), but behind another header
        it does not, so the parser's answer stands here, as for the pypcapfile
        engine.

    """
    hdr_len = (segment[12] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
    if hdr_len < TCP_MIN_HEADER_LEN or hdr_len > len(segment):
        return None
    if hdr_len > TCP_MIN_HEADER_LEN and not _default_accepts('TCP', segment[:hdr_len]):
        return None
    return segment[:hdr_len], segment[hdr_len:]


def _tcp_carrier(packet: 'Packet') -> 'tuple[IP | IPv6, TCP, bytes, bytes] | None':
    """Fetch the TCP segment of a Scapy packet, and the IP layer that carries it.

    Args:
        packet: Scapy packet.

    Returns:
        The nearest :class:`~scapy.layers.inet.IP` or
        :class:`~scapy.layers.inet6.IPv6` layer above the packet's TCP layer,
        that layer, and the segment's header and payload (see
        :func:`_tcp_segment`); or :data:`None` if there is no such IP layer, or
        the default engine reads no TCP there: it dissects no TCP layer in the
        frame (see :func:`_dissected`) -- one behind a link type it leaves raw
        (:issue:`1650`), behind a layer it leaves raw, such as GRE
        (:issue:`1636`), an IPv4 layer whose header it rejects, or a later IPv4
        fragment (:issue:`1617`), in the datagram an ICMP or ICMPv6 error quotes
        (see :func:`_quoted`, :issue:`1627`), or past the frame's layer bound or
        an extension header chain's (:issue:`1609`). A TCP segment the default
        engine reads behind an AH or IPv6 extension header in IPv4 is split by
        :func:`_tcp_behind_extension_headers` instead (:issue:`1606`).

    Note:
        The nearest is the innermost IP layer of an IP-in-IP tunnel
        (:rfc:`2003`, :rfc:`2473`, :rfc:`4213`), whose addresses are the TCP
        endpoints', as for the default engine
        (:func:`pcapkit.toolkit.pcap.tcp_segment`). ``packet['IP']`` finds the
        outermost IPv4 layer instead, which is the tunnel's, or with IPv4
        carried in IPv6 the inner one (:issue:`1581`). The extension headers
        between an IPv6 layer and its payload are not IP layers, so are
        stepped over.

    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6

    carrier = None  # type: IP | IPv6 | None
    for found in _dissected(packet):
        if isinstance(found.layer, (IP, IPv6)):
            carrier = found.layer
        elif isinstance(found.layer, TCP):
            if carrier is None:
                return None
            segment = _tcp_segment(found.layer) if found.segment is None else found.segment
            return None if segment is None else (carrier, found.layer, *segment)
    return None


def ipv4_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        packet: Scapy packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv4 reassembly.

        * If the ``packet`` can be used for IPv4 reassembly. A packet can be reassembled
          if it contains IPv4 layer (:class:`scapy.layers.inet.IP`) -- the first of the
          frame the default engine dissects, so one carried in IPv6 counts but none an
          ICMP or ICMPv6 error quotes, a layer that engine leaves raw carries, such as
          GRE, a link type it leaves raw carries, or one past the frame's layer bound (see
          :func:`_first_ipv4`) -- whose header the default engine accepts (see
          :func:`_ipv4_accepted`) and lies inside every IPv6 packet carrying it, and the
          **DF** (:attr:`scapy.layers.inet.IP.flags.DF`) flag is :data:`False`.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')

    if (ipv4 := _first_ipv4(packet)) is not None:
        if ipv4.flags.DF:       # dismiss not fragmented packet
            return None
        # NOTE: ``bytes(ipv4)`` ends with the frame's trailer, which Scapy files
        # as padding at the end of the packet however deep the IPv4 layer, but
        # the default engine hands it only the octets inside the Payload Length
        # of each IPv6 packet above it, so those are all it keeps (:issue:`1623`)
        octets = _within_datagrams(ipv4)
        # NOTE: the IHL and Total Length are read off the octets, as Scapy
        # leaves ``ihl`` and ``len`` None on a layer built by hand until it is
        # built (:issue:`1676`)
        ihl = (octets[0] & 0x0F) * 4 if octets else IPV4_HEADER_LEN
        # the default engine dissects no IPv4 header those octets cut short
        if len(octets) < max(ihl, IPV4_HEADER_LEN) or not _ipv4_accepted(ipv4):
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
            ihl=ihl,                                   # internet header length
            mf=bool(ipv4.flags.MF),                    # more fragment flag
            tl=int.from_bytes(octets[2:4], 'big'),     # total length, header includes
            header=octets[:ihl],                       # raw bytes type header
            # NOTE: this keeps the octets past the Total Length, as the default
            # engine's adapter does, since the reassembly machinery cuts the
            # payload at ``tl - ihl`` itself. :func:`ipv6_reassembly` derives
            # its ``tl`` from the payload, so it has to cut them (:issue:`1584`).
            payload=bytearray(octets[ihl:]),           # raw bytearray type payload
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
          if it contains IPv6 layer (:class:`scapy.layers.inet6.IPv6`) -- the first of the
          frame the default engine dissects, so one carried in IPv4 counts but none an ICMP
          or ICMPv6 error quotes, a later IPv4 fragment carries, a layer that engine leaves
          raw carries, such as GRE, a link type it leaves raw carries, or one past the
          frame's layer bound (see :func:`_first_ipv6`) -- and IPv6 Fragment header
          (:rfc:`2460#section-4.5`) in that layer's own extension header chain, as far as
          the default engine walks it (see :func:`_ipv6_chain`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')

    if (found := _first_ipv6(packet)) is not None:
        ipv6 = cast('IPv6', found.layer)
        chain = _ipv6_chain(ipv6, found.depth)
        if chain.fragment is None:
            return None                        # dismiss not fragmented packet

        # NOTE: The unfragmentable part is every octet before the Fragment
        # header, which is the only part of the header the reassembled packet
        # keeps (:rfc:`8200#section-4.5`). The walk read the Fragment header off
        # the octets, as `Scapy`_ dissects none behind a Mobility, HIP or Shim6
        # header (:issue:`1626`).
        hdr_len = IPV6_HEADER_LEN + chain.fragment
        ipv6_frag = chain.payload[chain.fragment:chain.fragment + 8]
        field = int.from_bytes(ipv6_frag[2:4], 'big')
        # the fragment's data stops at the Payload Length, so neither it nor
        # ``tl`` below counts the frame's trailer (:issue:`1584`)
        payload = bytearray(chain.payload[chain.fragment + 8:])

        data = IP_Packet(
            bufid=(
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.src)),     # source IP address
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.dst)),     # destination IP address
                int.from_bytes(ipv6_frag[4:8], 'big'),    # identification
                Enum_TransType.get(ipv6_frag[0]),         # next header field in IPv6 Fragment Header
            ),
            num=count,                                    # original packet range number
            # NOTE: The Fragment Offset counts on-wire 8-octet units
            # (:rfc:`8200#section-4.5`), but the reassembly machinery indexes
            # the datagram buffer with ``fo``, so it must be scaled into octets.
            fo=(field >> 3) * 8,                          # fragment offset
            ihl=hdr_len,                                  # header length, only headers before IPv6-Frag
            mf=bool(field & 1),                           # more fragment flag
            # NOTE: the Fragment header is not counted, as the reassembly
            # machinery writes the payload over the span ``tl - ihl``, so counting
            # it would leave 8 octets of stray zeroes in every reassembled datagram.
            tl=hdr_len + len(payload),                    # total length, header includes
            header=bytes(ipv6)[:IPV6_HEADER_LEN] + chain.payload[:chain.fragment],  # header before IPv6-Frag
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
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`) whose fixed header
          lies inside its datagram, and whose Data Offset counts at least that header,
          behind no IPv4 header the default engine rejects, in no later IPv4 fragment, in
          no datagram an ICMP or ICMPv6 error quotes, in no layer or link type the default
          engine leaves raw, such as GRE or ``LINUX_SLL``, and inside the frame's layer
          bound and an extension header chain's; or a TCP segment the default engine reads
          behind an AH or IPv6 extension header in IPv4, or behind an IPv6 extension header
          `Scapy`_ dissects nothing behind. It is keyed by the IP layer that carries it --
          in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    if (found := _tcp_carrier(packet)) is not None:
        ip, tcp, header, payload = found

        raw_len = len(payload)                      # payload length, header excludes
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
            header=header,                          # raw bytes type header
            payload=bytearray(payload),             # raw bytearray type payload
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
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`), on the terms
          :func:`tcp_reassembly` sets.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    if (found := _tcp_carrier(packet)) is not None:
        ip, tcp, header, payload = found

        # NOTE: the link type of the interface the packet was read from, which
        # :class:`~pcapkit.foundation.engines.scapy.Scapy` attaches with
        # :func:`attach_linktype` -- not one inferred from the first layer,
        # which a raw IPv4 interface's packets share with no link type (#1517).
        linktype = getattr(packet, LINKTYPE_ATTR, None)
        if linktype is not None:
            protocol = Enum_LinkType.get(linktype)
        else:
            # A packet built by hand carries none, so it is looked up by its
            # first layer's name -- with no default, deliberately. ``get()``
            # with no default raises on an unresolvable name rather than minting
            # one (#775). NULL and RAW are genuine DLTs -- BSD loopback and raw
            # IP framing, respectively -- each meant to go with its own handler
            # protocol class, so neither is an honest stand-in for "unknown link
            # type" and this must not paper over the miss with either. An
            # IP-rooted Scapy packet's ``(IP()/TCP()).name`` is ``'IP'``, which
            # is not a LinkType member name, and raises. Note the asymmetry,
            # which is not a choice made here: an IPv6-rooted packet's name
            # uppercases to ``'IPV6'``, which *is* a member (``LinkType.IPV6``,
            # 229), so it resolves silently -- to a DLT the caller never chose.
            # Only the v4 name happens to miss. The ``KeyError`` from
            # :meth:`LinkType.get` is caught and re-raised as
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
            header=header,                                       # raw bytes type header
            payload=bytearray(payload),                          # raw bytearray type payload
        )
        return data
    return None
