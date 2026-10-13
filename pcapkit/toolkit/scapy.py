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
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.toolkit.pypcapfile import (IP_TUNNELS, IPV4_EXTENSION_HEADERS, IPV4_HEADER_LEN,
                                        IPV6_HEADER_LEN, TCP_MIN_HEADER_LEN, _default_accepts,
                                        _past_extension_headers)
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
    from typing import Any, Iterator

    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6, IPv6ExtHdrFragment
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
            length = max(carrier.len - carrier.ihl * 4, 0)
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

    """
    segment = _within_datagrams(tcp)
    hdr_len = tcp.dataofs * 4
    if len(segment) < 20 or hdr_len < 20:
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


def _extension_headers() -> 'tuple[type[Packet], ...]':
    """The `Scapy`_ layers of an IPv6 extension header chain that the default engine reads past.

    Returns:
        The base class of `Scapy`_'s IPv6 Hop-by-Hop Options, Routing, Fragment
        and Destination Options headers, and its AH.

    Note:
        Of the IPv6 extension headers
        (:class:`~pcapkit.const.ipv6.extension_header.ExtensionHeader`), the
        default engine reads past the Hop-by-Hop Options, Routing, Fragment,
        Destination Options, AH, Mobility, HIP and Shim6 headers. It stops at
        ESP, whose Next Header field lies in the encrypted part of the packet
        (:rfc:`4303`), and at codes 253 and 254, which have no parser. `Scapy`_
        dissects the ESP and Mobility headers but nothing behind them, nothing
        but IP behind an AH, and neither HIP nor Shim6.

    """
    from scapy.layers.inet6 import _IPv6ExtHdr
    from scapy.layers.ipsec import AH

    return _IPv6ExtHdr, AH


def _carries(layer: 'Packet', *, root: 'bool' = False) -> 'bool':
    """Test if the default engine dissects what a Scapy layer carries, as `Scapy`_ does.

    Args:
        layer: A layer of a dissected Scapy packet.
        root: Whether ``layer`` is the packet's first, the one the capture's
            link type selects.

    Returns:
        For an IPv4 layer, whether the default engine accepts its header (see
        :func:`_ipv4_accepted`) and it is no later fragment, whose data is a
        slice of the datagram's payload with no upper-layer header in it
        (:rfc:`791#section-3.2`, :issue:`1617`). For any other, whether it is
        the first, an 802.1Q or 802.1ad tag, an IPv6 layer or an extension
        header in its chain (see :func:`_extension_headers`). :data:`False`
        for the datagram an ICMP or ICMPv6 error quotes (see :func:`_quoted`).

    Note:
        The default engine dissects IP only where its dispatch tables send it:
        an EtherType of the link layer or of a VLAN tag
        (:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`),
        and a protocol number of IP or of an extension header
        (:attr:`Internet.__proto__
        <pcapkit.protocols.internet.internet.Internet.__proto__>`). It leaves
        raw the other layers `Scapy`_ dissects IP inside -- GRE, PPPoE, an
        802.3 frame's LLC/SNAP header, VXLAN, the PPP frame L2TPv2 carries,
        and ICMP -- so it reads no IP, and no TCP, past one (:issue:`1636`).
        The first layer is the one the capture's link type selects, and is
        taken to carry whatever `Scapy`_ dissects in it. Where `Scapy`_
        dissects another layer before IP there -- PPP behind HDLC-like framing
        (link types 9 and 50) or PPPoE (51), the LLC header of an 802.11 frame
        (105), or the 802.11 frame behind a radiotap or PPI header (127, 192)
        -- that layer is taken to carry nothing, as the default engine
        dissects none of those link types.

    """
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6
    from scapy.layers.l2 import Dot1AD, Dot1Q

    if _quoted(layer):
        return False
    if isinstance(layer, IP):
        return not layer.frag and _ipv4_accepted(layer)
    return root or isinstance(layer, (Dot1Q, Dot1AD, IPv6, *_extension_headers()))


def _dissected(packet: 'Packet') -> 'Iterator[Packet]':
    """Walk the layers of a Scapy packet that the default engine dissects too.

    Args:
        packet: Scapy packet.

    Yields:
        Each layer of the packet from the first on, up to the first that does
        not carry what follows it as the default engine dissects it (see
        :func:`_carries`), and short of the datagram an ICMP or ICMPv6 error
        quotes (see :func:`_quoted`).

    Note:
        The payloads are walked, not ``getlayer()``, which searches the
        packets a field holds as well, such as the IPv6 packet a Redirected
        Header option carries (:rfc:`4861#section-4.6.3`).

    """
    from scapy.packet import NoPayload

    layer = packet  # type: Packet
    while not isinstance(layer, NoPayload) and not _quoted(layer):
        yield layer
        if not _carries(layer, root=layer is packet):
            return
        layer = layer.payload


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
        engine leaves raw, such as GRE (:issue:`1636`).

    """
    from scapy.layers.inet import IP

    for layer in _dissected(packet):
        if isinstance(layer, IP):
            return layer
    return None


def _first_ipv6(packet: 'Packet') -> 'IPv6 | None':
    """Fetch the first IPv6 layer of a Scapy packet, as the default engine dissects it.

    Args:
        packet: Scapy packet.

    Returns:
        The first :class:`~scapy.layers.inet6.IPv6` layer of the packet the
        default engine dissects too, however deep -- e.g. one carried in IPv4
        (:rfc:`4213`) -- or :data:`None` if there is none (see
        :func:`_dissected`).

    Note:
        The default engine takes ``frame['IPv6']``
        (:func:`pcapkit.toolkit.pcap.ipv6_reassembly`). ``packet['IPv6']``
        finds the same layer but for one inside an ICMP or ICMPv6 error's
        quote, a later IPv4 fragment, or a layer the default engine leaves
        raw, such as GRE (:issue:`1635`).

    """
    from scapy.layers.inet6 import IPv6

    for layer in _dissected(packet):
        if isinstance(layer, IPv6):
            return layer
    return None


def _fragment_header(ipv6: 'IPv6') -> 'IPv6ExtHdrFragment | None':
    """Fetch the Fragment header of a Scapy IPv6 layer's own extension header chain.

    Args:
        ipv6: IPv6 layer of a dissected Scapy packet.

    Returns:
        The first :class:`~scapy.layers.inet6.IPv6ExtHdrFragment` of the
        extension headers that follow ``ipv6`` (see
        :func:`_extension_headers`), or :data:`None` if there is none before the
        upper-layer header.

    Note:
        The default engine reads the Fragment header of that chain alone
        (:func:`pcapkit.toolkit.pcap.ipv6_reassembly`). One behind the
        upper-layer header, such as that of an IPv6 packet tunnelled in this
        one, belongs to the packet inside (:rfc:`8200#section-4`,
        :rfc:`2473#section-3.1`), and ``IPv6ExtHdrFragment in ipv6`` finds it
        all the same (:issue:`1635`).

    """
    from scapy.layers.inet6 import IPv6ExtHdrFragment

    layer = ipv6.payload  # type: Packet
    while isinstance(layer, _extension_headers()):
        if isinstance(layer, IPv6ExtHdrFragment):
            return layer
        layer = layer.payload
    return None


def _tcp_behind_extension_headers(segment: 'bytes') -> 'tuple[bytes, bytes] | None':
    """Split a TCP segment the default engine reads behind an AH or IPv6 extension header in IPv4.

    Args:
        segment: Raw octets from the TCP header on, as far as the IPv4 layer
            carrying it goes (see :func:`_tcp_carrier`).

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
        the default engine reads no TCP there: it dissects nothing past a layer
        above it (see :func:`_carries`) -- one it leaves raw, such as GRE
        (:issue:`1636`), an IPv4 layer whose header it rejects, or a later IPv4
        fragment (:issue:`1617`) -- or the TCP layer lies in the datagram an
        ICMP or ICMPv6 error quotes (see :func:`_quoted`, :issue:`1627`).

        An IPv4 layer whose protocol names an AH or IPv6 extension header
        carries what the default engine reads past those headers, by its own
        rules and up to
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` of
        them in a row (see
        :func:`~pcapkit.toolkit.pypcapfile._past_extension_headers`): a tunnel,
        walked on as above, or a TCP segment (see
        :func:`_tcp_behind_extension_headers`), each dissected from the
        octets (:issue:`1606`).

    Note:
        The nearest is the innermost IP layer of an IP-in-IP tunnel
        (:rfc:`2003`, :rfc:`2473`, :rfc:`4213`), whose addresses are the TCP
        endpoints', as for the default engine
        (:func:`pcapkit.toolkit.pcap.tcp_segment`). ``packet['IP']`` finds the
        outermost IPv4 layer instead, which is the tunnel's, or with IPv4
        carried in IPv6 the inner one (:issue:`1581`). The extension header
        layers `Scapy`_ dissects between an IPv6 layer and its payload are not
        IP layers, so are stepped over.

        Inside IPv4, `Scapy`_ dissects an AH alone of those headers, and behind
        one only IPv6 and, for a Next Header of ``0``, IPv4, so the default
        engine's rules are applied to the octets instead. It also dissects IPv6
        and AH inside a later fragment, binding neither to a zero fragment
        offset as it binds TCP.

    """
    from scapy.layers.inet import IP, TCP
    from scapy.layers.inet6 import IPv6
    from scapy.packet import NoPayload

    tcp = cast('TCP | None', packet.getlayer('TCP'))
    carrier = None  # type: IP | IPv6 | None
    layer = packet  # type: Packet
    while layer is not tcp:
        if isinstance(layer, NoPayload) or not _carries(layer, root=layer is packet):
            return None
        if isinstance(layer, IP):
            carrier = layer
            if layer.proto in IPV4_EXTENSION_HEADERS:
                upper = _past_extension_headers(layer.proto, _within_datagrams(layer.payload))
                if upper is not None and upper[0] == Enum_TransType.TCP:
                    segment = _tcp_behind_extension_headers(upper[1])
                    return None if segment is None else (carrier, TCP(upper[1]), *segment)
                if upper is None or upper[0] not in IP_TUNNELS:
                    return None
                version, data = IP_TUNNELS[upper[0]], upper[1]
                if len(data) < (IPV4_HEADER_LEN if version == 4 else IPV6_HEADER_LEN):
                    return None
                layer = IP(data) if version == 4 else IPv6(data)
                tcp = cast('TCP | None', layer.getlayer('TCP'))
                continue
        elif isinstance(layer, IPv6):
            carrier = layer
        layer = layer.payload

    if carrier is None or (segment := _tcp_segment(tcp)) is None:
        return None
    return carrier, tcp, *segment


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
          ICMP or ICMPv6 error quotes or a layer that engine leaves raw carries, such as
          GRE (see :func:`_first_ipv4`) -- whose header the default engine accepts (see
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
        ihl = ipv4.ihl * 4
        # the default engine dissects no IPv4 header those octets cut short
        if len(octets) < ihl or not _ipv4_accepted(ipv4):
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
            tl=ipv4.len,                               # total length, header includes
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
          or ICMPv6 error quotes, a later IPv4 fragment carries, or a layer that engine
          leaves raw carries, such as GRE (see :func:`_first_ipv6`) -- and IPv6 Fragment
          header (:rfc:`2460#section-4.5`, i.e., :class:`scapy.layers.inet6.IPv6ExtHdrFragment`)
          in that layer's own extension header chain (see :func:`_fragment_header`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')

    if (ipv6 := _first_ipv6(packet)) is not None:
        if (ipv6_frag := _fragment_header(ipv6)) is None:
            return None                        # dismiss not fragmented packet

        # NOTE: ``len()`` of a Scapy layer spans that layer and everything after
        # it, so the difference is the unfragmentable part -- every octet before
        # the Fragment header, which is the only part of the header the
        # reassembled packet keeps (:rfc:`8200#section-4.5`).
        hdr_len = len(ipv6) - len(ipv6_frag)
        # the fragment's data stops at the Payload Length, so neither it nor
        # ``tl`` below counts the frame's trailer (:issue:`1584`)
        payload = bytearray(_within_datagrams(ipv6_frag.payload))

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
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`) whose fixed header
          lies inside its datagram, and whose Data Offset counts at least that header,
          behind no IPv4 header the default engine rejects, in no later IPv4 fragment, in
          no datagram an ICMP or ICMPv6 error quotes and in no layer the default engine
          leaves raw, such as GRE, or a TCP segment the default engine reads behind an AH
          or IPv6 extension header in IPv4. It is keyed by the IP layer that carries it --
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
