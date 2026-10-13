# -*- coding: utf-8 -*-
"""DPKT Tools
================

.. module:: pcapkit.toolkit.dpkt

:mod:`pcapkit.toolkit.dpkt` contains the adapters for the `DPKT`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. _DPKT: https://dpkt.readthedocs.io

"""
import copy
import decimal
import ipaddress
from typing import TYPE_CHECKING, NamedTuple, cast

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.data import FrameRecord
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.protocols.internet.internet import EXTENSION_HEADER_LIMIT
from pcapkit.protocols.link.loopback import family_byteorder
from pcapkit.protocols.protocol import FRAME_LAYER_LIMIT
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.toolkit.pypcapfile import (IPV4_EXTENSION_HEADERS, IPV4_HEADER_LEN,
                                        IPV6_EXTENSION_HEADERS, IPV6_HEADER_LEN, TCP_MIN_HEADER_LEN,
                                        VLAN_TAG_LEN, VLAN_TAGS, _default_accepts,
                                        _walk_extension_headers)
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from decimal import Decimal
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Iterator, Optional

    from dpkt.dpkt import Packet
    from dpkt.ethernet import Ethernet
    from dpkt.ip import IP
    from dpkt.ip6 import IP6

__all__ = [
    'RecordTimestamp', 'Timestamp', 'DecimalTimestamp', 'ipv6_hdr_len', 'attach_timestamp', 'packet2timestamp', 'attach_buffer', 'packet2bytes',
    'attach_linktype', 'packet2frame', 'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow'
]

#: Attribute a frame's capture timestamp is stashed under.
#:
#: `DPKT`_ keeps the two halves of a record apart -- its reader yields
#: ``(timestamp, bytes)`` and only the bytes become a packet -- so a frame on its
#: own does not know when it was captured. Anything that reads a frame *after* the
#: extraction loop has moved on therefore has no way back to the timestamp unless
#: the engine puts it somewhere, and this is where
#: :class:`~pcapkit.foundation.engines.dpkt.DPKT` puts it.
#:
#: A `DPKT`_ packet carries a :attr:`~object.__dict__`, so this is an ordinary
#: attribute rather than anything exotic; the name is spelled out here so that
#: nothing has to know it by hand.
#:
#: .. _DPKT: https://dpkt.readthedocs.io
TIMESTAMP_ATTR = '__pcapkit_timestamp__'

#: Attribute a frame's record octets are stashed under.
#:
#: A `DPKT`_ packet keeps no copy of the octets it was parsed from, and
#: serialising it again is not the same thing: :meth:`dpkt.ip.IP.__bytes__`
#: recomputes a zeroed checksum and length and writes them back into the
#: packet, as do the transport layers beneath it. So the adapters below slice
#: the wire octets out of this buffer instead, which
#: :class:`~pcapkit.foundation.engines.dpkt.DPKT` attaches alongside
#: :data:`TIMESTAMP_ATTR`.
#:
#: .. _DPKT: https://dpkt.readthedocs.io
BUFFER_ATTR = '__pcapkit_buffer__'

#: Attribute a frame's data link type is stashed under, as the capture's
#: ``LINKTYPE_*`` number, by :func:`attach_linktype`.
LINKTYPE_ATTR = '__pcapkit_linktype__'

#: IP protocol numbers of the IP-in-IP tunnels the default engine dissects
#: (see :attr:`Internet.__proto__
#: <pcapkit.protocols.internet.internet.Internet.__proto__>`), over IPv4 and
#: IPv6 alike: IPv4 (protocol 4, :rfc:`2003`) and IPv6 (protocol 41,
#: :rfc:`2473` and :rfc:`4213`). `DPKT`_ also decodes an IPv4 packet's
#: protocol 0 as IPv4, its ``IP_PROTO_IP``, where the default engine reads an
#: IPv6 Hop-by-Hop Options header, so :func:`_ip_layers` does not enter it.
#:
#: .. _DPKT: https://dpkt.readthedocs.io
IP_TUNNELS = frozenset((int(Enum_TransType.IPv4), int(Enum_TransType.IPv6)))

#: Length of an Ethernet II header: two MAC addresses and the EtherType.
ETHERNET_HEADER_LEN = 14

#: Length of a BSD loopback header: the address family.
LOOPBACK_HEADER_LEN = 4

#: EtherTypes of the IP layers the default engine dissects over Ethernet, each
#: mapped to its IP version (see :attr:`Link.__proto__
#: <pcapkit.protocols.link.link.Link.__proto__>`).
ETHERTYPE_IP_VERSIONS = {
    Enum_EtherType.Internet_Protocol_version_4: 4,
    Enum_EtherType.Internet_Protocol_version_6: 6,
}  # type: dict[int, int]

#: Address families of the IP layers the default engine dissects over BSD
#: loopback, each mapped to its IP version (see :attr:`Loopback.__proto__
#: <pcapkit.protocols.link.loopback.Loopback.__proto__>`).
LOOPBACK_IP_VERSIONS = {2: 4, 24: 6, 28: 6, 30: 6}  # type: dict[int, int]

#: Destination address prefixes by which `DPKT`_ reads an Ethernet frame whose
#: EtherType field is an 802.3 length, at most 1500, as Cisco ISL; the default
#: engine reads one as raw octets (see :func:`_ethernet_accepted`).
#:
#: .. _DPKT: https://dpkt.readthedocs.io
ISL_ADDRESSES = (b'\x01\x00\x0c\x00\x00', b'\x03\x00\x0c\x00\x00')

#: TPIDs of the VLAN tags `DPKT`_ steps over in an Ethernet II frame: 802.1Q,
#: 802.1ad and the legacy QinQ ``0x9100`` and ``0x9200``, i.e.
#: ``dpkt.ethernet._ETH_TYPES_QINQ`` (see :func:`_vlan_tpids`).
#:
#: .. _DPKT: https://dpkt.readthedocs.io
DPKT_VLAN_TAGS = frozenset((0x8100, 0x88A8, 0x9100, 0x9200))


class RecordTimestamp:
    """A record's capture timestamp, with what a PCAP frame record needs of it.

    The readers :class:`~pcapkit.foundation.engines.dpkt.DPKT` uses yield
    ``(timestamp, octets)`` and nothing else, so a record's exact timestamp, its
    resolution and its original length would be lost between the reader and
    :func:`packet2frame`. The engine's readers yield a :class:`Timestamp` or a
    :class:`DecimalTimestamp` instead, which *is* the value `DPKT`_ yields --
    so a stored frame's timestamp is exactly what it was before -- and also
    carries those three. Reassembly and flow tracing are handed a plain
    :obj:`float` of it, as by every other engine (:issue:`1501`).

    A copy, a deep copy and a pickle at any protocol all rebuild a timestamp
    from what its :meth:`~object.__reduce__` returns, so all keep the three.
    This class answers each of those protocols itself, ahead of the numeric base
    class: the pure-Python :class:`~decimal.Decimal` copies a subclass as
    ``type(self)(str(self))``, with the constructor's defaults for the rest
    (:issue:`1647`).

    .. _DPKT: https://dpkt.readthedocs.io

    """

    __slots__ = ()

    if TYPE_CHECKING:
        #: Exact timestamp, in seconds since the UNIX epoch.
        exact: 'Decimal'
        #: Timestamp resolution of the record, in units per second.
        resolution: 'int'
        #: Original length of the packet, or :data:`None` if unknown.
        orig_len: 'Optional[int]'

    def __reduce__(self) -> 'tuple[Any, ...]':
        raise NotImplementedError(f'{type(self).__name__} does not say how it is rebuilt')

    def __reduce_ex__(self, protocol: 'Any') -> 'tuple[Any, ...]':
        return self.__reduce__()

    def __copy__(self) -> 'Any':
        factory, args = self.__reduce__()
        return factory(*args)

    def __deepcopy__(self, memo: 'Any') -> 'Any':
        factory, args = self.__reduce__()
        return factory(*copy.deepcopy(args, memo))


class Timestamp(RecordTimestamp, float):
    """A :obj:`float` capture timestamp; see :class:`RecordTimestamp`.

    Args:
        value: The timestamp, as `DPKT`_ yields it.
        exact: Exact timestamp; ``value`` itself if not given.
        resolution: Timestamp resolution of the record, in units per second.
        orig_len: Original length of the packet, or :data:`None` if unknown.

    .. _DPKT: https://dpkt.readthedocs.io

    """

    __slots__ = ('exact', 'resolution', 'orig_len')

    def __new__(cls, value: 'Any' = 0.0, exact: 'Optional[Decimal]' = None,
                resolution: 'int' = 1_000_000, orig_len: 'Optional[int]' = None) -> 'Timestamp':
        self = super().__new__(cls, value)
        self.exact = decimal.Decimal(float(self)) if exact is None else exact
        self.resolution = resolution
        self.orig_len = orig_len
        return self

    def __reduce__(self) -> 'tuple[Any, ...]':
        return type(self), (float(self), self.exact, self.resolution, self.orig_len)


class DecimalTimestamp(RecordTimestamp, decimal.Decimal):
    """A :class:`~decimal.Decimal` capture timestamp; see :class:`RecordTimestamp`.

    `DPKT`_ yields a :class:`~decimal.Decimal` for a nanosecond PCAP.

    Args:
        value: The timestamp, as `DPKT`_ yields it, which is exact.
        resolution: Timestamp resolution of the record, in units per second.
        orig_len: Original length of the packet, or :data:`None` if unknown.

    .. _DPKT: https://dpkt.readthedocs.io

    """

    __slots__ = ('exact', 'resolution', 'orig_len')

    def __new__(cls, value: 'Any' = '0', resolution: 'int' = 1_000_000_000,
                orig_len: 'Optional[int]' = None) -> 'DecimalTimestamp':
        self = super().__new__(cls, value)
        self.exact = decimal.Decimal(self)
        self.resolution = resolution
        self.orig_len = orig_len
        return self

    def __reduce__(self) -> 'tuple[Any, ...]':
        return type(self), (str(self), self.resolution, self.orig_len)


def attach_timestamp(packet: 'Packet', timestamp: 'float') -> 'None':
    """Stash a frame's capture timestamp on the frame.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet, as `DPKT`_'s reader yielded it
            beside the record's octets.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    setattr(packet, TIMESTAMP_ATTR, timestamp)


def packet2timestamp(packet: 'Packet') -> 'float':
    """Read back the capture timestamp of a DPKT packet.

    Args:
        packet: DPKT packet, as stored by
            :class:`~pcapkit.foundation.engines.dpkt.DPKT`.

    Returns:
        Capture timestamp of the packet, in seconds since the epoch.

    Raises:
        UnsupportedCall: If the packet carries no timestamp, i.e. it did not come
            through :class:`~pcapkit.foundation.engines.dpkt.DPKT`. Raised rather
            than defaulted, because a plausible-looking zero would silently
            misdate whatever was going to use it.

    """
    timestamp = getattr(packet, TIMESTAMP_ATTR, None)
    if timestamp is None:
        raise UnsupportedCall(
            f'{type(packet).__name__} carries no capture timestamp; only a frame read by '
            "'Extractor(engine=dpkt)' has one attached"
        )
    return cast('float', timestamp)


def attach_buffer(packet: 'Packet', buffer: 'bytes') -> 'None':
    """Stash a frame's record octets on the frame.

    Args:
        packet: DPKT packet.
        buffer: Octets of the record the packet was parsed from, as `DPKT`_'s
            reader yielded them.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    setattr(packet, BUFFER_ATTR, bytes(buffer))


def attach_linktype(packet: 'Packet', linktype: 'int') -> 'None':
    """Stash the data link type of a frame's capture on the frame.

    Args:
        packet: DPKT packet.
        linktype: ``LINKTYPE_*`` number: the PCAP global header's, or the
            PCAP-NG interface's the packet was captured on.

    Note:
        A frame `DPKT`_ cannot decode is kept as raw octets (see
        :meth:`DPKT.read_frame <pcapkit.foundation.engines.dpkt.DPKT.read_frame>`),
        which do not say what link layer they start with. The adapters read its
        layers off those octets by this (see :func:`_link_network`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    setattr(packet, LINKTYPE_ATTR, int(linktype))


def packet2bytes(packet: 'Packet') -> 'bytes':
    """Fetch the octets of a DPKT packet without modifying it.

    Args:
        packet: DPKT packet.

    Returns:
        The record octets attached by :func:`attach_buffer`, i.e. the frame as
        it was captured. A packet that carries none -- one built by hand rather
        than read by :class:`~pcapkit.foundation.engines.dpkt.DPKT` -- is
        serialised from a copy instead, so that `DPKT`_'s checksum and length
        recomputation never reaches the packet itself.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    buffer = getattr(packet, BUFFER_ATTR, None)
    if buffer is not None:
        return cast('bytes', buffer)
    return cast('bytes', copy.deepcopy(packet).pack())


def packet2frame(packet: 'Packet', timestamp: 'float | Decimal', *,
                 data_link: 'Enum_LinkType') -> 'FrameRecord':
    """Report a DPKT packet to the flow tracer, with its PCAP frame record.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet. The one attached by
            :func:`attach_timestamp`, if any, is preferred, since it is the value
            `DPKT`_'s reader yielded.
        data_link: Data link type.

    Returns:
        The :func:`packet2dict` mapping of the packet, which every trace format
        but PCAP writes as it always has, carrying the captured octets, from
        :func:`packet2bytes`, the PCAP record header the PCAP trace dumper
        writes, and the exact timestamp it reads the header's resolution from.

    Note:
        The fraction in ``frame_info.ts_usec`` is in the capture's own resolution,
        as the default engine's is, and both it and ``orig_len`` come from the
        reader: :class:`~pcapkit.foundation.engines.dpkt.DPKT` reads PCAP and
        PCAP-NG alike into a :class:`RecordTimestamp`. A timestamp that is not one
        -- a packet built by hand, or read by a ``dpkt`` whose reader the engine
        could not extend -- is read as `DPKT`_ yields it: a
        :class:`~decimal.Decimal` counts nanoseconds and a :obj:`float`
        microseconds, and the octets are taken to be whole.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    stamp = getattr(packet, TIMESTAMP_ATTR, timestamp)
    octets = packet2bytes(packet)
    if isinstance(stamp, RecordTimestamp):
        epoch, resolution, orig_len = stamp.exact, stamp.resolution, stamp.orig_len
    elif isinstance(stamp, decimal.Decimal):
        epoch, resolution, orig_len = stamp, 1_000_000_000, None
    else:
        epoch, resolution, orig_len = round(decimal.Decimal(stamp), 6), 1_000_000, None
    ts_sec = int(epoch)
    ts_usec = int((epoch - ts_sec) * (1_000_000_000 if resolution > 1_000_000 else 1_000_000))

    # the mapping is exactly the one reported before #1507, plain value types
    # included, so that the dict-capable trace formats write the same bytes
    if isinstance(timestamp, float):
        timestamp = float(timestamp)
    elif isinstance(timestamp, decimal.Decimal):
        timestamp = decimal.Decimal(timestamp)
    return FrameRecord(
        packet2dict(packet, timestamp, data_link=data_link),
        packet=octets,
        frame_info=Data_FrameInfo(
            ts_sec=ts_sec,
            ts_usec=ts_usec,
            incl_len=len(octets),
            orig_len=len(octets) if orig_len is None else orig_len,
        ),
        time_epoch=decimal.Decimal(epoch),
    )


def _ipv6_ext_hdrs(ipv6: 'IP6') -> 'list[Any]':
    """Fetch an IPv6 packet's extension headers, in the order they were parsed.

    Args:
        ipv6: DPKT IPv6 packet.

    Returns:
        :attr:`dpkt.ip6.IP6.all_extension_headers` where `DPKT`_ recorded it,
        which keeps the on-wire order and any header type that occurs twice;
        otherwise the values of :attr:`~dpkt.ip6.IP6.extension_hdrs`, which
        :meth:`dpkt.ip6.IP6.__len__` falls back to in the same way.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    ext_hdrs = getattr(ipv6, 'all_extension_headers', None)
    if ext_hdrs:
        return list(ext_hdrs)
    return list(getattr(ipv6, 'extension_hdrs', {}).values())


def _vlan_tpids(wire: 'bytes | memoryview') -> 'list[int]':
    """Read the TPIDs of the VLAN tags `DPKT`_ steps over in an Ethernet II frame, off its octets.

    Args:
        wire: Octets of an Ethernet frame, from its destination address on.

    Returns:
        The frame's EtherType, then each tag's but the last's, for as long as
        each is one of the :data:`DPKT_VLAN_TAGS` and a whole tag follows it;
        empty for a frame whose EtherType field is an 802.3 length.

    Note:
        :class:`dpkt.ethernet.Ethernet` reads at most two tags at a time, and
        reads on only while the tag it read names 802.1Q. Where it then has no
        decoder for the EtherType, its constructor reads again from there, and
        starts its :attr:`~dpkt.ethernet.Ethernet.vlan_tags` afresh: so it keeps
        only the tags of its last read, one for 802.1Q then 802.1ad, two
        802.1ad, or three tags, and its re-serialisation is 4 octets short for
        each tag it dropped. Where it decodes the payload, the tags it stepped
        over are all those heading it, since none of the :data:`DPKT_VLAN_TAGS`
        has a decoder, so they are read off the octets instead.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    tpids = []  # type: list[int]
    offset = 12
    while len(wire) >= offset + 2 + VLAN_TAG_LEN:
        tpid = int.from_bytes(wire[offset:offset + 2], 'big')
        if tpid not in DPKT_VLAN_TAGS:
            break
        tpids.append(tpid)
        offset += VLAN_TAG_LEN
    return tpids


def _network_octets(packet: 'Packet', ip: 'IP | IP6') -> 'bytes':
    """Fetch the octets of a DPKT packet's network layer, from its first octet on.

    Args:
        packet: DPKT packet, i.e. the outermost layer.
        ip: Its network layer, as :func:`_network` finds it: ``packet`` itself,
            or the payload of its link layer.

    Returns:
        With a buffer attached by :func:`attach_buffer`, the record octets from
        the layer's offset to the end of the frame, so any link-layer trailer is
        still there; otherwise the layer alone, serialised from a copy (see
        :func:`packet2bytes`). Behind an Ethernet II header, the offset counts
        the VLAN tags off the octets, as :class:`dpkt.ethernet.Ethernet` keeps
        only some of a stack it reads in two goes (see :func:`_vlan_tpids`);
        behind any other link layer, it is what the layer's ``len()`` counts
        before its payload.

    Raises:
        ProtocolError: If the buffer does not carry the layer's own header where
            the link layer placed it. `DPKT`_ unpacks a header field by field and
            :meth:`~dpkt.dpkt.Packet.pack_hdr` packs those fields back without
            recomputing any of them, so the two agree octet for octet wherever
            the offset is right -- which makes this an exact check rather than a
            plausibility one. It is raised rather than worked around because a
            misplaced slice reaches the reassembler as a believable datagram and
            so is invisible in its output.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    buffer = getattr(packet, BUFFER_ATTR, None)  # type: Optional[bytes]
    if buffer is None:
        return packet2bytes(ip)
    if ip is packet:
        offset = 0
    elif isinstance(packet, dpkt.ethernet.Ethernet):
        offset = ETHERNET_HEADER_LEN + VLAN_TAG_LEN * len(_vlan_tpids(buffer))
    else:
        offset = len(packet) - len(ip)
    wire = buffer[offset:]
    if wire[:ip.__hdr_len__] != ip.pack_hdr():
        raise ProtocolError(
            f'{type(ip).__name__} header not found at offset {offset} of the '
            f'{len(buffer)}-octet record; the frame cannot be sliced without re-serialising it'
        )
    return wire


def _ethernet_accepted(packet: 'Ethernet') -> 'bool':
    """Test if the default engine reads past a DPKT Ethernet frame's link layer as `DPKT`_ did.

    Args:
        packet: DPKT Ethernet frame.

    Returns:
        :data:`False` if `DPKT`_ reached its payload past an MPLS label stack, a
        Cisco ISL header, or a VLAN tag whose TPID is neither of the
        :data:`~pcapkit.toolkit.pypcapfile.VLAN_TAGS`; else :data:`True`.

    Note:
        `DPKT`_ pops an MPLS label stack and guesses IPv4 or IPv6 from the
        nibble after it, unwraps an ISL header, and steps over the legacy QinQ
        tags ``0x9100`` and ``0x9200``, naming the IPv4 or IPv6 packet it finds
        ``ip`` or ``ip6`` as for an untagged frame. The default engine reads
        what follows any of them as raw octets (see :attr:`Link.__proto__
        <pcapkit.protocols.link.link.Link.__proto__>`), an ISL frame's 802.3
        length field included (:issue:`1638`). A tag's TPID is the EtherType
        before it: the frame's, then each tag's but the last's.

        `DPKT`_ records an ISL header as a tag, but unwraps it into the frame
        itself, so a VLAN tag of the frame inside replaces it; the captured
        octets attached by :func:`attach_buffer` still show it, by the
        :data:`ISL_ADDRESSES` and length field `DPKT`_ recognises it by. Nor
        does it keep every tag of a stack it reads in two goes, so the TPIDs
        are read off those octets too (see :func:`_vlan_tpids`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    if getattr(packet, 'mpls_labels', None):
        return False
    tags = list(getattr(packet, 'vlan_tags', None) or ())
    if any(isinstance(tag, dpkt.ethernet.VLANtagISL) for tag in tags):
        return False
    buffer = getattr(packet, BUFFER_ATTR, None)  # type: Optional[bytes]
    if buffer is None:
        tpids = [packet.type, *(tag.type for tag in tags)][:len(tags)]
    elif buffer[:5] in ISL_ADDRESSES and int.from_bytes(buffer[12:14], 'big') <= 1500:
        return False
    else:
        tpids = _vlan_tpids(buffer)
    return all(tpid in VLAN_TAGS for tpid in tpids)


def _network(packet: 'Packet') -> 'Optional[IP | IP6]':
    """Fetch the network layer of a DPKT packet.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The packet itself if it is an IPv4 or IPv6 packet, as `DPKT`_ reads every
        frame of a raw-IP link type (:issue:`1548`); otherwise the IPv4 or IPv6
        payload of its link layer, which `DPKT`_ names ``ip`` or ``ip6`` -- a
        bare IP packet names neither -- or :data:`None` if it has none, or the
        default engine dissects no payload of an Ethernet frame where `DPKT`_
        found one (see :func:`_ethernet_accepted`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    if isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return packet
    if isinstance(packet, dpkt.ethernet.Ethernet) and not _ethernet_accepted(packet):
        return None
    if hasattr(packet, 'ip'):
        return cast('IP', packet.ip)
    return getattr(packet, 'ip6', None)


def _network_depth(packet: 'Packet') -> 'int':
    """Count the layers of a DPKT packet the default engine dissects up to its network layer.

    Args:
        packet: DPKT packet, i.e. the outermost layer, whose network layer
            :func:`_network` found.

    Returns:
        The place of that layer in the frame, its first layer being ``1``, as
        the default engine counts towards
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`: ``1`` for the
        packet of a raw-IP link type, which is the network layer itself; else
        ``2``, and one more for each VLAN tag of an Ethernet frame, which the
        default engine dissects as a layer of its own.

    Note:
        The tags are read off the captured octets, as `DPKT`_ keeps only some
        of a stack it reads in two goes (see :func:`_vlan_tpids`). Each is
        802.1Q or 802.1ad, or :func:`_ethernet_accepted` refuses the frame.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    if isinstance(packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
        return 1
    tags = 0
    if isinstance(packet, dpkt.ethernet.Ethernet):
        buffer = getattr(packet, BUFFER_ATTR, None)  # type: Optional[bytes]
        if buffer is None:
            tags = len(getattr(packet, 'vlan_tags', None) or ())
        else:
            tags = len(_vlan_tpids(buffer))
    return 2 + tags


def _ipv4_header_accepted(header: 'bytes') -> 'bool':
    """Test if the default engine reads an IPv4 header as an IPv4 layer.

    Args:
        header: The header's captured octets, from its first 20 on to as many as
            its IHL counts, or to the end of the capture if that comes first.

    Returns:
        :data:`False` if the default engine's IPv4 parser rejects it -- its
        version is not 4, its options are ones the parser rejects, or its IHL
        runs past the captured octets (:issue:`1607`) -- as the default engine
        then dissects nothing past it; else :data:`True`.

    Note:
        A header of version 4 with no options is not parsed, as the parser
        checks nothing else of one; any other is asked of the parser itself, as
        the pypcapfile engine asks it (see
        :func:`pcapkit.toolkit.pypcapfile._default_accepts`).

    """
    return header[0] == 0x45 or _default_accepts('IPv4', bytes(header))


def _ipv4_accepted(ipv4: 'IP') -> 'bool':
    """Test if the default engine reads a DPKT IPv4 packet as an IPv4 layer.

    Args:
        ipv4: DPKT IPv4 packet.

    Returns:
        What :func:`_ipv4_header_accepted` says of its header. `DPKT`_ decodes
        what an IPv4 EtherType or tunnel carries as IPv4 whatever its version,
        and never checks its options. Its octets are the fields as `DPKT`_ read
        them and the options as captured, which is exact.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    return _ipv4_header_accepted(ipv4.pack_hdr() + bytes(ipv4.opts))


class _Segment(NamedTuple):
    """A TCP segment the default engine reads, keyed by the IP layer that carries it (see :func:`_tcp_carrier`)."""

    #: Source address of the IP layer.
    src: 'IPv4Address | IPv6Address'
    #: Destination address of the IP layer.
    dst: 'IPv4Address | IPv6Address'
    #: Source port.
    srcport: 'int'
    #: Destination port.
    dstport: 'int'
    #: Sequence number.
    seq: 'int'
    #: Acknowledgement number.
    ack: 'int'
    #: Reset (RST) flag.
    rst: 'bool'
    #: Synchronise (SYN) flag.
    syn: 'bool'
    #: Finish (FIN) flag.
    fin: 'bool'
    #: Captured header, as far as the Data Offset goes.
    header: 'bytes'
    #: Captured payload, as far as the IP packet carrying it goes.
    payload: 'bytes'


class _IPLayer(NamedTuple):
    """An IPv4 or IPv6 header the default engine dissects as a layer of a frame (see :func:`_ip_layer`)."""

    #: IP version of the header, ``4`` or ``6``.
    version: 'int'
    #: Captured octets from the header on, to the end of the frame or of the
    #: packets carrying it, whichever comes first.
    octets: 'bytes'
    #: Place of the layer in the frame, its first layer being ``1``, as the
    #: default engine counts towards
    #: :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`.
    depth: 'int'


class _Upper(NamedTuple):
    """The layer the default engine dissects behind an IP header and the headers it reads past."""

    #: Protocol number of the layer.
    protocol: 'int'
    #: Captured octets from its header on, to the end of the packet carrying it.
    octets: 'bytes'
    #: Place of the layer in the frame, as for :attr:`_IPLayer.depth`.
    depth: 'int'
    #: Whether an AH or IPv6 extension header in IPv4 comes before it, which the
    #: default engine dissects as a layer of its own (see :func:`_tcp_carrier`).
    behind: 'bool'


def _ip_layer(version: 'int', octets: 'bytes', depth: 'int') -> 'Optional[_IPLayer]':
    """Read an IP header as the default engine dissects it.

    Args:
        version: IP version to read the header as, ``4`` or ``6``.
        octets: Captured octets from the header on, to the end of the frame or
            of the packets carrying it.
        depth: Place of the header in the frame (see :attr:`_IPLayer.depth`).

    Returns:
        The layer, or :data:`None` if the default engine dissects none there:
        past :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers
        (:issue:`1610`), short of the fixed header, or an IPv4 header whose IHL
        is below 5 or which its parser rejects (see
        :func:`_ipv4_header_accepted`). `DPKT`_ decodes no header that short or
        with that IHL either, and neither it nor the default engine checks an
        IPv6 header's version.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    if depth > FRAME_LAYER_LIMIT:
        return None
    if version == 4:
        ihl = (octets[0] & 0x0F) * 4 if len(octets) >= IPV4_HEADER_LEN else 0
        if ihl < IPV4_HEADER_LEN or not _ipv4_header_accepted(octets[:ihl]):
            return None
    elif len(octets) < IPV6_HEADER_LEN:
        return None
    return _IPLayer(version, bytes(octets), depth)


def _link_network(linktype: 'Optional[int]', octets: 'bytes') -> 'Optional[_IPLayer]':
    """Find the IP layer the default engine dissects right after a frame's link layer, from its octets.

    Args:
        linktype: The frame's ``LINKTYPE_*`` number (see :func:`attach_linktype`),
            if known.
        octets: The frame's record octets.

    Returns:
        The layer (see :func:`_ip_layer`), or :data:`None` if there is none.
        Over Ethernet II, that is an IPv4 or IPv6 EtherType after the 14-octet
        header and every 802.1Q and 802.1ad tag behind it (the
        :data:`~pcapkit.toolkit.pypcapfile.VLAN_TAGS`), each tag a layer of its
        own; over BSD loopback (``NULL`` and ``LOOP``), an IPv4 or IPv6 address
        family (:data:`LOOPBACK_IP_VERSIONS`) in the byte order
        :func:`~pcapkit.protocols.link.loopback.family_byteorder` gives. An
        ``IPV4`` or ``IPV6`` frame is IP of that version, and a ``RAW`` one of
        the version its first octet gives. The default engine leaves every other
        link type, EtherType and family raw, and a frame cut short of its link
        header.

    """
    if linktype == Enum_LinkType.ETHERNET:
        if len(octets) < ETHERNET_HEADER_LEN:
            return None
        ethertype, start = int.from_bytes(octets[12:14], 'big'), ETHERNET_HEADER_LEN
        while ethertype in VLAN_TAGS:
            if len(octets) < start + VLAN_TAG_LEN:
                return None
            ethertype, start = int.from_bytes(octets[start + 2:start + 4], 'big'), start + VLAN_TAG_LEN
        version = ETHERTYPE_IP_VERSIONS.get(ethertype)
        depth = 2 + (start - ETHERNET_HEADER_LEN) // VLAN_TAG_LEN
    elif linktype in (Enum_LinkType.NULL, Enum_LinkType.LOOP):
        if len(octets) < LOOPBACK_HEADER_LEN:
            return None
        family, start, depth = octets[:LOOPBACK_HEADER_LEN], LOOPBACK_HEADER_LEN, 2
        version = LOOPBACK_IP_VERSIONS.get(int.from_bytes(family, family_byteorder(family, linktype)))
    elif linktype in (Enum_LinkType.IPV4, Enum_LinkType.IPV6, Enum_LinkType.RAW) and octets:
        version = {Enum_LinkType.IPV4: 4, Enum_LinkType.IPV6: 6}.get(linktype, octets[0] >> 4)
        start, depth = 0, 1
    else:
        return None
    if version not in (4, 6):
        return None
    return _ip_layer(version, octets[start:], depth)


def _network_layer(packet: 'Packet') -> 'Optional[_IPLayer]':
    """Fetch the network layer of a DPKT packet, as the default engine dissects it.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The IPv4 or IPv6 packet :func:`_network` finds, with the octets
        :func:`_network_octets` slices for it and its place in the frame as
        :func:`_network_depth` counts it; or, if `DPKT`_ left the frame's
        payload undecoded, the layer :func:`_link_network` reads off the record
        octets :func:`attach_buffer` attached. That is a frame behind a VLAN tag
        stack `DPKT`_ does not finish decoding in two passes (:issue:`1654`),
        an IPv6 packet whose extension headers it cannot decode, and a frame it
        cannot decode at all, which the engine keeps as raw octets with its link
        type attached by :func:`attach_linktype` (:issue:`1626`). Else
        :data:`None`.

    Note:
        A packet built by hand carries no record octets, so its network layer's
        octets are `DPKT`_'s re-serialisation of it (see :func:`packet2bytes`),
        and one that is no :class:`dpkt.ip.IP` or :class:`dpkt.ip6.IP6` has
        none.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    ip = _network(packet)
    if ip is not None:
        if not isinstance(ip, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None
        return _ip_layer(6 if isinstance(ip, dpkt.ip6.IP6) else 4, _network_octets(packet, ip),
                         _network_depth(packet))

    buffer = getattr(packet, BUFFER_ATTR, None)  # type: Optional[bytes]
    if buffer is None or not isinstance(getattr(packet, 'data', None), (bytes, bytearray)):
        return None
    if isinstance(packet, dpkt.ethernet.Ethernet):
        return _link_network(Enum_LinkType.ETHERNET, buffer)
    if isinstance(packet, dpkt.loopback.Loopback):  # an address family it has no decoder for
        return None
    return _link_network(getattr(packet, LINKTYPE_ATTR, None), buffer)


def _ipv4_upper(layer: '_IPLayer') -> 'Optional[_Upper]':
    """Step over an IPv4 header to the layer the default engine dissects behind it.

    Args:
        layer: IPv4 layer.

    Returns:
        The layer its protocol names, in the octets its Total Length leaves --
        a Total Length of ``0``, which TCP segmentation offload leaves, the rest
        of what carries it -- past the headers the default engine reads past,
        one layer each (see
        :func:`~pcapkit.toolkit.pypcapfile._walk_extension_headers`); or
        :data:`None` if it dissects none: in a later fragment, whose data is a
        slice of the datagram's payload (:rfc:`791#section-3.2`), or behind one
        of those headers it leaves undissected.

    """
    octets = layer.octets
    if int.from_bytes(octets[6:8], 'big') & 0x1FFF:  # a later fragment
        return None
    ihl, total = (octets[0] & 0x0F) * 4, int.from_bytes(octets[2:4], 'big')
    payload = octets[ihl:max(total, ihl)] if total else octets[ihl:]
    if octets[9] not in IPV4_EXTENSION_HEADERS:
        return _Upper(octets[9], payload, layer.depth + 1, False)
    walked = _walk_extension_headers(octets[9], payload)
    if walked is None:
        return None
    protocol, upper, hops = walked
    return _Upper(protocol, upper, layer.depth + hops + 1, True)


def _ipv6_chain(layer: '_IPLayer') -> 'tuple[bytes, Optional[int], Optional[_Upper]]':
    """Walk an IPv6 packet's extension headers as the default engine does.

    Args:
        layer: IPv6 layer.

    Returns:
        The packet's octets as far as its Payload Length goes -- for a zero one,
        the Jumbo Payload Length (:rfc:`2675`) of a Hop-by-Hop Options header
        right after the IPv6 header, and lacking one, no payload at all
        (:issue:`1651`) -- then where in them its first Fragment header starts,
        if the walk reaches one, and the layer behind the last header walked, or
        :data:`None` if the default engine dissects none.

        Each of the :data:`~pcapkit.toolkit.pypcapfile.IPV6_EXTENSION_HEADERS`
        is walked, Mobility, HIP and Shim6 included (:issue:`1626`), and is a
        layer of the frame: an AH is ``(Payload Length + 2) * 4`` octets long, a
        Fragment header 8, and any other ``(Hdr Ext Len + 1) * 8``. The walk
        ends with no layer behind past
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`
        headers (:issue:`1604`) or
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of the
        frame (:issue:`1610`), at a header cut short or overrunning the packet,
        and at a later fragment's Fragment header, behind which lies a slice of
        the Fragmentable Part (:rfc:`8200#section-4.5`).

    Note:
        Where a header's own parser rejects it, the default engine reads it
        with a generic one that takes the same length, so the lengths alone
        decide its walk. `DPKT`_'s walk does not stop at either bound, decodes
        none of 135, 139 and 140, runs a zero Payload Length to the end of the
        frame, and raises :exc:`AttributeError` at a Fragment header first in
        the chain with another header behind it (:issue:`1351`), which keeps the
        whole frame raw, so the walk is the default engine's own.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    octets = layer.octets
    extent = (int.from_bytes(octets[4:6], 'big')
              or jumbo_payload_length(octets[6], octets[IPV6_HEADER_LEN:]) or 0)
    data = octets[:IPV6_HEADER_LEN + extent]
    nxt, offset, count, fragment = octets[6], IPV6_HEADER_LEN, 0, None  # type: int, int, int, Optional[int]
    while nxt in IPV6_EXTENSION_HEADERS:
        if (count == EXTENSION_HEADER_LIMIT or layer.depth + count >= FRAME_LAYER_LIMIT
                or len(data) < offset + 8):
            return data, fragment, None
        if nxt == Enum_TransType.IPv6_Frag:
            if fragment is None:
                fragment = offset
            if int.from_bytes(data[offset + 2:offset + 4], 'big') >> 3:  # a later fragment
                return data, fragment, None
            length = 8
        elif nxt == Enum_TransType.AH:
            length = (data[offset + 1] + 2) * 4
        else:
            length = (data[offset + 1] + 1) * 8
        nxt, offset, count = data[offset], offset + length, count + 1
    if len(data) < offset:
        return data, fragment, None
    return data, fragment, _Upper(nxt, data[offset:], layer.depth + count + 1, False)


def _ip_layers(packet: 'Packet') -> 'Iterator[tuple[_IPLayer, Optional[_Upper]]]':
    """Walk the IP layers of a DPKT packet that the default engine dissects.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Yields:
        Each IP layer, outermost first, with the layer the default engine
        dissects behind it, if any (see :func:`_ipv4_upper` and
        :func:`_ipv6_chain`). The first is the network layer (see
        :func:`_network_layer`), and each next one the IPv4 or IPv6 packet the
        last carries in an IP-in-IP tunnel (the :data:`IP_TUNNELS`), as deep as
        they go.

    Note:
        Every layer is read off the octets, by the default engine's rules,
        rather than off what `DPKT`_ decoded of them, which differs from it in
        the ways :func:`_ipv6_chain` and :func:`_network_layer` give.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    layer = _network_layer(packet)
    while layer is not None:
        upper = _ipv4_upper(layer) if layer.version == 4 else _ipv6_chain(layer)[2]
        yield layer, upper
        if upper is None or upper.protocol not in IP_TUNNELS:
            return
        layer = _ip_layer(4 if upper.protocol == Enum_TransType.IPv4 else 6, upper.octets, upper.depth)


def _first_layer(packet: 'Packet', version: 'int') -> 'Optional[_IPLayer]':
    """Fetch the first IP layer of a version in a DPKT packet, as the default engine dissects it.

    Args:
        packet: DPKT packet, i.e. the outermost layer.
        version: IP version, ``4`` or ``6``.

    Returns:
        The first such layer :func:`_ip_layers` walks, or :data:`None`.

    Note:
        The default engine hands IP reassembly ``frame['IPv4']`` or
        ``frame['IPv6']``, the first such layer however deep
        (:func:`pcapkit.toolkit.pcap.ipv4_reassembly`), so IPv4 carried in IPv6
        counts, and IPv6 in IPv4 (:issue:`1615`, :issue:`1637`).

    """
    return next((layer for layer, _ in _ip_layers(packet) if layer.version == version), None)


def _tcp_carrier(packet: 'Packet') -> 'Optional[_Segment]':
    """Fetch the TCP segment of a DPKT packet, keyed by the IP layer that carries it.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The segment behind the innermost IP layer :func:`_ip_layers` walks, if
        the default engine reads one there, inside
        :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of the
        frame (:issue:`1609`); else :data:`None`. It has at least
        :data:`TCP_MIN_HEADER_LEN <pcapkit.toolkit.pypcapfile.TCP_MIN_HEADER_LEN>`
        octets, and a Data Offset counting no fewer; behind an AH or IPv6
        extension header in IPv4, also no more octets than were captured, and
        options its TCP parser accepts (see
        :func:`~pcapkit.toolkit.pypcapfile._default_accepts`).

    Note:
        Directly over IP, the default engine reads a TCP header its parser
        rejects out of the raw octets left behind
        (:func:`pcapkit.toolkit.pcap.tcp_segment`), as `DPKT`_ decodes one, and
        an IPv6 packet's extension headers do not come between, as it dissects
        them itself. Behind a header that is a layer of its own, it does not, so
        the parser's answer stands there, as for the pypcapfile engine. The TCP
        endpoints are the innermost IP layer's addresses, as for the default
        engine; the outer ones are the tunnel's (:issue:`1581`). Each flag is
        read from the flags octet alone, as the default engine reads it
        (:issue:`1618`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    walked = None
    for walked in _ip_layers(packet):
        pass
    if walked is None:
        return None
    layer, upper = walked
    if upper is None or upper.protocol != Enum_TransType.TCP or upper.depth > FRAME_LAYER_LIMIT:
        return None
    segment = upper.octets
    hdr_len = (segment[12] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
    if hdr_len < TCP_MIN_HEADER_LEN:
        return None
    if upper.behind and (hdr_len > len(segment) or (
            hdr_len > TCP_MIN_HEADER_LEN and not _default_accepts('TCP', segment[:hdr_len]))):
        return None
    src, dst = _addresses(layer)
    flags = segment[13]
    return _Segment(
        src=src,
        dst=dst,
        srcport=int.from_bytes(segment[0:2], 'big'),
        dstport=int.from_bytes(segment[2:4], 'big'),
        seq=int.from_bytes(segment[4:8], 'big'),
        ack=int.from_bytes(segment[8:12], 'big'),
        rst=bool(flags & 0x04),
        syn=bool(flags & 0x02),
        fin=bool(flags & 0x01),
        header=segment[:hdr_len],
        payload=segment[hdr_len:],
    )


def _addresses(layer: '_IPLayer') -> 'tuple[IPv4Address | IPv6Address, IPv4Address | IPv6Address]':
    """Read the source and destination addresses of an IP layer.

    Args:
        layer: IPv4 or IPv6 layer.

    Returns:
        The source address, then the destination.

    """
    octets = layer.octets
    if layer.version == 4:
        return ipaddress.ip_address(octets[12:16]), ipaddress.ip_address(octets[16:20])
    return ipaddress.ip_address(octets[8:24]), ipaddress.ip_address(octets[24:40])


def ipv6_hdr_len(ipv6: 'IP6') -> 'int':
    """Calculate length of headers before IPv6 Fragment header.

    Args:
        ipv6: DPKT IPv6 packet.

    Returns:
        Length of headers before IPv6 Fragment header
        :class:`dpkt.ip6.IP6FragmentHeader` (:rfc:`2460#section-4.5`).

    As specified in :rfc:`2460#section-4.1`, such a header may be a Hop-by-Hop Options
    header :class:`dpkt.ip6.IP6HopOptsHeader` (:rfc:`2460#section-4.3`), a Destination
    Options header :class:`dpkt.ip6.IP6DstOptsHeader` (:rfc:`2460#section-4.6`) or a
    Routing header :class:`dpkt.ip6.IP6RoutingHeader` (:rfc:`2460#section-4.4`). An
    Authentication header (:rfc:`4302`) reaches here as well, though, so the headers are
    walked in the order they were parsed rather than looked up by a fixed list of types.
    Walking them is also what counts a header type occurring twice twice, and what leaves
    out one that sits *after* the Fragment header rather than before it.

    """
    frag = ipv6.extension_hdrs.get(44)
    hdr_len = ipv6.__hdr_len__
    for ext_hdr in _ipv6_ext_hdrs(ipv6):
        if ext_hdr is frag:
            break
        hdr_len += ext_hdr.length
    return hdr_len


def packet2chain(packet: 'Packet') -> 'str':
    """Fetch DPKT packet protocol chain.

    Args:
        packet: DPKT packet.

    Returns:
        Colon (``:``) separated list of protocol chain. It ends at the first
        payload that is no layer, as in :func:`packet2dict`, e.g. VRRP's ``''``.

    """
    chain = [type(packet).__name__]
    payload = packet.data
    while hasattr(payload, '__hdr_fields__'):
        chain.append(type(payload).__name__)
        payload = payload.data
    return ':'.join(chain)


def packet2dict(packet: 'Packet', timestamp: 'float', *,
                data_link: 'Enum_LinkType') -> 'dict[str, Any]':
    """Convert DPKT packet into :obj:`dict`.

    Args:
        packet: DPKT packet.
        timestamp: Timestamp of packet.
        data_link: Data link type.

    Returns:
        Dict[str, Any]: A :obj:`dict` mapping of packet data. A layer's payload
        is mapped as a layer of its own only where it is one, i.e. has the
        header fields a :class:`dpkt.dpkt.Packet` has; any other is leaf data.
        `DPKT`_ leaves some undecoded payloads as a :obj:`str` rather than as
        :obj:`bytes`, e.g. ``''`` for VRRP's. A frame the engine keeps as raw
        data, as it keeps one `DPKT`_ cannot decode, has no header fields, so
        maps to an empty :obj:`dict`.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    def wrapper(packet: 'Packet') -> 'dict[str, Any]':
        dict_ = {}  # type: dict[str, Any]
        for field in getattr(packet, '__hdr_fields__', ()):
            dict_[field] = getattr(packet, field, None)
        payload = packet.data
        if hasattr(payload, '__hdr_fields__'):
            dict_[type(payload).__name__] = wrapper(payload)
        return dict_

    return {
        'timestamp': timestamp,
        'packet': packet2bytes(packet),
        data_link.name: wrapper(packet),
    }


def ipv4_reassembly(packet: 'Packet', timestamp: 'float', *,
                    count: 'int' = -1) -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet, which drives the reassembly
            timeout. `DPKT`_'s reader yields it beside the record's octets rather
            than on the packet, so it is passed in -- as :func:`tcp_traceflow`
            does. A caller holding only a frame can read it back with
            :func:`packet2timestamp`, which is where
            :class:`~pcapkit.foundation.engines.dpkt.DPKT` leaves it. Handed on
            as a :obj:`float`, as every engine's adapters do, though `DPKT`_ reads
            a nanosecond PCAP's as a :class:`~decimal.Decimal` (:issue:`1501`).
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv4 reassembly.

        * If the ``packet`` can be used for IPv4 reassembly. A packet can be reassembled
          if it contains an IPv4 layer the default engine dissects -- the first of the
          frame, as for the default engine, so one carried in IPv6 counts (see
          :func:`_first_layer`) -- and its **DF** flag is :data:`False`.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    Note:
        The header and payload are sliced out of the record octets
        :class:`~pcapkit.foundation.engines.dpkt.DPKT` attached to the frame, so
        they are the captured ones. A packet built by hand carries no such
        buffer, and its octets are then :mod:`dpkt`'s re-serialisation of it, in
        which a zeroed checksum or length comes back recomputed --
        :func:`attach_buffer` is what makes them the wire's again. The packet
        itself is left untouched either way.

        The header is the IHL's octets and the payload the rest, to the end of
        the frame or of the IPv6 packets carrying it, as the default engine
        hands them over; the reassembler bounds the payload by the Total Length
        itself. Neither is cut at the Total Length, which may be shorter than
        the header (:issue:`1616`).

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    ipv4 = _first_layer(packet, 4)
    if ipv4 is None:
        return None
    octets = ipv4.octets
    flags = int.from_bytes(octets[6:8], 'big')
    if flags & 0x4000:  # dismiss not fragmented packet
        return None
    src, dst = _addresses(ipv4)
    # internet header length, in octets, options included
    ihl = (octets[0] & 0x0F) * 4

    data = IP_Packet(
        bufid=(
            cast('IPv4Address', src),                           # source IP address
            cast('IPv4Address', dst),                           # destination IP address
            int.from_bytes(octets[4:6], 'big'),                 # identification
            Enum_TransType.get(octets[9]),                      # payload protocol type
        ),
        num=count,                                              # original packet range number
        fo=(flags & 0x1FFF) * 8,                                # fragment offset
        ihl=ihl,                                                # internet header length
        mf=bool(flags & 0x2000),                                # more fragment flag
        tl=int.from_bytes(octets[2:4], 'big'),                  # total length, header includes
        header=octets[:ihl],                                    # raw bytes type header
        payload=bytearray(octets[ihl:]),                        # raw bytearray type payload
        timestamp=float(timestamp),                             # capture timestamp
    )
    return data


def ipv6_reassembly(packet: 'Packet', timestamp: 'float', *,
                    count: 'int' = -1) -> 'IP_Packet[IPv6Address] | None':
    """Make data for IPv6 reassembly.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet, which drives the reassembly
            timeout; :func:`packet2timestamp` reads it back off a stored frame.
            Handed on as a :obj:`float`, as for :func:`ipv4_reassembly`.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv6 reassembly.

        * If the ``packet`` can be used for IPv6 reassembly. A packet can be reassembled
          if it contains an IPv6 layer the default engine dissects -- the first of the
          frame, as for the default engine, so one carried in IPv4 counts (see
          :func:`_first_layer`) -- and an IPv6 Fragment header (:rfc:`2460#section-4.5`)
          among the extension headers the default engine walks (see :func:`_ipv6_chain`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    Note:
        The header and payload are sliced out of the record octets
        :class:`~pcapkit.foundation.engines.dpkt.DPKT` attached to the frame, so
        they are the captured ones. A packet built by hand carries no such
        buffer, and its octets are then :mod:`dpkt`'s re-serialisation of it, in
        which a zeroed checksum or length comes back recomputed --
        :func:`attach_buffer` is what makes them the wire's again. The packet
        itself is left untouched either way.

        The header is the octets before the first Fragment header, and the
        payload those after it, as far as the Payload Length goes, or the Jumbo
        Payload Length (:rfc:`2675`) of a zero one, as the default engine cuts
        them.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    ipv6 = _first_layer(packet, 6)
    if ipv6 is None:
        return None
    octets, fragment, _ = _ipv6_chain(ipv6)
    if fragment is None:  # dismiss not fragmented packet
        return None
    src, dst = _addresses(ipv6)
    word = int.from_bytes(octets[fragment + 2:fragment + 4], 'big')
    # payload following the IPv6 Fragment header
    payload = octets[fragment + 8:]

    data = IP_Packet(
        bufid=(
            cast('IPv6Address', src),                            # source IP address
            cast('IPv6Address', dst),                            # destination IP address
            # NOTE: The reassembly key is the Fragment header's Identification
            # (:rfc:`8200#section-4.5`), not the IPv6 header's Flow Label. The
            # label is optional and routinely zero, so keying on it collapses
            # every datagram between one address pair into a single buffer and
            # interleaves their fragments; it would also disagree with
            # ``bufid[2]`` in every other engine, which feeds
            # :attr:`pcapkit.foundation.reassembly.data.ip.DatagramID.id`.
            int.from_bytes(octets[fragment + 4:fragment + 8], 'big'),  # identification
            Enum_TransType.get(octets[fragment]),                # next header field in IPv6 Fragment Header
        ),
        num=count,                                               # original packet range number
        # NOTE: The Fragment Offset is the top 13 bits of its word, in 8-octet
        # units (:rfc:`8200#section-4.5`). The reassembly machinery indexes the
        # datagram buffer with ``fo``, so the units have to become octets here,
        # exactly as :func:`pcapkit.toolkit.scapy.ipv6_reassembly` does.
        fo=(word >> 3) * 8,                                      # fragment offset
        ihl=fragment,                                            # header length, only headers before IPv6-Frag
        mf=bool(word & 0x1),                                     # more fragment flag
        tl=fragment + len(payload),                              # total length, header includes
        header=octets[:fragment],                                # raw bytes type header before IPv6-Frag
        payload=bytearray(payload),                              # raw bytearray type payload after IPv6-Frag
        timestamp=float(timestamp),                              # capture timestamp
    )
    return data


def tcp_reassembly(packet: 'Packet', timestamp: 'float', *,
                   count: 'int' = -1) -> 'TCP_Packet | None':
    """Make data for TCP reassembly.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet, which drives the reassembly
            timeout; :func:`packet2timestamp` reads it back off a stored frame.
            Handed on as a :obj:`float`, as for :func:`ipv4_reassembly`.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP reassembly. A packet can be reassembled
          if it contains a TCP segment the default engine reads, keyed by the IP packet
          that carries it -- in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Note:
        The header and payload are sliced out of the record octets
        :class:`~pcapkit.foundation.engines.dpkt.DPKT` attached to the frame, so
        they are the captured ones. A packet built by hand carries no such
        buffer, and its octets are then :mod:`dpkt`'s re-serialisation of it, in
        which a zeroed checksum or length comes back recomputed --
        :func:`attach_buffer` is what makes them the wire's again. The packet
        itself is left untouched either way.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    segment = _tcp_carrier(packet)
    if segment is not None:
        raw_len = len(segment.payload)                          # payload length, header excludes

        data = TCP_Packet(
            bufid=(
                segment.src,                                    # source IP address
                segment.srcport,                                # source port
                segment.dst,                                    # destination IP address
                segment.dstport,                                # destination port
            ),
            num=count,                                          # original packet range number
            ack=segment.ack,                                    # acknowledgement
            dsn=segment.seq,                                    # data sequence number
            rst=segment.rst,                                    # reset connection flag
            syn=segment.syn,                                    # synchronise flag
            fin=segment.fin,                                    # finish flag
            header=segment.header,                              # raw bytes type header
            payload=bytearray(segment.payload),                 # raw bytearray type payload
            first=segment.seq,                                  # first sequence number of payload
            last=segment.seq + raw_len - 1,                     # last sequence number of payload
            len=raw_len,                                        # payload length, header excludes
            timestamp=float(timestamp),                         # capture timestamp
        )
        return data
    return None


def tcp_traceflow(packet: 'Packet', timestamp: 'float', *,
                  data_link: 'Enum_LinkType', count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: DPKT packet.
        timestamp: Timestamp of the packet, handed on as a :obj:`float`, as for
            :func:`ipv4_reassembly`. The PCAP frame record is built from the
            exact timestamp attached by :func:`attach_timestamp`, if any; see
            :func:`packet2frame`.
        data_link: Data link layer protocol (from global header).
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains a TCP segment the default engine reads, keyed by the IP packet
          that carries it -- in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Note:
        The header and payload are sliced out of the record octets
        :class:`~pcapkit.foundation.engines.dpkt.DPKT` attached to the frame, so
        they are the captured ones. A packet built by hand carries no such
        buffer, and its octets are then :mod:`dpkt`'s re-serialisation of it, in
        which a zeroed checksum or length comes back recomputed --
        :func:`attach_buffer` is what makes them the wire's again. The packet
        itself is left untouched either way.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    segment = _tcp_carrier(packet)
    if segment is not None:
        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=data_link,                                         # data link type from global header
            index=count,                                                # frame number
            frame=packet2frame(packet, timestamp, data_link=data_link),  # extracted packet
            syn=segment.syn,                                            # TCP synchronise (SYN) flag
            fin=segment.fin,                                            # TCP finish (FIN) flag
            rst=segment.rst,                                            # TCP reset (RST) flag
            src=segment.src,                                            # source IP
            dst=segment.dst,                                            # destination IP
            srcport=segment.srcport,                                    # TCP source port
            dstport=segment.dstport,                                    # TCP destination port
            timestamp=float(timestamp),                                 # timestamp
            seq=segment.seq,                                            # TCP sequence number
            ack=segment.ack,                                            # TCP acknowledgement number
            header=segment.header,                                      # raw bytes type header
            payload=bytearray(segment.payload),                         # raw bytearray type payload
        )
        return data
    return None
