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
from typing import TYPE_CHECKING, cast

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.data import FrameRecord
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.data.misc.pcap.frame import FrameInfo as Data_FrameInfo
from pcapkit.toolkit.pypcapfile import (IPV4_EXTENSION_HEADERS, TCP_MIN_HEADER_LEN, VLAN_TAG_LEN,
                                        VLAN_TAGS, _default_accepts, _past_extension_headers,
                                        _walk_extension_headers)
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from decimal import Decimal
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from dpkt.dpkt import Packet
    from dpkt.ethernet import Ethernet
    from dpkt.ip import IP
    from dpkt.ip6 import IP6, IP6FragmentHeader
    from dpkt.tcp import TCP

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType

__all__ = [
    'RecordTimestamp', 'Timestamp', 'DecimalTimestamp', 'ipv6_hdr_len', 'attach_timestamp', 'packet2timestamp', 'attach_buffer', 'packet2bytes',
    'packet2frame', 'packet2chain', 'packet2dict',
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

#: IP protocol numbers of the IP-in-IP tunnels the default engine dissects
#: (see :attr:`Internet.__proto__
#: <pcapkit.protocols.internet.internet.Internet.__proto__>`), over IPv4 and
#: IPv6 alike: IPv4 (protocol 4, :rfc:`2003`) and IPv6 (protocol 41,
#: :rfc:`2473` and :rfc:`4213`). `DPKT`_ also decodes an IPv4 packet's
#: protocol 0 as IPv4, its ``IP_PROTO_IP``, where the default engine reads an
#: IPv6 Hop-by-Hop Options header, so neither :func:`_tcp_carrier` nor
#: :func:`_first_ipv6` enters it.
#:
#: .. _DPKT: https://dpkt.readthedocs.io
IP_TUNNELS = frozenset((int(Enum_TransType.IPv4), int(Enum_TransType.IPv6)))

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


def _wire_hdr_len(packet: 'Packet', payload: 'Packet', wire: 'Optional[bytes | memoryview]' = None) -> 'int':
    """Calculate the octets a layer occupies before its payload begins.

    Args:
        packet: DPKT packet, i.e. one layer of a frame.
        payload: That layer's payload, i.e. :attr:`packet.data <dpkt.dpkt.Packet.data>`.
        wire: The captured octets of ``packet``, from its first on, if any.

    Returns:
        The advance :meth:`~dpkt.dpkt.Packet.unpack` itself made to reach the
        payload.

        For IPv6 that is the fixed header plus each extension header's
        :attr:`~dpkt.ip6.IP6ExtensionHeader.length`, which is what
        :meth:`dpkt.ip6.IP6.unpack` walks the buffer by. It cannot be taken from
        ``len()``: :meth:`dpkt.ip6.IP6.__len__` sums ``len()`` of the extension
        headers instead, and that is 12 octets plus the *rest of the frame* for
        an Authentication header -- :class:`dpkt.ip6.IP6AHHeader` trims only into
        :attr:`~dpkt.ip6.IP6AHHeader.auth_data` and leaves
        :attr:`~dpkt.dpkt.Packet.data` running to the end of the buffer -- and 8
        octets short of the wire for a Routing header whose Hdr Ext Len is odd
        (:class:`dpkt.ip6.IP6RoutingHeader` keeps whole addresses only).

        Every other layer's ``len()`` does bound its payload, so the difference
        of the two is used there. For IPv4 that difference is the Internet
        Header Length, options included. For an Ethernet II frame whose
        ``wire`` is given, 4 octets are added for each VLAN tag
        :class:`dpkt.ethernet.Ethernet` stepped over but dropped from its
        :attr:`~dpkt.ethernet.Ethernet.vlan_tags`, which ``len()`` counts (see
        :func:`_vlan_tpids`).

    """
    import dpkt  # isort:skip

    if hasattr(packet, 'extension_hdrs'):
        return packet.__hdr_len__ + sum(
            ext_hdr.length for ext_hdr in _ipv6_ext_hdrs(cast('IP6', packet))
        )
    hdr_len = len(packet) - len(payload)
    if wire is not None and isinstance(packet, dpkt.ethernet.Ethernet) and int.from_bytes(wire[12:14], 'big') > 1500:
        dropped = len(_vlan_tpids(wire)) - len(getattr(packet, 'vlan_tags', None) or ())
        hdr_len += VLAN_TAG_LEN * dropped
    return hdr_len


def _layer2bytes(packet: 'Packet', layer: 'Packet') -> 'tuple[bytes, bool]':
    """Fetch the octets of a layer of a DPKT packet, from its first octet on.

    Args:
        packet: DPKT packet, i.e. the outermost layer.
        layer: A layer nested within ``packet``.

    Returns:
        The octets, and whether they are the captured ones. With a buffer
        attached by :func:`attach_buffer` they are the record octets from the
        layer's offset to the end of the frame, so any link-layer trailer is
        still there for the caller to trim; otherwise they are the layer alone,
        serialised from a copy (see :func:`packet2bytes`).

    Raises:
        ProtocolError: If the buffer does not carry the layer's own header where
            the walk above placed it. `DPKT`_ unpacks a header field by field and
            :meth:`~dpkt.dpkt.Packet.pack_hdr` packs those fields back without
            recomputing any of them, so the two agree octet for octet wherever
            the offset is right -- which makes this an exact check rather than a
            plausibility one. It is raised rather than worked around because a
            misplaced slice reaches the reassembler as a believable datagram and
            so is invisible in its output.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    buffer = getattr(packet, BUFFER_ATTR, None)
    if buffer is not None:
        offset = 0
        current = packet
        view = memoryview(cast('bytes', buffer))
        while current is not layer:
            payload = getattr(current, 'data', None)
            if payload is None or isinstance(payload, (bytes, bytearray)):
                break
            offset += _wire_hdr_len(current, payload, view[offset:])
            current = payload
        else:
            wire = cast('bytes', buffer)[offset:]
            hdr_len = getattr(layer, '__hdr_len__', 0)
            if hdr_len and wire[:hdr_len] != layer.pack_hdr():
                raise ProtocolError(
                    f'{type(layer).__name__} header not found at offset {offset} of the '
                    f'{len(cast("bytes", buffer))}-octet record; the frame cannot be '
                    'sliced without re-serialising it'
                )
            return wire, True
    return packet2bytes(layer), False


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


def _ipv4_accepted(ipv4: 'IP') -> 'bool':
    """Test if the default engine reads a DPKT IPv4 packet as an IPv4 layer.

    Args:
        ipv4: DPKT IPv4 packet.

    Returns:
        :data:`False` if the default engine's IPv4 parser rejects its header --
        its version is not 4, its options are ones the parser rejects, or its
        IHL runs past the captured octets (:issue:`1607`) -- as the default
        engine then dissects nothing past it; else :data:`True`.

    Note:
        `DPKT`_ decodes what an IPv4 EtherType or tunnel carries as IPv4
        whatever its version, and never checks its options, so the header is
        asked of the parser itself, as the pypcapfile engine asks it (see
        :func:`pcapkit.toolkit.pypcapfile._default_accepts`). Its octets are the
        fields as `DPKT`_ read them and the options as captured, which is
        exact. A header of version 4 with no options is not parsed: `DPKT`_
        decodes none shorter than 20 octets or with an IHL below 5, and the
        parser checks nothing else of one.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    if ipv4.v == 4 and ipv4.hl == 5:
        return True
    return _default_accepts('IPv4', ipv4.pack_hdr() + bytes(ipv4.opts))


def _past_ipv4_extension_headers(packet: 'Packet', ipv4: 'IP') -> 'Optional[tuple[int, bytes]]':
    """Step over the headers at the head of a DPKT IPv4 packet's payload that the default engine reads past.

    Args:
        packet: DPKT packet ``ipv4`` is a layer of, whose octets
            :func:`_layer2bytes` slices.
        ipv4: DPKT IPv4 packet, whose protocol is one of the
            :data:`~pcapkit.toolkit.pypcapfile.IPV4_EXTENSION_HEADERS`.

    Returns:
        The protocol number after the last of those headers and the octets from
        its header on, as far as the Total Length goes -- a Total Length of
        ``0``, which TCP segmentation offload leaves, runs to the end of the
        frame -- or :data:`None` if the default engine reads no upper-layer
        header there: ``ipv4`` is a later fragment, whose data is a slice of the
        datagram's payload (:rfc:`791#section-3.2`), or it leaves one of the
        headers undissected, which
        :func:`~pcapkit.toolkit.pypcapfile._past_extension_headers` decides by
        the default engine's own rules, up to
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`
        headers in a row (:issue:`1604`).

    Note:
        The default engine dispatches an IPv4 packet's protocol through the
        registry IPv6 uses, so it reads an AH or IPv6 extension header there
        and what its Next Header names. `DPKT`_ decodes protocol 0 as IPv4 and
        an AH as :class:`dpkt.ah.AH`, and keeps the rest as octets, so the
        octets are read instead (:issue:`1606`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    if ipv4.offset:
        return None
    wire, _ = _layer2bytes(packet, ipv4)
    ihl = ipv4.hl * 4
    return _past_extension_headers(ipv4.p, wire[ihl:max(ipv4.len, ihl)] if ipv4.len else wire[ihl:])


def _decode_tcp(segment: 'bytes') -> 'Optional[TCP]':
    """Decode a TCP segment the default engine reads behind an AH or IPv6 extension header in IPv4.

    Args:
        segment: Raw octets from the TCP header on, as far as the IPv4 packet
            carrying it goes (see :func:`_past_ipv4_extension_headers`).

    Returns:
        The segment, with ``segment`` attached by :func:`attach_buffer` so that
        its header is the captured one; or :data:`None` if the default engine
        reads no TCP there: fewer than :data:`TCP_MIN_HEADER_LEN
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
    import dpkt  # isort:skip

    hdr_len = (segment[12] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
    if hdr_len < TCP_MIN_HEADER_LEN or hdr_len > len(segment):
        return None
    if hdr_len > TCP_MIN_HEADER_LEN and not _default_accepts('TCP', segment[:hdr_len]):
        return None
    tcp = dpkt.tcp.TCP(segment)
    attach_buffer(tcp, segment)
    return tcp


def _decode_ip(protocol: 'int', data: 'bytes') -> 'Optional[IP | IP6]':
    """Decode an IP packet the default engine reads behind an AH or IPv6 extension header in IPv4.

    Args:
        protocol: The IP-in-IP protocol number, one of the :data:`IP_TUNNELS`.
        data: Raw octets from the IP header on, as far as the IPv4 packet
            carrying it goes (see :func:`_past_ipv4_extension_headers`).

    Returns:
        The packet as `DPKT`_ decodes one in a tunnel, with ``data`` attached by
        :func:`attach_buffer`, so that :func:`_layer2bytes` slices its layers
        out of the captured octets; or :data:`None` if decoding it raises
        anything at all, as :class:`~pcapkit.foundation.engines.dpkt.DPKT` then
        keeps a frame raw. `DPKT`_ raises more than its own
        :exc:`~dpkt.dpkt.UnpackError`: dpkt 1.9.8 reads ``frag_off`` from
        whatever header follows an IPv6 Fragment header, so one followed by
        another extension header raises :exc:`AttributeError` (:issue:`1351`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    klass = dpkt.ip.IP if protocol == Enum_TransType.IPv4 else dpkt.ip6.IP6
    try:
        ip = klass(data)
    except Exception:  # as the DPKT engine does, for a whole frame
        return None
    attach_buffer(ip, data)
    return ip


def _tcp_carrier(packet: 'Packet') -> 'tuple[Optional[IP | IP6], Optional[TCP]]':
    """Fetch the IP layer of a DPKT packet that carries its TCP segment, and the segment.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The innermost IPv4 or IPv6 packet of the network layer (see
        :func:`_network`) and of the IP-in-IP tunnels it carries, and its
        :class:`dpkt.tcp.TCP` payload, if it has one; else :data:`None` for the
        latter, and for both with no network layer, or if the default engine
        rejects the header of an IPv4 packet on the way (see
        :func:`_ipv4_accepted`). A tunnel is a packet whose protocol, or for
        IPv6 the next header after its extension headers, is one of the
        :data:`IP_TUNNELS`. An IPv4 packet whose protocol names an AH or IPv6
        extension header carries what the default engine reads past them (see
        :func:`_past_ipv4_extension_headers`), a tunnel or a TCP segment, which
        are decoded from the captured octets (see :func:`_decode_ip` and
        :func:`_decode_tcp`).

    Note:
        `DPKT`_ decodes an IPv4 or IPv6 packet inside another (:rfc:`2003`,
        :rfc:`2473`, :rfc:`4213`) as its ``data``. The TCP endpoints are the
        innermost packet's addresses, as for the default engine
        (:func:`pcapkit.toolkit.pcap.tcp_segment`); the outer ones are the
        tunnel's (:issue:`1581`). A segment found behind an extension header is
        no layer of ``packet``, so it carries its own octets, which
        :func:`_layer2bytes` then hands back (:issue:`1606`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    ip = _network(packet)
    if ip is None:
        return None, None
    root = packet   # the packet ``ip`` is a layer of
    while True:
        if isinstance(ip, dpkt.ip.IP):
            if not _ipv4_accepted(ip):
                return None, None
            if ip.p in IPV4_EXTENSION_HEADERS:
                upper = _past_ipv4_extension_headers(root, ip)
                if upper is not None and upper[0] == Enum_TransType.TCP:
                    return ip, _decode_tcp(upper[1])
                if upper is None or upper[0] not in IP_TUNNELS or (inner := _decode_ip(*upper)) is None:
                    return ip, None
                root = ip = inner
                continue
        if getattr(ip, 'p', None) not in IP_TUNNELS or not isinstance(ip.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            break
        ip = ip.data

    tcp = getattr(ip, 'tcp', None)  # type: Optional[TCP]
    if tcp is None and type(getattr(ip, 'data', None)).__name__ == 'TCP':
        tcp = cast('TCP', ip.data)
    if tcp is not None and root is not packet:
        attach_buffer(tcp, _layer2bytes(root, tcp)[0])
    return ip, tcp


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
        :obj:`bytes`, e.g. ``''`` for VRRP's.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    def wrapper(packet: 'Packet') -> 'dict[str, Any]':
        dict_ = {}  # type: dict[str, Any]
        for field in packet.__hdr_fields__:
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


def _first_ipv4(packet: 'Packet') -> 'tuple[Optional[IP], Optional[int]]':
    """Fetch the first IPv4 layer of a DPKT packet, as the default engine dissects it.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The network layer (see :func:`_network`) if it is IPv4, else the first
        IPv4 packet its IPv6 packet carries (:rfc:`2473`) -- directly, behind
        extension headers, or inside more IPv6. Beside it, :data:`None` for the
        former, and for the latter how many of its octets, from its first on,
        lie inside the Payload Length of every IPv6 packet carrying it. Both are
        :data:`None` if there is no such IPv4 packet, or the default engine
        dissects nothing past an IPv6 packet on the way: a later fragment
        (:rfc:`8200#section-4.5`), one with more than
        :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT`
        extension headers (:issue:`1604`), or one whose Payload Length is zero
        with no Jumbo Payload option to stand in for it (:rfc:`2675`).

    Note:
        The default engine takes ``frame['IPv4']``, the first IPv4 layer however
        deep (:func:`pcapkit.toolkit.pcap.ipv4_reassembly`); TCP is keyed by the
        innermost instead (see :func:`_tcp_carrier`). It hands that layer only
        the octets inside each Payload Length above it, so they end there, short
        of any trailer (:issue:`1615`). `DPKT`_ decodes the IPv4 packet in all
        three cases above -- a later fragment unless its Fragment header comes
        first, any number of extension headers, and a zero Payload Length as the
        rest of the frame -- so each is checked here.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    from pcapkit.protocols.internet.internet import EXTENSION_HEADER_LIMIT  # isort:skip
    from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length  # isort:skip

    ip = _network(packet)
    extent = None  # type: Optional[int] # octets of ``ip`` the packets above hold
    while isinstance(ip, dpkt.ip6.IP6):
        ext_hdrs = _ipv6_ext_hdrs(ip)
        if len(ext_hdrs) > EXTENSION_HEADER_LIMIT or any(
            isinstance(ext_hdr, dpkt.ip6.IP6FragmentHeader) and ext_hdr.frag_off for ext_hdr in ext_hdrs
        ):
            return None, None
        if getattr(ip, 'p', None) not in IP_TUNNELS or not isinstance(ip.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            return None, None

        plen = ip.plen
        if not plen:
            plen = jumbo_payload_length(ip.nxt, _layer2bytes(packet, ip)[0][ip.__hdr_len__:])
            if plen is None:
                return None, None
        end = ip.__hdr_len__ + plen
        if extent is not None:
            end = min(end, extent)
        extent = max(end - _wire_hdr_len(ip, ip.data), 0)
        ip = ip.data

    if not isinstance(ip, dpkt.ip.IP):
        return None, None
    return ip, extent


def _first_ipv6(packet: 'Packet') -> 'tuple[Optional[IP6], Optional[tuple[bytes, bool]], int]':
    """Fetch the first IPv6 layer of a DPKT packet, as the default engine dissects it.

    Args:
        packet: DPKT packet, i.e. the outermost layer.

    Returns:
        The network layer (see :func:`_network`) if it is IPv6, else the first
        IPv6 packet its IPv4 packet carries (:rfc:`4213`) -- directly, behind
        the headers the default engine reads past (see
        :func:`~pcapkit.toolkit.pypcapfile._past_extension_headers`), or inside
        more IPv4 (:rfc:`2003`). Beside it, :data:`None` for the former, whose
        octets are those :func:`_layer2bytes` slices, and for the latter its
        octets from its first on, as far as the Total Length of every IPv4
        packet carrying it goes, and whether they are the captured ones; then
        its place in the frame (see :func:`_network_depth`), one more for each
        IPv4 packet and each of those headers before it. Both are :data:`None`,
        and the place ``0``, if there is no such packet, or the default engine
        dissects nothing past an IPv4 packet on the way: one whose header it
        rejects (see :func:`_ipv4_accepted`), a later fragment
        (:rfc:`791#section-3.2`), or one carrying any other protocol, such as
        the ICMP error that quotes an IPv6 packet. So too if the IPv6 packet is
        past :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT`, which the
        default engine keeps raw (:issue:`1610`).

    Note:
        The default engine takes ``frame['IPv6']``, the first IPv6 layer however
        deep (:func:`pcapkit.toolkit.pcap.ipv6_reassembly`), and an IPv4 packet
        hands its payload the octets its Total Length leaves -- a Total Length
        of ``0``, which TCP segmentation offload leaves, the rest of what
        carries it -- so they are cut here as it cuts them (:issue:`1637`).
        `DPKT`_ decodes the IPv6 packet an IPv4 packet carries directly, but
        reads protocol 0 as IPv4 and keeps the IPv6 extension headers as octets,
        so one behind an AH or extension header is decoded from the octets
        instead (see :func:`_decode_ip`), as in :func:`_tcp_carrier`.

    .. _DPKT: https://dpkt.readthedocs.io

    """
    import dpkt  # isort:skip

    from pcapkit.protocols.protocol import FRAME_LAYER_LIMIT  # isort:skip

    ip = _network(packet)
    if ip is None:
        return None, None, 0
    octets = None  # type: Optional[tuple[bytes, bool]] # of ``ip``, once sliced
    depth = _network_depth(packet)  # of ``ip``
    while isinstance(ip, dpkt.ip.IP) and depth <= FRAME_LAYER_LIMIT:
        if ip.p not in IP_TUNNELS and ip.p not in IPV4_EXTENSION_HEADERS:
            return None, None, 0
        if not _ipv4_accepted(ip) or ip.offset:
            return None, None, 0
        wire, captured = octets or _layer2bytes(packet, ip)
        ihl = ip.hl * 4
        payload = wire[ihl:max(ip.len, ihl)] if ip.len else wire[ihl:]
        if ip.p in IPV4_EXTENSION_HEADERS:
            walked = _walk_extension_headers(ip.p, payload)
            if walked is None or walked[0] not in IP_TUNNELS:
                return None, None, 0
            proto, upper, hops = walked
            if (inner := _decode_ip(proto, upper)) is None:
                return None, None, 0
            ip, octets, depth = inner, (upper, captured), depth + 1 + hops
        elif isinstance(ip.data, (dpkt.ip.IP, dpkt.ip6.IP6)):
            ip, octets, depth = ip.data, (payload, captured), depth + 1
        else:
            return None, None, 0
    if not hasattr(ip, 'extension_hdrs') or depth > FRAME_LAYER_LIMIT:
        return None, None, 0
    return cast('IP6', ip), octets, depth


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
          if it contains IPv4 layer (:class:`dpkt.ip.IP`) -- the first of the frame, as
          for the default engine, so one carried in IPv6 counts (see
          :func:`_first_ipv4`) -- whose header the default engine accepts (see
          :func:`_ipv4_accepted`), and the **DF** (:attr:`dpkt.ip.IP.df`) flag is
          :data:`False`.
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
    ipv4, extent = _first_ipv4(packet)
    if ipv4 is not None and _ipv4_accepted(ipv4):
        if ipv4.df:     # dismiss not fragmented packet
            return None
        # internet header length, in octets -- ``IP.hl`` counts 32-bit words and
        # covers any IP options, whereas ``IP.__hdr_len__`` is the fixed 20-octet
        # struct size and would leave option octets at the head of the payload
        ihl = ipv4.hl * 4
        wire, _ = _layer2bytes(packet, ipv4)
        if extent is not None:
            wire = wire[:extent]
            # a Jumbo Payload Length may leave less than DPKT decoded from the
            # rest of the frame, and the default engine then dissects no IPv4
            if len(wire) < ihl:
                return None

        data = IP_Packet(
            bufid=(
                cast('IPv4Address',
                     ipaddress.ip_address(ipv4.src)),           # source IP address
                cast('IPv4Address',
                     ipaddress.ip_address(ipv4.dst)),           # destination IP address
                ipv4.id,                                        # identification
                Enum_TransType.get(ipv4.p),                     # payload protocol type
            ),
            num=count,                                          # original packet range number
            fo=ipv4.offset * 8,                                 # fragment offset
            ihl=ihl,                                            # internet header length
            mf=bool(ipv4.mf),                                   # more fragment flag
            tl=ipv4.len,                                        # total length, header includes
            header=wire[:ihl],                                  # raw bytes type header
            payload=bytearray(wire[ihl:]),                      # raw bytearray type payload
            timestamp=float(timestamp),                         # capture timestamp
        )
        return data
    return None


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
          if it contains IPv6 layer (:class:`dpkt.ip6.IP6`) -- the first of the frame, as
          for the default engine, so one carried in IPv4 counts (see :func:`_first_ipv6`)
          -- and IPv6 Fragment header (:rfc:`2460#section-4.5`, i.e.,
          :class:`dpkt.ip6.IP6FragmentHeader`) inside its Payload Length, and among its first
          :data:`~pcapkit.protocols.internet.internet.EXTENSION_HEADER_LIMIT` extension
          headers, the most the default engine walks (:issue:`1604`), and inside the first
          :data:`~pcapkit.protocols.protocol.FRAME_LAYER_LIMIT` layers of the frame, past
          which it dissects nothing (:issue:`1610`).
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

        The captured octets end at the Payload Length, as the default engine
        cuts them, or at the Jumbo Payload Length (:rfc:`2675`) of a zero one.
        A zero Payload Length with no Jumbo Payload option leaves the default
        engine no extension header to read, and so no input; `DPKT`_ reads the
        rest of the frame instead.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    .. _DPKT: https://dpkt.readthedocs.io

    """
    from pcapkit.protocols.internet.internet import EXTENSION_HEADER_LIMIT  # isort:skip
    from pcapkit.protocols.protocol import FRAME_LAYER_LIMIT  # isort:skip
    from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length  # isort:skip

    ipv6, octets, depth = _first_ipv6(packet)
    if ipv6 is not None:
        ipv6_frag = ipv6.extension_hdrs.get(44)  # type: Optional[IP6FragmentHeader]
        if ipv6_frag is None:       # dismiss not fragmented packet
            return None
        # the default engine walks no more extension headers than either bound
        # leaves, each header one layer of the frame past the IPv6 header's
        bound = min(EXTENSION_HEADER_LIMIT, FRAME_LAYER_LIMIT - depth)
        if not any(ext_hdr is ipv6_frag for ext_hdr in _ipv6_ext_hdrs(ipv6)[:bound]):
            return None
        hdr_len = ipv6_hdr_len(ipv6)
        wire, captured = octets or _layer2bytes(packet, ipv6)
        if captured:
            plen = ipv6.plen or jumbo_payload_length(ipv6.nxt, wire[ipv6.__hdr_len__:])
            if not plen:
                return None
            wire = wire[:ipv6.__hdr_len__ + plen]
            if len(wire) < hdr_len + ipv6_frag.__hdr_len__:     # Fragment header cut short
                return None
        # payload following the IPv6 Fragment header
        payload = wire[hdr_len + ipv6_frag.__hdr_len__:]

        data = IP_Packet(
            bufid=(
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.src)),            # source IP address
                cast('IPv6Address',
                     ipaddress.ip_address(ipv6.dst)),            # destination IP address
                # NOTE: The reassembly key is the Fragment header's Identification
                # (:rfc:`8200#section-4.5`), not the IPv6 header's Flow Label. The
                # label is optional and routinely zero, so keying on it collapses
                # every datagram between one address pair into a single buffer and
                # interleaves their fragments; it would also disagree with
                # ``bufid[2]`` in every other engine, which feeds
                # :attr:`pcapkit.foundation.reassembly.data.ip.DatagramID.id`.
                ipv6_frag.id,                                    # identification
                Enum_TransType.get(ipv6_frag.nxt),               # next header field in IPv6 Fragment Header
            ),
            num=count,                                           # original packet range number
            # NOTE: ``IP6FragmentHeader.frag_off`` is a ``__bit_fields__`` property
            # over the 13-bit on-wire Fragment Offset, i.e. already shifted out of
            # the flags word, so it counts 8-octet units (:rfc:`8200#section-4.5`).
            # The reassembly machinery indexes the datagram buffer with ``fo``, so
            # the units have to become octets here, exactly as
            # :func:`pcapkit.toolkit.scapy.ipv6_reassembly` does.
            fo=ipv6_frag.frag_off * 8,                           # fragment offset
            ihl=hdr_len,                                         # header length, only headers before IPv6-Frag
            mf=bool(ipv6_frag.m_flag),                           # more fragment flag
            tl=hdr_len + len(payload),                           # total length, header includes
            header=wire[:hdr_len],                               # raw bytes type header before IPv6-Frag
            payload=bytearray(payload),                          # raw bytearray type payload after IPv6-Frag
            timestamp=float(timestamp),                          # capture timestamp
        )
        return data
    return None


def _tcp_flags(tcp: 'TCP') -> 'tuple[bool, bool, bool]':
    """Read the RST, SYN and FIN flags of a DPKT TCP segment.

    Args:
        tcp: DPKT TCP packet.

    Returns:
        Whether RST, SYN and FIN are set, in that order.

    Note:
        Each flag is masked out of :attr:`dpkt.tcp.TCP.flags` by its ``TH_*``
        value, so it is read from the flags octet alone, as the default engine
        reads it. `DPKT`_ 1.9.8 makes that field nine bits wide, its top bit
        the NS bit (:rfc:`3540`): read by its position among the field's binary
        digits, every flag was one bit low with NS set, a SYN reading as a FIN
        (:issue:`1618`).

    .. _DPKT: https://dpkt.readthedocs.io

    """
    from dpkt.tcp import TH_FIN, TH_RST, TH_SYN  # isort:skip

    flags = tcp.flags
    return bool(flags & TH_RST), bool(flags & TH_SYN), bool(flags & TH_FIN)


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
          if it contains TCP layer (:class:`dpkt.tcp.TCP`), keyed by the IP packet that
          carries it -- in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`)
          -- and behind no IPv4 header the default engine rejects.
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
    ip, tcp = _tcp_carrier(packet)
    if ip is not None and tcp is not None:
        rst, syn, fin = _tcp_flags(tcp)
        wire, _ = _layer2bytes(packet, tcp)
        raw_len = len(tcp.data)                                 # payload length, header excludes

        data = TCP_Packet(
            bufid=(
                ipaddress.ip_address(ip.src),                   # source IP address
                tcp.sport,                                      # source port
                ipaddress.ip_address(ip.dst),                   # destination IP address
                tcp.dport,                                      # destination port
            ),
            num=count,                                          # original packet range number
            ack=tcp.ack,                                        # acknowledgement
            dsn=tcp.seq,                                        # data sequence number
            rst=rst,                                            # reset connection flag
            syn=syn,                                            # synchronise flag
            fin=fin,                                            # finish flag
            header=wire[:tcp.off * 4],                          # raw bytes type header
            payload=bytearray(bytes(tcp.data)),                 # raw bytearray type payload
            first=tcp.seq,                                      # first sequence number of payload
            last=tcp.seq + raw_len - 1,                         # last sequence number of payload
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
          if it contains TCP layer (:class:`dpkt.tcp.TCP`), keyed by the IP packet that
          carries it -- in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`)
          -- and behind no IPv4 header the default engine rejects.
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
    ip, tcp = _tcp_carrier(packet)
    if ip is not None and tcp is not None:
        rst, syn, fin = _tcp_flags(tcp)
        wire, _ = _layer2bytes(packet, tcp)

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=data_link,                                         # data link type from global header
            index=count,                                                # frame number
            frame=packet2frame(packet, timestamp, data_link=data_link),  # extracted packet
            syn=syn,                                                    # TCP synchronise (SYN) flag
            fin=fin,                                                    # TCP finish (FIN) flag
            rst=rst,                                                    # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                           # source IP
            dst=ipaddress.ip_address(ip.dst),                           # destination IP
            srcport=tcp.sport,                                          # TCP source port
            dstport=tcp.dport,                                          # TCP destination port
            timestamp=float(timestamp),                                 # timestamp
            seq=tcp.seq,                                                # TCP sequence number
            ack=tcp.ack,                                                # TCP acknowledgement number
            header=wire[:tcp.off * 4],                                  # raw bytes type header
            payload=bytearray(bytes(tcp.data)),                         # raw bytearray type payload
        )
        return data
    return None
