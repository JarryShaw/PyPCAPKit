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
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from decimal import Decimal
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from dpkt.dpkt import Packet
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


class RecordTimestamp:
    """A record's capture timestamp, with what a PCAP frame record needs of it.

    The readers :class:`~pcapkit.foundation.engines.dpkt.DPKT` uses yield
    ``(timestamp, octets)`` and nothing else, so a record's exact timestamp, its
    resolution and its original length would be lost between the reader and
    :func:`packet2frame`. The engine's readers yield a :class:`Timestamp` or a
    :class:`DecimalTimestamp` instead, which *is* the value `DPKT`_ yields --
    so reassembly and flow labels see exactly what they did before -- and also
    carries those three.

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


def _wire_hdr_len(packet: 'Packet', payload: 'Packet') -> 'int':
    """Calculate the octets a layer occupies before its payload begins.

    Args:
        packet: DPKT packet, i.e. one layer of a frame.
        payload: That layer's payload, i.e. :attr:`packet.data <dpkt.dpkt.Packet.data>`.

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
        Header Length, options included.

    """
    if hasattr(packet, 'extension_hdrs'):
        return packet.__hdr_len__ + sum(
            ext_hdr.length for ext_hdr in _ipv6_ext_hdrs(cast('IP6', packet))
        )
    return len(packet) - len(payload)


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
        while current is not layer:
            payload = getattr(current, 'data', None)
            if payload is None or isinstance(payload, (bytes, bytearray)):
                break
            offset += _wire_hdr_len(current, payload)
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
        Colon (``:``) separated list of protocol chain.

    """
    chain = [type(packet).__name__]
    payload = packet.data
    while not isinstance(payload, bytes):
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
        Dict[str, Any]: A :obj:`dict` mapping of packet data.

    """
    def wrapper(packet: 'Packet') -> 'dict[str, Any]':
        dict_ = {}  # type: dict[str, Any]
        for field in packet.__hdr_fields__:
            dict_[field] = getattr(packet, field, None)
        payload = packet.data
        if not isinstance(payload, bytes):
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
            :class:`~pcapkit.foundation.engines.dpkt.DPKT` leaves it.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv4 reassembly.

        * If the ``packet`` can be used for IPv4 reassembly. A packet can be reassembled
          if it contains IPv4 layer (:class:`dpkt.ip.IP`) and the **DF** (:attr:`dpkt.ip.IP.df`)
          flag is :data:`False`.
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

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    ipv4 = getattr(packet, 'ip', None)  # type: Optional[IP]
    if ipv4 is not None:
        if ipv4.df:     # dismiss not fragmented packet
            return None
        # internet header length, in octets -- ``IP.hl`` counts 32-bit words and
        # covers any IP options, whereas ``IP.__hdr_len__`` is the fixed 20-octet
        # struct size and would leave option octets at the head of the payload
        ihl = ipv4.hl * 4
        wire, captured = _layer2bytes(packet, ipv4)
        # a zero Total Length is what TCP segmentation offload leaves behind, in
        # which case the datagram runs to the end of the frame, as with DPKT
        if captured and ipv4.len:
            wire = wire[:ipv4.len]

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
            timestamp=timestamp,                                # capture timestamp
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
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv6 reassembly.

        * If the ``packet`` can be used for IPv6 reassembly. A packet can be reassembled
          if it contains IPv6 layer (:class:`dpkt.ip6.IP6`) and IPv6 Fragment header
          (:rfc:`2460#section-4.5`, i.e., :class:`dpkt.ip6.IP6FragmentHeader`).
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

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    """
    ipv6 = getattr(packet, 'ip6', None)  # type: Optional[IP6]
    if ipv6 is not None:
        ipv6_frag = ipv6.extension_hdrs.get(44)  # type: Optional[IP6FragmentHeader]
        if ipv6_frag is None:       # dismiss not fragmented packet
            return None
        hdr_len = ipv6_hdr_len(ipv6)
        wire, captured = _layer2bytes(packet, ipv6)
        # a zero Payload Length is a jumbogram or TCP segmentation offload, in
        # which case the datagram runs to the end of the frame, as with DPKT
        if captured and ipv6.plen:
            wire = wire[:ipv6.__hdr_len__ + ipv6.plen]
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
            timestamp=timestamp,                                 # capture timestamp
        )
        return data
    return None


def tcp_reassembly(packet: 'Packet', timestamp: 'float', *,
                   count: 'int' = -1) -> 'TCP_Packet | None':
    """Make data for TCP reassembly.

    Args:
        packet: DPKT packet.
        timestamp: Capture timestamp of the packet, which drives the reassembly
            timeout; :func:`packet2timestamp` reads it back off a stored frame.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP reassembly. A packet can be reassembled
          if it contains TCP layer (:class:`dpkt.tcp.TCP`).
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
    if hasattr(packet, 'ip'):
        ip = cast('IP', packet.ip)
    elif hasattr(packet, 'ip6'):
        ip = cast('IP6', packet.ip6)
    else:
        return None

    tcp = getattr(ip, 'tcp', None)  # type: Optional[TCP]
    if tcp is None and type(getattr(ip, 'data', None)).__name__ == 'TCP':
        tcp = cast('TCP', ip.data)
    if tcp is not None:
        flags = bin(tcp.flags)[2:].zfill(8)
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
            rst=bool(int(flags[5])),                            # reset connection flag
            syn=bool(int(flags[6])),                            # synchronise flag
            fin=bool(int(flags[7])),                            # finish flag
            header=wire[:tcp.off * 4],                          # raw bytes type header
            payload=bytearray(bytes(tcp.data)),                 # raw bytearray type payload
            first=tcp.seq,                                      # first sequence number of payload
            last=tcp.seq + raw_len - 1,                         # last sequence number of payload
            len=raw_len,                                        # payload length, header excludes
            timestamp=timestamp,                                # capture timestamp
        )
        return data
    return None


def tcp_traceflow(packet: 'Packet', timestamp: 'float', *,
                  data_link: 'Enum_LinkType', count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: DPKT packet.
        timestamp: Timestamp of the packet.
        data_link: Data link layer protocol (from global header).
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be reassembled
          if it contains TCP layer (:class:`dpkt.tcp.TCP`).
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
    if hasattr(packet, 'ip'):
        ip = cast('IP', packet.ip)
    elif hasattr(packet, 'ip6'):
        ip = cast('IP6', packet.ip6)
    else:
        return None

    tcp = getattr(ip, 'tcp', None)  # type: Optional[TCP]
    if tcp is None and type(getattr(ip, 'data', None)).__name__ == 'TCP':
        tcp = cast('TCP', ip.data)
    if tcp is not None:
        flags = bin(tcp.flags)[2:].zfill(8)
        wire, _ = _layer2bytes(packet, tcp)

        data = TF_TCP_Packet(  # type: ignore[type-var]
            protocol=data_link,                                         # data link type from global header
            index=count,                                                # frame number
            frame=packet2frame(packet, timestamp, data_link=data_link),  # extracted packet
            syn=bool(int(flags[6])),                                    # TCP synchronise (SYN) flag
            fin=bool(int(flags[7])),                                    # TCP finish (FIN) flag
            rst=bool(int(flags[5])),                                    # TCP reset (RST) flag
            src=ipaddress.ip_address(ip.src),                           # source IP
            dst=ipaddress.ip_address(ip.dst),                           # destination IP
            srcport=tcp.sport,                                          # TCP source port
            dstport=tcp.dport,                                          # TCP destination port
            timestamp=timestamp,                                        # timestamp
            seq=tcp.seq,                                                # TCP sequence number
            ack=tcp.ack,                                                # TCP acknowledgement number
            header=wire[:tcp.off * 4],                                  # raw bytes type header
            payload=bytearray(bytes(tcp.data)),                         # raw bytearray type payload
        )
        return data
    return None
