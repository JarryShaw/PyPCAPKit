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
from pcapkit.protocols.internet.ipv6 import IPV6_HEADER_LEN
from pcapkit.protocols.schema.internet.ipv4 import IPV4_HEADER_LEN
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.protocols.schema.misc.pcap.header import RESOLUTION, RESOLUTION_PLACES
from pcapkit.protocols.schema.transport.tcp import TCP_DATA_OFFSET_OCTET, TCP_MIN_HEADER_LEN
from pcapkit.toolkit.pypcapfile import (IP_TUNNELS, IPV4_EXTENSION_HEADERS, _default_accepts,
                                        _walk_extension_headers)
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
        but PCAP writes unchanged, carrying the octets `Scapy`_ dissected
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

        The fraction in ``frame_info.ts_usec`` is in the capture's own
        resolution. That resolution is the one
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

    nanosecond = getattr(packet, RESOLUTION_ATTR, RESOLUTION[False]) > RESOLUTION[False]
    stamp = packet.time
    epoch = (decimal.Decimal(stamp) if isinstance(stamp, decimal.Decimal)
             else round(decimal.Decimal(stamp), RESOLUTION_PLACES[nanosecond]))
    ts_sec = int(epoch)
    ts_usec = int((epoch - ts_sec) * RESOLUTION[nanosecond])

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
        every field left to its default. ``bytes()`` of it builds a header out
        of nothing -- 20 octets at ``RAW`` and ``IPV4``, 14 at ``ETHERNET`` --
        where the record has none (:issue:`1676`).

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
        with it. Those octets are no part of the datagram (:issue:`1584`), so
        they are cut off here. An IPv4 Total Length of zero, as TCP
        segmentation offload leaves, declares nothing, so the datagram runs to
        the end of the frame (:issue:`1547`); an IPv6 Payload Length of zero
        gives way to a Jumbo Payload option (:issue:`1434`), whose length is
        read here rather than left to Scapy, which reads it in host byte order
        and adds the Hop-by-Hop Options header to it a second time.

        Every IP layer above ``layer`` bounds it, not only the nearest: a
        datagram tunnelled in IP may declare more than the one carrying it
        holds, or nothing at all. An IPv4 layer built by hand has no ``ihl``
        until it is built, so one given a Total Length alone has its IHL read
        off the octets it builds into (:issue:`1676`).

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
        (:rfc:`9293#section-3.1`), as there is then no header to split off.

    Note:
        The Data Offset is read off the octets, which for a dissected layer
        carry the ``dataofs`` `Scapy`_ read, and for a layer built by hand the
        one it builds, as it leaves ``dataofs`` :data:`None` until then
        (:issue:`1676`).

    """
    segment = _within_datagrams(tcp)
    hdr_len = (segment[TCP_DATA_OFFSET_OCTET] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
    if hdr_len < TCP_MIN_HEADER_LEN:
        return None
    return segment[:hdr_len], segment[hdr_len:]


def _tcp_behind_extension_headers(segment: 'bytes') -> 'tuple[bytes, bytes] | None':
    """Split a TCP segment carried behind an AH or IPv6 extension header in IPv4.

    Args:
        segment: Raw octets from the TCP header on, as far as the IPv4 layer
            carrying it goes (see :func:`_tcp_carrier`).

    Returns:
        The header, as many octets as the Data Offset counts, and the payload
        after it; or :data:`None` if there are fewer than
        :data:`TCP_MIN_HEADER_LEN <pcapkit.protocols.schema.transport.tcp.TCP_MIN_HEADER_LEN>`
        octets, the Data Offset counts fewer or more than were captured, or
        pcapkit's own TCP parser rejects the options (see
        :func:`~pcapkit.toolkit.pypcapfile._default_accepts`).

    Note:
        `Scapy`_ dissects no TCP layer there (see :func:`_tcp_carrier`), so
        the segment is read off the octets, and its options are left to
        pcapkit's parser to check.

    """
    hdr_len = (segment[TCP_DATA_OFFSET_OCTET] >> 4) * 4 if len(segment) >= TCP_MIN_HEADER_LEN else 0
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
        an IPv4 layer above it is a later fragment, whose data is a slice of
        the datagram's payload with no upper-layer header in it
        (:rfc:`791#section-3.2`, :issue:`1617`).

        An IPv4 layer whose protocol names an AH or IPv6 extension header
        (:data:`~pcapkit.toolkit.pypcapfile.IPV4_EXTENSION_HEADERS`) has those
        headers stepped over in its octets, up to
        :data:`~pcapkit.utilities.config.EXTENSION_HEADER_LIMIT` of
        them in a row (see
        :func:`~pcapkit.toolkit.pypcapfile._walk_extension_headers`), and what
        follows them is dissected from the octets: a tunnel, walked on as
        above, or a TCP segment (see :func:`_tcp_behind_extension_headers`,
        :issue:`1606`). In the datagram an ICMP error quotes, they are left as
        `Scapy`_ dissects them.

    Note:
        The nearest is the innermost IP layer of an IP-in-IP tunnel
        (:rfc:`2003`, :rfc:`2473`, :rfc:`4213`), whose addresses are the TCP
        endpoints' (:issue:`1581`). ``packet['IP']`` finds the outermost IPv4
        layer instead, which is the tunnel's, or with IPv4 carried in IPv6 the
        inner one. The extension header layers `Scapy`_ dissects between an
        IPv6 layer and its payload are not IP layers, so are stepped over.

        Inside IPv4, `Scapy`_ dissects an AH alone of those headers, and behind
        one only IPv6 and, for a Next Header of ``0``, IPv4, so the octets are
        read instead. It also dissects IPv6 and AH inside a later fragment,
        binding neither to a zero fragment offset as it binds TCP.

    """
    from scapy.layers.inet import IP, TCP, IPerror
    from scapy.layers.inet6 import IPv6
    from scapy.packet import NoPayload

    tcp = cast('TCP | None', packet.getlayer('TCP'))
    carrier = None  # type: IP | IPv6 | None
    layer = packet  # type: Packet
    while layer is not tcp:
        if isinstance(layer, NoPayload):
            return None
        if isinstance(layer, IP):
            if layer.frag:
                return None
            carrier = layer
            # the datagram an ICMP error quotes is left as Scapy dissects it
            if layer.proto in IPV4_EXTENSION_HEADERS and not isinstance(layer, IPerror):
                upper = _walk_extension_headers(layer.proto, _within_datagrams(layer.payload))
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
          if it contains IPv4 layer (:class:`scapy.layers.inet.IP`) whose header -- as
          many octets as its IHL counts, and at least 20 -- lies inside the frame and
          every IP datagram carrying it (see :func:`_within_datagrams`), and the **DF**
          (:attr:`scapy.layers.inet.IP.flags.DF`) flag is :data:`False`. A zero-length
          frame has none, though `Scapy`_ hands it back as an IPv4 layer of defaults at
          the ``RAW`` and ``IPV4`` link types (see :func:`_frame`).
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    if 'IP' in packet:
        ipv4 = cast('IP', packet['IP'])
        if ipv4.flags.DF:       # dismiss not fragmented packet
            return None
        if not _frame(packet):  # a zero-length frame (:issue:`1676`)
            return None
        # NOTE: ``bytes(ipv4)`` ends with the frame's trailer, which Scapy files
        # as padding at the end of the packet however deep the IPv4 layer, so
        # only the octets inside every IP datagram above it are kept, the
        # Payload Length of IPv6 carrying it included (:issue:`1623`). The IHL
        # and Total Length are read off them, as Scapy leaves ``ihl`` and
        # ``len`` None on a layer built by hand until it is built (:issue:`1676`).
        octets = _within_datagrams(ipv4)
        ihl = (octets[0] & 0x0F) * 4 if octets else IPV4_HEADER_LEN
        if len(octets) < max(ihl, IPV4_HEADER_LEN):     # a header those octets cut short
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
            # NOTE: this keeps the octets past the Total Length, since the
            # reassembly machinery cuts the payload at ``tl - ihl`` itself.
            # :func:`ipv6_reassembly` derives its ``tl`` from the payload, so it
            # has to cut them (:issue:`1584`).
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
          if it contains IPv6 layer (:class:`scapy.layers.inet6.IPv6`), in no later IPv4
          fragment, and IPv6 Fragment header (:rfc:`2460#section-4.5`, i.e.,
          :class:`scapy.layers.inet6.IPv6ExtHdrFragment`) among the extension headers
          `Scapy`_ dissects in that layer's own chain.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv6
          reassembly (:term:`reasm.ipv6.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ModuleNotFound: If `Scapy`_ is not installed.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv6.IPv6`

    Note:
        A later IPv4 fragment's data is a slice of the datagram's payload, with
        no upper-layer header in it (:rfc:`791#section-3.2`), but `Scapy`_
        dissects IPv6 there whatever the fragment offset. And the header and
        addresses handed on are those of the IPv6 layer the Fragment header
        follows, so one inside a packet that layer carries, such as the inner
        packet of 6in6, is not taken.

    """
    if scapy is None:
        raise ModuleNotFound("No module named 'scapy'", name='scapy')
    from scapy.layers.inet import IP
    from scapy.layers.inet6 import IPv6ExtHdrFragment, _IPv6ExtHdr

    if 'IPv6' in packet:
        ipv6 = cast('IPv6', packet['IPv6'])
        above = ipv6.underlayer
        while above is not None:
            if isinstance(above, IP) and above.frag:    # data of a later fragment
                return None
            above = above.underlayer
        ipv6_frag = ipv6.payload
        while isinstance(ipv6_frag, _IPv6ExtHdr) and not isinstance(ipv6_frag, IPv6ExtHdrFragment):
            ipv6_frag = ipv6_frag.payload
        if not isinstance(ipv6_frag, IPv6ExtHdrFragment):
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
          in no later IPv4 fragment; or a TCP segment behind an AH or IPv6 extension
          header in IPv4, read off the octets. It is keyed by the IP layer that carries
          it -- in an IP-in-IP tunnel, the innermost (see :func:`_tcp_carrier`).
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
        Data for TCP flow tracing.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be traced
          if it contains TCP layer (:class:`scapy.layers.inet.TCP`), on the terms
          :func:`tcp_reassembly` sets.
        * If the ``packet`` can be traced, then the :obj:`dict` mapping of data for TCP
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
            # own timestamp on ``Packet.time``, so that is what is reported.
            timestamp=float(packet.time),                        # capture timestamp
            seq=tcp.seq,                                         # TCP sequence number
            ack=tcp.ack,                                         # TCP acknowledgement number
            header=header,                                       # raw bytes type header
            payload=bytearray(payload),                          # raw bytearray type payload
        )
        return data
    return None
