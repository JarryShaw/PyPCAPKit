# -*- coding: utf-8 -*-
"""PyPCAPFile Tools
=====================

.. module:: pcapkit.toolkit.pypcapfile

:mod:`pcapkit.toolkit.pypcapfile` contains the adapters for the `PyPCAPFile`_ engine.
The reassembly and flow tracing adapters return the data their
:mod:`pcapkit.foundation` counterpart consumes, or :data:`None` if the frame
cannot be used for it.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

.. important::

   `PyPCAPFile`_ decodes Ethernet, IPv4, TCP and UDP and nothing else -- there
   is no IPv6 decoder at all. :func:`ipv6_reassembly` therefore cannot be
   implemented and raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`
   instead of quietly returning :data:`None`, which would be indistinguishable
   from "this frame carries no IPv6 fragment".

   For the same reason :func:`tcp_reassembly` and :func:`tcp_traceflow` see TCP
   over IPv4 only, and decline a frame carrying TCP over IPv6. That loss is not
   silent: it is reported with one
   :exc:`~pcapkit.utilities.warnings.AttributeWarning` per capture, on its first
   such frame, rather than one per frame.

   `PyPCAPFile`_ decodes no VLAN tag either, so :func:`_network` reads past the
   802.1Q and 802.1ad tags the default engine steps over (see
   :data:`VLAN_TAGS`), however deeply stacked, and decodes the IPv4 packet
   behind them with `PyPCAPFile`_'s own decoder. TCP and IPv4 reassembly and TCP
   flow tracing therefore see a tagged IPv4 frame as they see an untagged one.
   Nor does it decode a tunnel, and TCP carried in IPv4 or IPv6 that is itself
   carried in IP (e.g. 4in4, 6in4, 6in6) is left out with an
   :exc:`~pcapkit.utilities.warnings.AttributeWarning` of its own, once per
   capture. Either warning follows the default engine's own rules for where it
   finds TCP, read off the raw headers, with one stated exception for a
   malformed tunnelled frame (see :func:`_upper_layer`).

   Note also that `PyPCAPFile`_ decoders *replace* the payload bytes of the layer
   they decode. :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` therefore
   stops at the network layer, which keeps the transport segment verbatim so that
   the header/payload split this module reports is exact. The transport header is
   decoded on demand below, using `PyPCAPFile`_'s own
   :class:`~pcapfile.protocols.transport.tcp.TCP` class rather than a
   reimplementation.

"""
import binascii
import collections
import ctypes
import ipaddress
import struct
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.ipv6.extension_header import ExtensionHeader as Enum_ExtensionHeader
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall, stacklevel
from pcapkit.utilities.warnings import AttributeWarning, warn

if TYPE_CHECKING:
    from collections import OrderedDict, deque
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from pcapfile.protocols.network.ip import IP
    from pcapfile.structs import pcap_packet as Packet

__all__ = [
    'packet2timestamp', 'ipv4_header', 'packet2chain', 'packet2dict',
    'ipv4_reassembly', 'ipv6_reassembly', 'tcp_reassembly', 'tcp_traceflow',
]

#: Whether :meth:`bytes.hex` supports the ``sep`` argument (Python 3.8+), as used
#: below by :func:`_parse_mac_address` -- mirrors the same guard in
#: :meth:`pcapkit.protocols.link.ethernet.Ethernet._read_mac_addr`.
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)

#: Minimum length of a TCP header, i.e. the fixed part with no options.
TCP_MIN_HEADER_LEN = 20

#: IPv4 **DF** (don't fragment) bit, within the three-bit flags field.
IPV4_FLAG_DF = 0b010

#: IPv4 **MF** (more fragments) bit, within the three-bit flags field.
IPV4_FLAG_MF = 0b001

#: Length of the fixed IPv4 header, i.e. with no options, :rfc:`791#section-3.1`.
IPV4_HEADER_LEN = 20

#: Length of the fixed IPv6 header, :rfc:`8200#section-3`.
IPV6_HEADER_LEN = 40

#: EtherTypes of the VLAN tags :func:`_network` reads past: the 802.1Q customer
#: tag and the 802.1ad service tag, which QinQ stacks. These are the two the
#: default engine dissects (see :attr:`Link.__proto__
#: <pcapkit.protocols.link.link.Link.__proto__>`).
VLAN_TAGS = frozenset((
    Enum_EtherType.Customer_VLAN_Tag_Type,
    Enum_EtherType.IEEE_Std_802_1Q_Service_VLAN_tag_identifier,
))

#: Length of a VLAN tag (IEEE 802.1Q): two octets of tag control information,
#: then the EtherType of what follows the tag.
VLAN_TAG_LEN = 4

#: IP protocol numbers of the IP-in-IP tunnels the default engine dissects
#: (see :attr:`Internet.__proto__
#: <pcapkit.protocols.internet.internet.Internet.__proto__>`), each mapped to the
#: IP version it carries: IPv4 (protocol 4, :rfc:`2003`) and IPv6 (protocol 41,
#: :rfc:`2473` and :rfc:`4213`).
IP_TUNNELS = {Enum_TransType.IPv4: 4, Enum_TransType.IPv6: 6}

#: IPv6 extension headers that :func:`_upper_layer` steps over on its way
#: to the upper-layer protocol, as the default engine does: the ones
#: :rfc:`8200#section-4.1` orders before it, less ESP, whose payload is
#: encrypted, plus the Mobility, HIP and Shim6 headers. Those three are sized in
#: 8-octet units like most of the rest, and the default engine dissects whatever
#: protocol their next header field names. The experimental 253 and 254 are left
#: out, because the default engine dissects nothing after them.
IPV6_EXTENSION_HEADERS = frozenset((
    Enum_ExtensionHeader.HOPOPT, Enum_ExtensionHeader.IPv6_Opts, Enum_ExtensionHeader.IPv6_Route,
    Enum_ExtensionHeader.IPv6_Frag, Enum_ExtensionHeader.AH, Enum_ExtensionHeader.Mobility_Header,
    Enum_ExtensionHeader.HIP, Enum_ExtensionHeader.Shim6,
))

#: The warning :func:`_decline_tcp` gives for each kind of TCP that
#: :func:`_left_out` finds this engine cannot read.
TCP_LEFT_OUT = {
    'ipv6': "TCP over IPv6 is left out of TCP reassembly and flow tracing, as 'pypcapfile' "
            'has no IPv6 decoder',
    'tunnel': 'TCP tunnelled in IP (IPv4 or IPv6 carried in IPv4 or IPv6) is left out of TCP '
              "reassembly and flow tracing, as 'pypcapfile' decodes no tunnel",
}

#: How many warnings :func:`_decline_tcp` remembers having given, each for one
#: kind in :data:`TCP_LEFT_OUT` and one capture. Each one pins a packet of its
#: own in memory (see :func:`_capture_of`), so the memory is bounded and the
#: oldest is forgotten first. Up to this many read at the same time warn exactly
#: once each.
TCP_WARNED_LIMIT = 32

#: The warnings :func:`_decline_tcp` has given, oldest first. Each is keyed by
#: the key :func:`_capture_of` gives and the kind, and maps to the anchor that
#: keeps that key unique.
_tcp_warned = collections.OrderedDict()  # type: OrderedDict[tuple[int, str], Any]

#: The frame :func:`_network` last warned it could not decode: the key
#: :func:`_capture_of` gives, the packet index and the anchor that keeps the key
#: unique. The adapters each fetch the network layer of a frame in turn, so this
#: is what holds them to one warning per frame between them.
_undecoded_last = collections.deque(maxlen=1)  # type: deque[tuple[int, int, Any]]


def packet2timestamp(packet: 'Packet') -> 'float':
    """Calculate the timestamp of a PyPCAPFile packet.

    Args:
        packet: PyPCAPFile packet.

    Returns:
        Timestamp of the packet, in seconds since the epoch.

    Note:
        `PyPCAPFile`_ keeps the two halves of the per-packet timestamp apart, and
        the sub-second half is nanoseconds rather than microseconds when the
        savefile carries the nanosecond magic number -- which is recorded on the
        savefile header as ``ns_resolution``.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    divisor = 1_000_000_000 if packet.header[0].ns_resolution else 1_000_000
    return packet.timestamp + packet.timestamp_us / divisor


def _parse_ipv4_address(value: 'Any') -> 'IPv4Address':
    """Parse a raw PyPCAPFile IPv4 ``src``/``dst`` field.

    Args:
        value: Raw value of an :attr:`IP.src <pcapfile.protocols.network.ip.IP.src>`
            or :attr:`IP.dst <pcapfile.protocols.network.ip.IP.dst>` field.

    Returns:
        The parsed address.

    Note:
        The released `PyPCAPFile`_ (0.12.0) stores ``src``/``dst`` as
        dotted-decimal ASCII text in a :class:`ctypes.c_char_p` -- e.g.
        ``b'10.1.1.2'`` -- rather than as a packed 4-byte value, which is all
        :class:`ipaddress.IPv4Address` accepts from a :obj:`bytes` argument
        (it raises :exc:`~ipaddress.AddressValueError` otherwise). This helper
        also accepts a packed 4-byte :obj:`bytes` value directly, so a
        differently-represented `PyPCAPFile`_ fork or release still works.
        Anything that is not :obj:`bytes`, a plain :obj:`int` included, is
        rejected outright. The unit-test stand-ins model the field as
        dotted-decimal :obj:`bytes`, as the released library does, rather than
        this helper being widened to fit a fixture.

    Raises:
        ProtocolError: If ``value`` cannot be parsed as an IPv4 address.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    if not isinstance(value, bytes):
        raise ProtocolError(f'invalid PyPCAPFile IPv4 address: {value!r}')
    try:
        if len(value) != 4:
            # Dotted-decimal ASCII text, the actual PyPCAPFile 0.12.0 form --
            # a packed 4-byte address is never a valid dotted-quad string,
            # since the shortest one (``0.0.0.0``) is already 7 bytes long.
            return ipaddress.IPv4Address(value.decode('ascii'))
        return ipaddress.IPv4Address(value)
    except (ValueError, UnicodeDecodeError) as error:
        raise ProtocolError(f'invalid PyPCAPFile IPv4 address: {value!r}') from error


def _parse_mac_address(value: 'Any') -> 'str':
    """Parse a raw PyPCAPFile Ethernet ``src``/``dst`` field.

    Args:
        value: Raw value of an :attr:`Ethernet.src
            <pcapfile.protocols.linklayer.ethernet.Ethernet.src>` or
            :attr:`Ethernet.dst <pcapfile.protocols.linklayer.ethernet.Ethernet.dst>`
            field.

    Returns:
        Lowercase, colon-separated hex MAC address, e.g. ``'01:00:5e:01:03:03'``
        -- the same form :meth:`~pcapkit.protocols.link.ethernet.Ethernet._read_mac_addr`
        uses for the default engine.

    Note:
        The released `PyPCAPFile`_ (0.12.0) already stores ``src``/``dst`` pre-formatted
        exactly this way, as ASCII text in a :class:`ctypes.c_char_p` -- not as a raw
        6-byte value, which :func:`bytes` alone passes straight through unexamined. This
        helper also accepts a raw 6-byte value directly, so a differently-represented
        `PyPCAPFile`_ fork or release, and the stand-ins used in unit tests, keep working.

    Raises:
        ProtocolError: If ``value`` cannot be parsed as a MAC address.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    if not isinstance(value, (bytes, bytearray)):
        raise ProtocolError(f'invalid PyPCAPFile MAC address: {value!r}')
    raw = bytes(value)
    if len(raw) == 6:
        return raw.hex(':') if py38 else ':'.join(textwrap.wrap(raw.hex(), 2))
    try:
        return raw.decode('ascii')
    except UnicodeDecodeError as error:
        raise ProtocolError(f'invalid PyPCAPFile MAC address: {value!r}') from error


def _maybe_unhex(value: 'bytes') -> 'bytes':
    """Undo :func:`binascii.hexlify`, if ``value`` looks hex-encoded.

    Args:
        value: Raw bytes, possibly hex-encoded.

    Returns:
        ``value`` hex-decoded, if it is a valid even-length hex string;
        otherwise ``value`` itself, unchanged.

    Note:
        The released `PyPCAPFile`_ (0.12.0) stores an IPv4 packet's options
        (:attr:`IP.opt <pcapfile.protocols.network.ip.IP.opt>`) and payload
        (:attr:`IP.payload <pcapfile.protocols.network.ip.IP.payload>`) as
        :func:`binascii.hexlify`'d ASCII text once decoding stops short of the
        transport layer -- which is exactly how
        :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` calls it --
        rather than as the raw bytes this module otherwise assumes. Both forms
        are :obj:`bytes`, hex-encoded or not, which is why :func:`_is_raw`
        cannot tell them apart, and falling back to the original value when
        it does not decode as hex is what keeps this a no-op for the raw,
        non-hex stand-ins used in unit tests.

        This is **not** a guarantee against every false positive, only a
        cheap and, in practice, reliable heuristic: a genuinely raw payload
        whose every byte happens to fall in the ASCII hex-digit range (e.g. a
        24-byte TCP header built entirely from digits and ``A``-``F``) is
        indistinguishable from real hex text and gets silently halved. There
        is no way to tell the two forms apart from the bytes alone; this is
        acceptable here because that byte range is a small fraction of the
        possible values a real header or payload can take.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    try:
        return binascii.unhexlify(value)
    except binascii.Error:
        return value


def ipv4_header(ipv4: 'IP') -> 'bytes':
    """Rebuild the raw header bytes of a PyPCAPFile IPv4 packet.

    Args:
        ipv4: PyPCAPFile IPv4 packet.

    Returns:
        Raw IPv4 header bytes, options included.

    Note:
        `PyPCAPFile`_ discards the header bytes once decoded, but it retains
        *every* IPv4 header field plus the options blob, so this reconstruction
        is byte-exact rather than approximate.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    return struct.pack(
        '!BBHHHBBHII',
        (ipv4.v << 4) | ipv4.hl,                 # version and internet header length
        ipv4.tos,                                # type of service
        ipv4.len,                                # total length
        ipv4.id,                                 # identification
        (ipv4.flags << 13) | ipv4.off,           # flags and fragment offset
        ipv4.ttl,                                # time to live
        ipv4.p,                                  # payload protocol type
        ipv4.sum,                                # header checksum
        int(_parse_ipv4_address(ipv4.src)),      # source IP address
        int(_parse_ipv4_address(ipv4.dst)),      # destination IP address
    ) + _maybe_unhex(bytes(ipv4.opt))


def _is_raw(layer: 'Any') -> 'bool':
    """Test if a decoded layer is in fact undecoded raw bytes.

    Args:
        layer: Decoded layer, or raw bytes.

    """
    return isinstance(layer, (bytes, bytearray, memoryview))


def _untag(link: 'Any') -> 'Optional[tuple[int, bytes]]':
    """Read past the VLAN tags of an Ethernet frame whose payload is undecoded.

    Args:
        link: Decoded PyPCAPFile link layer.

    Returns:
        The EtherType after the last of the tags in :data:`VLAN_TAGS` and the
        raw octets it heads -- for an untagged frame, the frame's own EtherType
        and payload. :data:`None` if `PyPCAPFile`_ decoded the payload, or a tag
        is cut short.

    Note:
        `PyPCAPFile`_ leaves a payload it has no decoder for hex-encoded (see
        :func:`_maybe_unhex`), so this reads the raw octets and decodes nothing.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    ethertype = getattr(link, 'type', None)  # type: Optional[int]
    payload = getattr(link, 'payload', None)  # type: Any
    if ethertype is None or not _is_raw(payload):
        return None

    data = _maybe_unhex(bytes(payload))
    while ethertype in VLAN_TAGS:
        if len(data) < VLAN_TAG_LEN:
            return None
        ethertype, data = int.from_bytes(data[2:4], 'big'), data[VLAN_TAG_LEN:]
    return ethertype, data


def _network(packet: 'Packet', count: 'int' = -1) -> 'Optional[IP]':
    """Fetch the decoded IPv4 layer of a PyPCAPFile packet, if any.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index, for the warning below.

    Returns:
        The decoded :class:`~pcapfile.protocols.network.ip.IP` layer, or
        :data:`None` when the frame was not decoded that far -- which is the
        case for every non-IPv4 frame, `PyPCAPFile`_ having no other network
        layer decoder.

    Warns:
        AttributeWarning: If an IPv4 packet behind VLAN tags will not decode,
            in the words, and with the category,
            :meth:`PyPCAPFile._decode <pcapkit.foundation.engines.pypcapfile.PyPCAPFile._decode>`
            uses for an untagged one -- once per frame, however many adapters
            fetch its network layer.

    Note:
        `PyPCAPFile`_ decodes no VLAN tag, so it leaves an IPv4 packet behind
        one undecoded. That packet is decoded here, past every tag that
        :func:`_untag` reads past, with the same
        :class:`~pcapfile.protocols.network.ip.IP` decoder and the same depth
        :class:`~pcapfile.protocols.linklayer.ethernet.Ethernet` uses for an
        untagged frame, so the two decode alike; one that will not decode is
        left out with a warning, as an untagged one is. The engine warns of an
        untagged frame as it reads it, and this of a tagged one as reassembly or
        flow tracing does.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    link = packet.packet
    if _is_raw(link):
        return None

    payload = getattr(link, 'payload', None)
    if type(payload).__name__ == 'IP':
        return payload
    if getattr(link, 'type', None) not in VLAN_TAGS:
        return None

    untagged = _untag(link)
    if untagged is None or untagged[0] != Enum_EtherType.Internet_Protocol_version_4:
        return None

    # NOTE: imported only once there is something to decode, as in
    # :func:`tcp_reassembly`; ``layers=0`` stops at the network layer, as the
    # engine does (see :attr:`PyPCAPFile.LAYERS
    # <pcapkit.foundation.engines.pypcapfile.PyPCAPFile.LAYERS>`).
    from pcapfile.protocols.network.ip import IP  # isort:skip

    try:
        return IP(untagged[1], 0)
    except (struct.error, AssertionError, ValueError, IndexError, KeyError) as error:
        key, anchor = _capture_of(packet)
        if not _undecoded_last or _undecoded_last[0][:2] != (key, count):
            _undecoded_last.append((key, count, anchor))
            warn(f'Frame {count}: {Enum_LinkType.ETHERNET!r} decoding failed ({error!r}); '
                 'frame left undecoded', AttributeWarning, stacklevel=stacklevel())
        return None


def _upper_layer(version: 'int', data: 'bytes') -> 'Optional[tuple[int, bytes]]':
    """Step over an IP header to the upper-layer protocol it carries.

    Args:
        version: IP version of the header ``data`` starts with, ``4`` or ``6``.
        data: Raw octets of the IP packet.

    Returns:
        The upper-layer protocol number and the octets from its header on, or
        :data:`None` if no upper-layer header follows.

        An IPv4 header must be version 4 with a header length of at least
        :data:`IPV4_HEADER_LEN` octets, all of them captured, and what follows
        it ends at its Total Length, as in :func:`_ipv4_payload`. An IPv6 packet
        ends at its Payload Length or, where that is ``0``, at the Jumbo Payload
        Length a jumbogram's Hop-by-Hop Options header gives (:rfc:`2675`) --
        lacking one, it has no payload -- and is followed past the extension headers in
        :data:`IPV6_EXTENSION_HEADERS`; a first fragment is read past its
        Fragment header as if that header were not there. A later fragment of
        either has no upper-layer header, since from its offset on it carries a
        slice of the payload (:rfc:`791#section-3.2`, :rfc:`8200#section-4.5`).
        Nor does a truncated header or header chain.

    Note:
        Each of these rules is the default engine's own, as are the ones
        :func:`_left_out` applies to the TCP header, so that the warning
        :func:`_decline_tcp` gives fires on the frames the default engine finds
        TCP in. This reads only as far as the upper-layer protocol number and
        decodes nothing, so it does not see every reason the default engine has
        to leave octets undissected: an IPv4 option or an extension header
        option it rejects, which leaves the header raw, or TCP options it
        rejects, which in a tunnel leave the segment raw. A malformed tunnelled
        frame like that is warned of all the same, though the default engine
        finds no TCP in it either -- a warning that errs on the side of being
        given, rather than a dissection of every such frame to settle it.

    """
    if version == 4:
        if len(data) < IPV4_HEADER_LEN or data[0] >> 4 != 4:
            return None
        ihl = (data[0] & 0x0F) * 4
        if ihl < IPV4_HEADER_LEN or len(data) < ihl:
            return None
        if struct.unpack_from('!H', data, 6)[0] & 0x1FFF:  # a later fragment
            return None
        total = struct.unpack_from('!H', data, 2)[0]
        return data[9], data[ihl:max(total, ihl)] if total else data[ihl:]

    if len(data) < IPV6_HEADER_LEN:
        return None
    extent = struct.unpack_from('!H', data, 4)[0]
    if not extent:
        extent = jumbo_payload_length(data[6], data[IPV6_HEADER_LEN:]) or 0
    data = data[:IPV6_HEADER_LEN + extent]
    nxt, offset = data[6], IPV6_HEADER_LEN
    while nxt in IPV6_EXTENSION_HEADERS:
        if len(data) < offset + 8:
            return None
        if nxt == Enum_ExtensionHeader.IPv6_Frag:  # fixed length, second octet reserved
            if struct.unpack_from('!H', data, offset + 2)[0] >> 3:  # a later fragment
                return None
            length = 8
        elif nxt == Enum_ExtensionHeader.AH:  # length in 4-octet units, less two
            length = (data[offset + 1] + 2) * 4
        else:  # length in 8-octet units, less one
            length = (data[offset + 1] + 1) * 8
        nxt, offset = data[offset], offset + length
    if len(data) < offset:
        return None
    return nxt, data[offset:]


def _left_out(packet: 'Packet', ipv4: 'Optional[IP]') -> 'Optional[str]':
    """Name the TCP a PyPCAPFile frame carries that this engine cannot read.

    Args:
        packet: PyPCAPFile packet, which :func:`_transport` found no TCP segment in.
        ipv4: Its IPv4 layer, as :func:`_network` fetches it.

    Returns:
        ``'ipv6'`` if the frame is IPv6 carrying TCP, directly or behind
        extension headers; ``'tunnel'`` if it is IPv4 or IPv6 carrying TCP in one
        or more of the :data:`IP_TUNNELS`; otherwise :data:`None`. Either may be
        behind VLAN tags (see :func:`_untag`), and each IP header is stepped over
        as :func:`_upper_layer` does. An ESP payload cannot be seen into, so does
        not count.

        The TCP header has to be at least :data:`TCP_MIN_HEADER_LEN` octets
        long, as its Data Offset gives it, with that many captured. In a tunnel,
        the whole of the header its Data Offset gives has to be there too, as far
        as the inner IP packet's own length: the default engine's TCP parser
        rejects one cut short, e.g. by the snapshot length, and only directly
        over IPv6 does it then read the segment out of the raw octets left
        behind (:func:`pcapkit.toolkit.pcap.tcp_segment`, :issue:`1518`).

    """
    if ipv4 is not None:  # read by PyPCAPFile, so only a tunnel can hide TCP
        # a later fragment has no upper-layer header, see ``_upper_layer``
        if ipv4.off or ipv4.p not in IP_TUNNELS or not _is_raw(ipv4.payload):
            return None
        upper = ipv4.p, _ipv4_payload(ipv4)  # type: Optional[tuple[int, bytes]]
    else:
        link = packet.packet
        untagged = None if _is_raw(link) else _untag(link)
        if untagged is None or untagged[0] != Enum_EtherType.Internet_Protocol_version_6:
            return None
        upper = _upper_layer(6, untagged[1])

    kind = 'ipv6'
    while upper is not None and upper[0] in IP_TUNNELS:
        upper, kind = _upper_layer(IP_TUNNELS[upper[0]], upper[1]), 'tunnel'
    if upper is None or upper[0] != Enum_TransType.TCP:
        return None
    segment = upper[1]
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None
    header = (segment[12] >> 4) * 4  # the Data Offset, in octets
    if header < TCP_MIN_HEADER_LEN or (kind == 'tunnel' and header > len(segment)):
        return None
    return kind


def _capture_of(packet: 'Packet') -> 'tuple[int, Any]':
    """Identify the capture a PyPCAPFile packet was read from.

    Args:
        packet: PyPCAPFile packet.

    Returns:
        A key, equal for every packet of one capture, and an anchor: while the
        anchor is alive, no packet of another capture has the same key.

    Note:
        :attr:`pcap_packet.header <pcapfile.structs.pcap_packet.header>` is a
        :mod:`ctypes` pointer to the savefile header. Each read of the field
        builds a new pointer object, but every one of them points at the same
        header, so the header's address is the key. The pointer object read
        here is the anchor: it keeps its packet alive and, through that packet,
        the header itself, so no other capture's header can be allocated at
        that address while it is held. A header that is not a :mod:`ctypes`
        pointer is keyed by its identity instead, and anchors itself.

    """
    anchor = packet.header
    try:
        return ctypes.addressof(anchor.contents), anchor
    except (AttributeError, TypeError, ValueError):
        return id(anchor), anchor


def _decline_tcp(packet: 'Packet', ipv4: 'Optional[IP]', count: 'int') -> 'None':
    """Warn that a frame carrying TCP this engine cannot read is left out.

    Args:
        packet: PyPCAPFile packet, which :func:`_transport` found no TCP segment in.
        ipv4: Its IPv4 layer, as :func:`_network` fetches it.
        count: Packet index.

    Warns:
        AttributeWarning: If ``packet`` carries TCP that :func:`_left_out` names,
            and is the first frame of its capture carrying that kind of TCP to
            reach :func:`tcp_reassembly` or :func:`tcp_traceflow`. Later frames
            of the same capture and kind are left out without another warning,
            and every other capture or kind warns once of its own, however their
            frames interleave. Only the :data:`TCP_WARNED_LIMIT` warnings given
            most recently are remembered, so with more than that read at once a
            forgotten one is given again: a warning can repeat, but is never
            omitted.

    """
    key, anchor = _capture_of(packet)
    if all((key, kind) in _tcp_warned for kind in TCP_LEFT_OUT):
        return
    kind = _left_out(packet, ipv4)
    if kind is None or (key, kind) in _tcp_warned:
        return

    _tcp_warned[key, kind] = anchor
    while len(_tcp_warned) > TCP_WARNED_LIMIT:
        _tcp_warned.popitem(last=False)
    warn(f'Frame {count}: {TCP_LEFT_OUT[kind]}; later such frames of this capture are left out '
         'without another warning', AttributeWarning, stacklevel=stacklevel())


def _ipv4_payload(ipv4: 'IP') -> 'bytes':
    """Fetch the raw payload of a PyPCAPFile IPv4 packet, as far as its Total Length.

    Args:
        ipv4: PyPCAPFile IPv4 packet, whose payload `PyPCAPFile`_ left undecoded.

    Returns:
        The octets after the header, up to the Total Length. A Total Length of
        ``0``, which TCP segmentation offload leaves in a capture taken on the
        sending host, leaves the rest of the frame; one shorter than the header
        leaves none (:issue:`1547`).

    Note:
        `PyPCAPFile`_ keeps every octet after the header as the payload, so a
        frame padded to the Ethernet minimum carries its padding there. The
        default engine reads such octets as a trailer, outside the payload
        (:issue:`1209`), and so does this (:issue:`1577`).

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    payload = _maybe_unhex(bytes(ipv4.payload))
    if not ipv4.len:
        return payload
    return payload[:max(ipv4.len - ipv4.hl * 4, 0)]


def _transport(ipv4: 'IP') -> 'Optional[bytes]':
    """Fetch the verbatim TCP segment carried by a PyPCAPFile IPv4 packet.

    Args:
        ipv4: PyPCAPFile IPv4 packet.

    Returns:
        The raw TCP segment, as far as the Total Length (see
        :func:`_ipv4_payload`), or :data:`None` if the packet does not carry a
        TCP payload long enough to hold a header. A later fragment carries none:
        from its offset on, its data is a slice of the datagram's payload, with
        no upper-layer header in it (:rfc:`791#section-3.2`, :issue:`1576`).

    """
    if ipv4.p != Enum_TransType.TCP or ipv4.off:
        return None
    if not _is_raw(ipv4.payload):
        return None

    segment = _ipv4_payload(ipv4)
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None
    return segment


def _ethernet2dict(link: 'Any') -> 'dict[str, Any]':
    """Convert a PyPCAPFile Ethernet frame into :obj:`dict`.

    Args:
        link: PyPCAPFile Ethernet frame.

    Raises:
        ProtocolError: If ``link.src`` or ``link.dst`` cannot be parsed as a
            MAC address.

    """
    return {
        'dst': _parse_mac_address(link.dst),
        'src': _parse_mac_address(link.src),
        'type': link.type,
    }


def _ipv4_2dict(ipv4: 'IP') -> 'dict[str, Any]':
    """Convert a PyPCAPFile IPv4 packet into :obj:`dict`.

    Args:
        ipv4: PyPCAPFile IPv4 packet.

    """
    return {
        'v': ipv4.v,
        'hl': ipv4.hl,
        'tos': ipv4.tos,
        'len': ipv4.len,
        'id': ipv4.id,
        'flags': ipv4.flags,
        'off': ipv4.off,
        'ttl': ipv4.ttl,
        'p': ipv4.p,
        'sum': ipv4.sum,
        'src': str(_parse_ipv4_address(ipv4.src)),
        'dst': str(_parse_ipv4_address(ipv4.dst)),
        'opt': _maybe_unhex(bytes(ipv4.opt)),
    }


def _layer2dict(layer: 'Any') -> 'dict[str, Any]':
    """Convert a decoded PyPCAPFile layer into :obj:`dict`, recursively.

    Args:
        layer: Decoded PyPCAPFile layer, or raw bytes.

    Note:
        `PyPCAPFile`_'s own :class:`~pcapfile.protocols.linklayer.ethernet.Ethernet`
        and :class:`~pcapfile.protocols.network.ip.IP` decoders hex-encode the
        payload they retain rather than decoding it further (see
        :func:`_maybe_unhex`), so a raw payload reached by recursing *from* one of
        those two classes is un-hexed before being reported here. Without that,
        an ``IP`` layer with options would report its own ``opt`` correctly
        (:func:`_ipv4_2dict` already un-hexes it) while its nested ``'Raw'``
        payload stayed hex-encoded and twice the true length -- an inconsistency
        within the very same :obj:`dict`. Any other, unrecognised layer type's
        raw payload is left untouched, since nothing here establishes that it is
        `PyPCAPFile`_-hexlified rather than genuinely raw.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    if _is_raw(layer):
        raw = bytes(layer)
        return {'raw_len': len(raw), 'raw': raw}

    name = type(layer).__name__
    if name == 'Ethernet':
        dict_ = _ethernet2dict(layer)
    elif name == 'IP':
        dict_ = _ipv4_2dict(layer)
    else:
        dict_ = {field[0]: getattr(layer, field[0], None)
                 for field in getattr(type(layer), '_fields_', ())}

    payload = getattr(layer, 'payload', None)
    if payload is not None:
        if name in ('Ethernet', 'IP') and _is_raw(payload):
            payload = _maybe_unhex(bytes(payload))
        dict_['Raw' if _is_raw(payload) else type(payload).__name__] = _layer2dict(payload)
    return dict_


def packet2chain(packet: 'Packet', *, data_link: 'Enum_LinkType') -> 'str':
    """Fetch PyPCAPFile packet protocol chain.

    Args:
        packet: PyPCAPFile packet.
        data_link: Data link type, from the savefile header.

    Returns:
        Colon (``:``) separated list of protocol chain.

    Note:
        The chain reports what `PyPCAPFile`_ actually decoded and no more, so it
        ends in ``Raw`` -- the transport segment is left undecoded on purpose,
        see the module notes.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    layer = packet.packet
    if _is_raw(layer):
        return f'{data_link.name}:Raw'

    chain = []  # type: list[str]
    while not _is_raw(layer):
        chain.append(type(layer).__name__)
        layer = getattr(layer, 'payload', b'')
    chain.append('Raw')
    return ':'.join(chain)


def packet2dict(packet: 'Packet', *, data_link: 'Enum_LinkType') -> 'dict[str, Any]':
    """Convert PyPCAPFile packet into :obj:`dict`.

    Args:
        packet: PyPCAPFile packet.
        data_link: Data link type, from the savefile header.

    Returns:
        Dict[str, Any]: A :obj:`dict` mapping of packet data.

    Raises:
        ProtocolError: If a decoded IPv4 layer's ``src``/``dst`` cannot be
            parsed as an IPv4 address, or a decoded Ethernet layer's
            ``src``/``dst`` cannot be parsed as a MAC address.

    """
    return {
        'timestamp': packet2timestamp(packet),
        'capture_len': packet.capture_len,
        'packet_len': packet.packet_len,
        data_link.name: _layer2dict(packet.packet),
    }


def ipv4_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'IP_Packet[IPv4Address] | None':
    """Make data for IPv4 reassembly.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for IPv4 reassembly.

        * If the ``packet`` can be used for IPv4 reassembly. A packet can be reassembled
          if it contains an IPv4 layer (:class:`pcapfile.protocols.network.ip.IP`), behind
          802.1Q or 802.1ad VLAN tags or not, and the **DF** flag is :data:`False`.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    ipv4 = _network(packet, count)
    if ipv4 is None:
        return None
    if ipv4.flags & IPV4_FLAG_DF:  # dismiss not fragmented packet
        return None

    header = ipv4_header(ipv4)
    return IP_Packet(
        bufid=(
            _parse_ipv4_address(ipv4.src),          # source IP address
            _parse_ipv4_address(ipv4.dst),          # destination IP address
            ipv4.id,                                # identification
            Enum_TransType.get(ipv4.p),             # payload protocol type
        ),
        num=count,                                  # original packet range number
        fo=ipv4.off * 8,                            # fragment offset, in octets
        ihl=len(header),                            # internet header length
        mf=bool(ipv4.flags & IPV4_FLAG_MF),         # more fragment flag
        tl=ipv4.len,                                # total length, header includes
        header=header,                              # raw bytes type header
        payload=bytearray(_maybe_unhex(bytes(ipv4.payload))),  # raw bytearray type payload
        timestamp=packet2timestamp(packet),         # capture timestamp
    )


def ipv6_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'IP_Packet[IPv6Address] | None':
    """Make data for IPv6 reassembly.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index. If not provided, default to ``-1``.

    Raises:
        UnsupportedCall: Always, as `PyPCAPFile`_ has no IPv6 decoder.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    raise UnsupportedCall('IPv6 reassembly is not supported by the PyPCAPFile engine: '
                          "'pypcapfile' has no IPv6 decoder, so no IPv6 fragment header "
                          'can be read')


def tcp_reassembly(packet: 'Packet', *, count: 'int' = -1) -> 'TCP_Packet | None':
    """Make data for TCP reassembly.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP reassembly.

        * If the ``packet`` can be used for TCP reassembly. A packet can be reassembled
          if it contains an IPv4 layer carrying a TCP segment, behind 802.1Q or 802.1ad
          VLAN tags or not; TCP over IPv6 cannot be, as `PyPCAPFile`_ has no IPv6 decoder,
          and nor can TCP tunnelled in IP, as it decodes no tunnel.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    Warns:
        AttributeWarning: If ``packet`` carries TCP over IPv6, or tunnelled in IP,
            which is left out, and is the first such frame of its capture to
            reach either :func:`tcp_reassembly` or :func:`tcp_traceflow`. The
            rest of that capture's such frames are left out without another
            warning; each of the two kinds warns once of its own.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    ipv4 = _network(packet, count)
    if ipv4 is None or (segment := _transport(ipv4)) is None:
        _decline_tcp(packet, ipv4, count)
        return None

    # NOTE: imported only once there is something to decode, so that declining a
    # frame does not require ``pcapfile`` to be installed.
    from pcapfile.protocols.transport.tcp import TCP  # isort:skip

    tcp = TCP(segment)
    hdr_len = max(tcp.data_offset, TCP_MIN_HEADER_LEN)
    payload = segment[hdr_len:]

    return TCP_Packet(
        bufid=(
            _parse_ipv4_address(ipv4.src),    # source IP address
            tcp.src_port,                     # source port
            _parse_ipv4_address(ipv4.dst),    # destination IP address
            tcp.dst_port,                     # destination port
        ),
        num=count,                            # original packet range number
        ack=tcp.acknum,                       # acknowledgement
        dsn=tcp.seqnum,                       # data sequence number
        rst=bool(tcp.rst),                    # reset connection flag
        syn=bool(tcp.syn),                    # synchronise flag
        fin=bool(tcp.fin),                    # finish flag
        header=segment[:hdr_len],             # raw bytes type header
        payload=bytearray(payload),           # raw bytearray type payload
        first=tcp.seqnum,                     # first sequence number of payload
        last=tcp.seqnum + len(payload) - 1,   # last sequence number of payload
        len=len(payload),                     # payload length, header excludes
        timestamp=packet2timestamp(packet),   # capture timestamp
    )


def tcp_traceflow(packet: 'Packet', *, data_link: 'Enum_LinkType',
                  count: 'int' = -1) -> 'TF_TCP_Packet | None':
    """Trace packet flow for TCP.

    Args:
        packet: PyPCAPFile packet.
        data_link: Data link layer protocol (from the savefile header).
        count: Packet index. If not provided, default to ``-1``.

    Returns:
        Data for TCP flow tracing.

        * If the ``packet`` can be used for TCP flow tracing. A packet can be traced
          if it contains an IPv4 layer carrying a TCP segment, behind 802.1Q or 802.1ad
          VLAN tags or not; TCP over IPv6 cannot be, as `PyPCAPFile`_ has no IPv6 decoder,
          and nor can TCP tunnelled in IP, as it decodes no tunnel.
        * If the ``packet`` can be traced, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    Warns:
        AttributeWarning: If ``packet`` carries TCP over IPv6, or tunnelled in IP,
            which is left out, and is the first such frame of its capture to
            reach either :func:`tcp_reassembly` or :func:`tcp_traceflow`. The
            rest of that capture's such frames are left out without another
            warning; each of the two kinds warns once of its own.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    ipv4 = _network(packet, count)
    if ipv4 is None or (segment := _transport(ipv4)) is None:
        _decline_tcp(packet, ipv4, count)
        return None

    # NOTE: imported only once there is something to decode, so that declining a
    # frame does not require ``pcapfile`` to be installed.
    from pcapfile.protocols.transport.tcp import TCP  # isort:skip

    tcp = TCP(segment)
    hdr_len = max(tcp.data_offset, TCP_MIN_HEADER_LEN)
    return TF_TCP_Packet(  # type: ignore[type-var]
        protocol=data_link,                                 # data link type from savefile header
        index=count,                                        # frame number
        frame=packet2dict(packet, data_link=data_link),     # extracted packet
        syn=bool(tcp.syn),                                  # TCP synchronise (SYN) flag
        fin=bool(tcp.fin),                                  # TCP finish (FIN) flag
        rst=bool(tcp.rst),                                  # TCP reset (RST) flag
        src=_parse_ipv4_address(ipv4.src),                  # source IP
        dst=_parse_ipv4_address(ipv4.dst),                  # destination IP
        srcport=tcp.src_port,                               # TCP source port
        dstport=tcp.dst_port,                               # TCP destination port
        timestamp=packet2timestamp(packet),                 # timestamp
        seq=tcp.seqnum,                                     # TCP sequence number
        ack=tcp.acknum,                                     # TCP acknowledgement number
        header=segment[:hdr_len],                           # raw bytes type header
        payload=bytearray(segment[hdr_len:]),               # raw bytearray type payload
    )
