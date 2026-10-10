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
   over IPv4 only, and decline a frame carrying TCP over IPv6 -- TCP whose
   innermost IP layer is IPv6, tunnelled in IP (e.g. 6in4, 6in6) or not. That
   loss is not silent: it is reported with one
   :exc:`~pcapkit.utilities.warnings.AttributeWarning` per capture, on its first
   such frame, rather than one per frame.

   `PyPCAPFile`_ decodes no VLAN tag either, so :func:`_network` reads past the
   802.1Q and 802.1ad tags the default engine steps over (see
   :data:`VLAN_TAGS`), however deeply stacked, and decodes the IPv4 packet
   behind them with `PyPCAPFile`_'s own decoder. TCP and IPv4 reassembly and TCP
   flow tracing therefore see a tagged IPv4 frame as they see an untagged one.
   Nor does it decode a tunnel, so :func:`_innermost` steps through the IPv4
   and IPv6 packets carried in IP (e.g. 4in4, 4in6) to the innermost, and
   decodes it with the same decoder if it is IPv4: the TCP it carries is read
   and keyed by its addresses, as the default engine keys it, not by the
   tunnel's (:issue:`1581`). The warning follows the default engine's own rules
   for where it finds TCP, read off the raw headers (see :func:`_upper_layer`).
   IPv4 carried in IPv6 (4in6) also reaches :func:`ipv4_reassembly`, which the
   default engine gives the first IPv4 layer of a frame (see
   :func:`_ipv4_in_ipv6`), and TCP behind AH or an IPv6 extension header inside
   IPv4 is read past them (see :func:`_transport`).

   `PyPCAPFile`_ checks neither that an IPv4 header was captured whole nor its
   options, and the default engine rejects a header that fails either check, so
   such a header is left out of reassembly and flow tracing alike (see
   :func:`_ipv4_accepted`).

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
import functools
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
from pcapkit.protocols.internet.ipv4 import IPv4 as Protocol_IPv4
from pcapkit.protocols.schema.internet.ipv6 import jumbo_payload_length
from pcapkit.protocols.transport.tcp import TCP as Protocol_TCP
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

#: Length of the fixed part of an IP Authentication Header (AH), before its
#: Integrity Check Value, :rfc:`4302#section-2`. A Payload Length of ``0``
#: declares a shorter header, which the default engine rejects.
AH_HEADER_LEN = 12

#: IP protocol numbers of the headers :func:`_past_extension_headers` reads
#: past inside IPv4, on to the protocol each one's Next Header field names, as
#: the default engine does: it dispatches IPv4's protocol through the registry
#: IPv6 uses (:attr:`Internet.__proto__
#: <pcapkit.protocols.internet.internet.Internet.__proto__>`), and each of these
#: parsers then decodes what its Next Header names. That is AH and the IPv6
#: Hop-by-Hop Options, Routing, Fragment, Destination Options, Mobility and HIP
#: headers. ESP is left out, as its Next Header is encrypted, and Shim6, whose
#: parser refuses IPv4.
IPV4_EXTENSION_HEADERS = frozenset((
    Enum_TransType.HOPOPT, Enum_TransType.IPv6_Route, Enum_TransType.IPv6_Frag,
    Enum_TransType.AH, Enum_TransType.IPv6_Opts, Enum_TransType.Mobility_Header,
    Enum_TransType.HIP,
))

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
#: :func:`_left_out` finds this engine cannot read. TCP tunnelled in IP is no
#: kind of its own: the innermost IP layer carrying it is read if it is IPv4,
#: and is TCP over IPv6 otherwise (see :func:`_innermost`, :issue:`1581`).
TCP_LEFT_OUT = {
    'ipv6': "TCP over IPv6 is left out of TCP reassembly and flow tracing, as 'pypcapfile' "
            'has no IPv6 decoder',
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


@functools.lru_cache(maxsize=2)
def _default_accepts(name: 'str', header: 'bytes') -> 'bool':
    """Test if the default engine's parser accepts a header.

    Args:
        name: ``'IPv4'`` or ``'TCP'``, the parser to ask.
        header: The whole header, options included, and nothing after it.

    Returns:
        :data:`False` if the parser raises anything at all, as the default
        engine then leaves the layer undissected (see
        :func:`~pcapkit.utilities.decorators.beholder`); else :data:`True`.

    Note:
        This is for the options, whose rules are the parser's and too many for
        a header walk to follow, so it is asked only of a header that has some.
        It is given the header alone and stops at its own layer, so nothing
        past the header is dissected. What the parser logs and warns of, a
        rejected header's :exc:`~pcapkit.utilities.exceptions.ProtocolError`
        included, it logs and warns of as it does when the default engine reads
        the same frame; neither the warnings filters nor the logger's level are
        changed. The answer depends on the octets alone, so the last two are
        remembered: the adapters each fetch a frame's layers in turn, and this
        parses a frame's IPv4 and TCP headers once each between them.

    """
    protocol = Protocol_IPv4 if name == 'IPv4' else Protocol_TCP
    try:
        protocol(header, len(header), protocol=name)
    except Exception:  # as beholder does
        return False
    return True


def _ipv4_accepted(ipv4: 'IP') -> 'bool':
    """Test if the default engine reads a PyPCAPFile IPv4 packet as an IPv4 layer.

    Args:
        ipv4: PyPCAPFile IPv4 packet.

    Returns:
        :data:`False` if its header length (IHL) runs past the captured octets
        (:issue:`1591`), or its options are ones the default engine's IPv4
        parser rejects (:issue:`1596`); else :data:`True`.

    Note:
        `PyPCAPFile`_ slices the header at its IHL however few octets there
        are, and never checks the options. A header with none is not parsed:
        all the default engine checks of one is that it is version 4, with an
        IHL of at least 5 and 20 octets captured, and `PyPCAPFile`_'s decoder
        refuses any other.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    if ipv4.hl * 4 == IPV4_HEADER_LEN:
        return True
    options = _maybe_unhex(bytes(ipv4.opt))
    if IPV4_HEADER_LEN + len(options) < ipv4.hl * 4:
        return False
    return _default_accepts('IPv4', ipv4_header(ipv4))


def _network(packet: 'Packet', count: 'int' = -1) -> 'Optional[IP]':
    """Fetch the decoded IPv4 layer of a PyPCAPFile packet, if any.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index, for the warning below.

    Returns:
        The decoded :class:`~pcapfile.protocols.network.ip.IP` layer, or
        :data:`None` when the frame was not decoded that far -- which is the
        case for every non-IPv4 frame, `PyPCAPFile`_ having no other network
        layer decoder -- or the default engine rejects its header (see
        :func:`_ipv4_accepted`).

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
        return payload if _ipv4_accepted(payload) else None
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
        ipv4 = IP(untagged[1], 0)
    except (struct.error, AssertionError, ValueError, IndexError, KeyError) as error:
        key, anchor = _capture_of(packet)
        if not _undecoded_last or _undecoded_last[0][:2] != (key, count):
            _undecoded_last.append((key, count, anchor))
            warn(f'Frame {count}: {Enum_LinkType.ETHERNET!r} decoding failed ({error!r}); '
                 'frame left undecoded', AttributeWarning, stacklevel=stacklevel())
        return None
    return ipv4 if _ipv4_accepted(ipv4) else None


def _ipv4_in_ipv6(packet: 'Packet') -> 'Optional[IP]':
    """Fetch the IPv4 layer of a PyPCAPFile frame carrying IPv4 in IPv6 (4in6).

    Args:
        packet: PyPCAPFile packet.

    Returns:
        The first IPv4 packet inside an IPv6 packet -- directly, behind
        extension headers, or inside more IPv6 (6in6) -- decoded as
        :func:`_network` decodes one behind VLAN tags, or :data:`None` if there
        is none, it will not decode, or the default engine rejects its header
        (see :func:`_ipv4_accepted`). The frame may be tagged (see
        :func:`_untag`), and each IPv6 header is stepped over as
        :func:`_upper_layer` does.

    Note:
        `PyPCAPFile`_ has no IPv6 decoder, so leaves the IPv4 inside undecoded.
        This is for :func:`ipv4_reassembly` alone, which the default engine
        gives the first IPv4 layer of a frame however deep; TCP is keyed by the
        innermost instead (see :func:`_innermost`). Nor does an IPv4 packet that
        will not decode warn: `PyPCAPFile`_ never decodes IPv6, so has nothing
        to warn of.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    link = packet.packet
    untagged = None if _is_raw(link) else _untag(link)
    if untagged is None or untagged[0] != Enum_EtherType.Internet_Protocol_version_6:
        return None

    upper = _upper_layer(6, untagged[1])
    while upper is not None and upper[0] == Enum_TransType.IPv6:
        upper = _upper_layer(6, upper[1])
    if upper is None or upper[0] != Enum_TransType.IPv4:
        return None
    return _decode_ipv4(upper[1])


def _decode_ipv4(data: 'bytes') -> 'Optional[IP]':
    """Decode an IPv4 packet that `PyPCAPFile`_ left undecoded inside another IP packet.

    Args:
        data: Raw octets from the IPv4 header on, as far as the IP packet
            carrying it goes (see :func:`_upper_layer`).

    Returns:
        The packet, decoded as :func:`_network` decodes one behind VLAN tags, or
        :data:`None` if it will not decode or the default engine rejects its
        header (see :func:`_ipv4_accepted`), which then dissects nothing past it.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    # NOTE: imported only once there is something to decode, as in :func:`_network`.
    from pcapfile.protocols.network.ip import IP  # isort:skip

    try:
        ipv4 = IP(data, 0)
    except (struct.error, AssertionError, ValueError, IndexError, KeyError):
        return None
    return ipv4 if _ipv4_accepted(ipv4) else None


@functools.lru_cache(maxsize=8)
def _default_extension_header(protocol: 'int', data: 'bytes') -> 'Optional[tuple[int, int]]':
    """Read an extension header inside IPv4 with the default engine's own parser.

    Args:
        protocol: The header's protocol number, one of
            :data:`IPV4_EXTENSION_HEADERS` other than AH.
        data: Raw octets from the header on, as far as the IPv4 packet goes.

    Returns:
        The header's Next Header field and its length, or :data:`None` if the
        default engine leaves it undissected: its parser raises anything at
        all (see :func:`~pcapkit.utilities.decorators.beholder`), or fewer
        octets were captured than the header needs.

    Note:
        The parser is the one the default engine dispatches ``protocol`` to
        inside IPv4, called as it calls it, so its options, routing data,
        message or parameters are checked as the default engine checks them.
        It stops at its own layer, so nothing past the header is dissected, and
        the last few answers are remembered, as in :func:`_default_accepts`,
        which this logs and warns as.

    """
    # pylint: disable-next=protected-access
    klass = Protocol_IPv4._lookup_next_layer(Protocol_IPv4.__proto__, protocol)
    try:
        header = Protocol_IPv4._parse_next_layer(  # pylint: disable=protected-access
            klass, data, len(data), version=4, extension=False, alias=protocol, protocol=klass)
    except Exception:  # as beholder does
        return None
    nxt = getattr(header.info, 'next', None)  # none on a header cut short, read as raw octets
    if nxt is None:
        return None
    return int(nxt), header.length


def _past_extension_headers(protocol: 'int', data: 'bytes') -> 'Optional[tuple[int, bytes]]':
    """Step over the headers at the head of an IPv4 payload that the default engine reads past.

    Args:
        protocol: The IPv4 packet's protocol number.
        data: Raw octets of its payload.

    Returns:
        The protocol number after the last of the :data:`IPV4_EXTENSION_HEADERS`
        and the octets from its header on -- ``protocol`` and ``data``
        themselves if ``protocol`` is none of them -- or :data:`None` if the
        default engine leaves one of them undissected. An AH is
        ``(Payload Length + 2) * 4`` octets long (:rfc:`4302#section-2.2`), and
        no shorter than :data:`AH_HEADER_LEN`; any other is read by
        :func:`_default_extension_header` (:issue:`1597`).

    Note:
        Inside IPv4, the default engine decodes what an IPv6 Fragment header
        names whatever its offset, so a later fragment is read past too. Over
        IPv6, :func:`_upper_layer` steps over these as the extension headers
        they are there.

    """
    while protocol in IPV4_EXTENSION_HEADERS:
        if protocol == Enum_TransType.AH:
            length = (data[1] + 2) * 4 if len(data) >= AH_HEADER_LEN else 0
            if length < AH_HEADER_LEN or len(data) < length:
                return None
            protocol, data = data[0], data[length:]
            continue
        header = _default_extension_header(protocol, data)
        if header is None:
            return None
        protocol, data = header[0], data[header[1]:]
    return protocol, data


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
        it ends at its Total Length, as in :func:`_ipv4_payload`, and is
        followed past the headers :func:`_past_extension_headers` steps over.
        An IPv6 packet ends at its Payload Length or, where that is ``0``, at the Jumbo Payload
        Length a jumbogram's Hop-by-Hop Options header gives (:rfc:`2675`) --
        lacking one, it has no payload -- and is followed past the extension headers in
        :data:`IPV6_EXTENSION_HEADERS`; a first fragment is read past its
        Fragment header as if that header were not there. A later fragment of
        either has no upper-layer header, since from its offset on it carries a
        slice of the payload (:rfc:`791#section-3.2`, :rfc:`8200#section-4.5`).
        Nor does a truncated header or header chain.

    Note:
        Each of these rules is the default engine's own, as are the ones
        :func:`_left_out` applies to the TCP header, so that :func:`_innermost`
        stops at the IP layer the default engine finds TCP in, and the warning
        :func:`_decline_tcp` gives fires on the frames it finds TCP over IPv6 in.
        This reads only as far as the upper-layer protocol number and decodes
        nothing, so it does not see an IPv6 extension header option the default
        engine rejects, which leaves the header raw. Every IPv4 header on the
        way is checked by :func:`_innermost` (see :func:`_ipv4_accepted`), and a
        TCP header the default engine's TCP parser rejects directly over its IP
        layer, tunnelled or not, it still reads out of the raw octets left
        behind (:func:`pcapkit.toolkit.pcap.tcp_segment`).

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
        return _past_extension_headers(data[9], data[ihl:max(total, ihl)] if total else data[ihl:])

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


def _innermost(packet: 'Packet', count: 'int' = -1) -> 'tuple[Optional[IP], Optional[tuple[int, bytes]]]':
    """Fetch the innermost IP layer of a PyPCAPFile frame, the one carrying its TCP.

    Args:
        packet: PyPCAPFile packet.
        count: Packet index, for the warning :func:`_network` gives.

    Returns:
        The innermost IPv4 packet and :data:`None`, if the innermost IP layer is
        IPv4; :data:`None` and the upper-layer protocol and octets of the
        innermost IPv6 packet, as :func:`_upper_layer` gives them, if it is
        IPv6; otherwise neither.

        The outermost IP layer is the IPv4 packet :func:`_network` fetches, or
        an IPv6 packet, behind VLAN tags (see :func:`_untag`) or not. Each IPv4
        or IPv6 packet one of them carries in the :data:`IP_TUNNELS`, directly
        or behind the headers :func:`_upper_layer` steps over, is the next, as
        deep as they go. An IPv4 packet in a tunnel is decoded by
        :func:`_decode_ipv4`, and one it does not decode ends the walk with
        neither, as the default engine then dissects no TCP past it.

    Note:
        The default engine keys a TCP segment by the IP layer nearest above it
        (:func:`pcapkit.toolkit.pcap.tcp_segment`), which in a tunnel is the
        innermost, so the TCP endpoints are its addresses and not the tunnel's
        (:issue:`1581`).

    """
    ipv4 = _network(packet, count)
    if ipv4 is not None:
        # a later fragment has no upper-layer header, see ``_upper_layer``
        if (ipv4.off or (ipv4.p not in IP_TUNNELS and ipv4.p not in IPV4_EXTENSION_HEADERS)
                or not _is_raw(ipv4.payload)):
            return ipv4, None
        upper = _past_extension_headers(ipv4.p, _ipv4_payload(ipv4))  # type: Optional[tuple[int, bytes]]
    else:
        link = packet.packet
        untagged = None if _is_raw(link) else _untag(link)
        if untagged is None or untagged[0] != Enum_EtherType.Internet_Protocol_version_6:
            return None, None
        upper = _upper_layer(6, untagged[1])

    while upper is not None and upper[0] in IP_TUNNELS:
        version, data = IP_TUNNELS[upper[0]], upper[1]
        upper = _upper_layer(version, data)
        if version == 6:
            ipv4 = None
        elif (ipv4 := _decode_ipv4(data)) is None:
            return None, None
    if ipv4 is not None:
        return ipv4, None
    return None, upper


def _left_out(upper: 'Optional[tuple[int, bytes]]') -> 'Optional[str]':
    """Name the TCP a PyPCAPFile frame carries that this engine cannot read.

    Args:
        upper: The upper-layer protocol and octets of the frame's innermost IP
            layer, if that is IPv6, as :func:`_innermost` gives them.

    Returns:
        ``'ipv6'`` if they are a TCP header, i.e. the frame carries TCP over
        IPv6, directly or behind extension headers, tunnelled in IP or not;
        otherwise :data:`None`. An ESP payload cannot be seen into, so does not
        count.

        The TCP header has to be at least :data:`TCP_MIN_HEADER_LEN` octets
        long, as its Data Offset gives it, with that many captured. The rest of
        the header need not be: the default engine's TCP parser rejects one cut
        short, e.g. by the snapshot length, and then reads the segment out of
        the raw octets left behind (:func:`pcapkit.toolkit.pcap.tcp_segment`,
        :issue:`1518`).

    """
    if upper is None or upper[0] != Enum_TransType.TCP:
        return None
    segment = upper[1]
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None
    if (segment[12] >> 4) * 4 < TCP_MIN_HEADER_LEN:  # the Data Offset, in octets
        return None
    return 'ipv6'


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


def _decline_tcp(packet: 'Packet', upper: 'Optional[tuple[int, bytes]]', count: 'int') -> 'None':
    """Warn that a frame carrying TCP this engine cannot read is left out.

    Args:
        packet: PyPCAPFile packet, which :func:`_transport` found no TCP segment in.
        upper: The upper-layer protocol and octets of its innermost IP layer, if
            that is IPv6, as :func:`_innermost` gives them.
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
    kind = _left_out(upper)
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
        :func:`_ipv4_payload`), directly or behind AH or IPv6 extension headers
        (see :func:`_past_extension_headers`, :issue:`1593`, :issue:`1597`), or
        :data:`None` if the packet does
        not carry a TCP header the default engine reads. A later fragment
        carries none: from its offset on, its data is a slice of the datagram's
        payload, with no upper-layer header in it (:rfc:`791#section-3.2`,
        :issue:`1576`). Nor does a segment too short for a header, or whose Data
        Offset is below 5 words (:issue:`1590`).

        Behind those, the default engine reads TCP only as its TCP parser does, so
        the whole of the header its Data Offset gives must be there, and any
        options must be ones that parser accepts (see
        :func:`_default_accepts`). Directly over IPv4 it reads a header the
        parser rejects out of the raw octets left behind instead
        (:func:`pcapkit.toolkit.pcap.tcp_segment`, :issue:`1518`).

    """
    if (ipv4.p != Enum_TransType.TCP and ipv4.p not in IPV4_EXTENSION_HEADERS) or ipv4.off:
        return None
    if not _is_raw(ipv4.payload):
        return None

    upper = _past_extension_headers(ipv4.p, _ipv4_payload(ipv4))
    if upper is None or upper[0] != Enum_TransType.TCP:
        return None
    segment = upper[1]
    if len(segment) < TCP_MIN_HEADER_LEN:
        return None
    header = (segment[12] >> 4) * 4  # the Data Offset, in octets
    if header < TCP_MIN_HEADER_LEN:
        return None
    if ipv4.p != Enum_TransType.TCP and (header > len(segment) or (
            header > TCP_MIN_HEADER_LEN and not _default_accepts('TCP', segment[:header]))):
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
          802.1Q or 802.1ad VLAN tags or not, and the **DF** flag is :data:`False`. The
          layer is the first IPv4 packet of the frame, as for the default engine: one
          carried in IPv6 counts (see :func:`_ipv4_in_ipv6`), and one whose header the
          default engine rejects does not (see :func:`_ipv4_accepted`).
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
        ipv4 = _ipv4_in_ipv6(packet)
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
          if it contains an IPv4 layer carrying a TCP segment, directly or behind AH or
          IPv6 extension headers, and behind 802.1Q or 802.1ad VLAN tags or not (see
          :func:`_transport`). In an IP-in-IP tunnel the IPv4 layer is the innermost
          IP layer, whose addresses key the segment (see :func:`_innermost`); TCP over
          IPv6, tunnelled or not, cannot be, as `PyPCAPFile`_ has no IPv6 decoder.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    Warns:
        AttributeWarning: If ``packet`` carries TCP over IPv6, tunnelled in IP or
            not, which is left out, and is the first such frame of its capture to
            reach either :func:`tcp_reassembly` or :func:`tcp_traceflow`. The
            rest of that capture's such frames are left out without another
            warning.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    ipv4, upper = _innermost(packet, count)
    if ipv4 is None or (segment := _transport(ipv4)) is None:
        _decline_tcp(packet, upper, count)
        return None

    # NOTE: imported only once there is something to decode, so that declining a
    # frame does not require ``pcapfile`` to be installed.
    from pcapfile.protocols.transport.tcp import TCP  # isort:skip

    tcp = TCP(segment)
    hdr_len = tcp.data_offset  # at least TCP_MIN_HEADER_LEN, see ``_transport``
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
          if it contains an IPv4 layer carrying a TCP segment, directly or behind AH or
          IPv6 extension headers, and behind 802.1Q or 802.1ad VLAN tags or not (see
          :func:`_transport`). In an IP-in-IP tunnel the IPv4 layer is the innermost
          IP layer, whose addresses key the segment (see :func:`_innermost`); TCP over
          IPv6, tunnelled or not, cannot be, as `PyPCAPFile`_ has no IPv6 decoder.
        * If the ``packet`` can be traced, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    Warns:
        AttributeWarning: If ``packet`` carries TCP over IPv6, tunnelled in IP or
            not, which is left out, and is the first such frame of its capture to
            reach either :func:`tcp_reassembly` or :func:`tcp_traceflow`. The
            rest of that capture's such frames are left out without another
            warning.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    ipv4, upper = _innermost(packet, count)
    if ipv4 is None or (segment := _transport(ipv4)) is None:
        _decline_tcp(packet, upper, count)
        return None

    # NOTE: imported only once there is something to decode, so that declining a
    # frame does not require ``pcapfile`` to be installed.
    from pcapfile.protocols.transport.tcp import TCP  # isort:skip

    tcp = TCP(segment)
    hdr_len = tcp.data_offset  # at least TCP_MIN_HEADER_LEN, see ``_transport``
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
