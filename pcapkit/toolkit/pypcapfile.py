# -*- coding: utf-8 -*-
"""PyPCAPFile Tools
=====================

.. module:: pcapkit.toolkit.pypcapfile

:mod:`pcapkit.toolkit.pypcapfile` contains all you need for
:mod:`pcapkit` handy usage with `PyPCAPFile`_ engine. All reforming
functions returns with a flag to indicate if usable for
its caller.

.. _PyPCAPFile: https://github.com/kisom/pypcapfile

.. important::

   `PyPCAPFile`_ decodes Ethernet, IPv4, TCP and UDP and nothing else -- there
   is no IPv6 decoder at all. :func:`ipv6_reassembly` therefore cannot be
   implemented and raises :exc:`~pcapkit.utilities.exceptions.UnsupportedCall`
   instead of quietly returning :data:`None`, which would be indistinguishable
   from "this frame carries no IPv6 fragment".

   Note also that `PyPCAPFile`_ decoders *replace* the payload bytes of the layer
   they decode. :class:`~pcapkit.foundation.engines.pypcapfile.PyPCAPFile` therefore
   stops at the network layer, which keeps the transport segment verbatim so that
   the header/payload split this module reports is exact. The transport header is
   decoded on demand below, using `PyPCAPFile`_'s own
   :class:`~pcapfile.protocols.transport.tcp.TCP` class rather than a
   reimplementation.

"""
import binascii
import ipaddress
import struct
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.foundation.reassembly.data.ip import Packet as IP_Packet
from pcapkit.foundation.reassembly.data.tcp import Packet as TCP_Packet
from pcapkit.foundation.traceflow.data.tcp import Packet as TF_TCP_Packet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any, Optional

    from pcapfile.protocols.network.ip import IP
    from pcapfile.structs import pcap_packet as Packet

    from pcapkit.const.reg.linktype import LinkType as Enum_LinkType

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
        Anything that is not :obj:`bytes` is rejected outright: an earlier
        revision also accepted a plain :obj:`int`, kept only because this
        module's own unit test stand-ins modelled the field that way --
        which meant production had been widened specifically to keep a
        fixture passing that was hiding this very defect, so the stand-ins
        were changed to use dotted-decimal :obj:`bytes` instead and the
        ``int`` case was dropped.

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


def _network(packet: 'Packet') -> 'Optional[IP]':
    """Fetch the decoded IPv4 layer of a PyPCAPFile packet, if any.

    Args:
        packet: PyPCAPFile packet.

    Returns:
        The decoded :class:`~pcapfile.protocols.network.ip.IP` layer, or
        :data:`None` when the frame was not decoded that far -- which is the
        case for every non-IPv4 frame, `PyPCAPFile`_ having no other network
        layer decoder.

    .. _PyPCAPFile: https://github.com/kisom/pypcapfile

    """
    link = packet.packet
    if _is_raw(link):
        return None

    payload = getattr(link, 'payload', None)
    if type(payload).__name__ != 'IP':
        return None
    return payload


def _transport(ipv4: 'IP') -> 'Optional[bytes]':
    """Fetch the verbatim TCP segment carried by a PyPCAPFile IPv4 packet.

    Args:
        ipv4: PyPCAPFile IPv4 packet.

    Returns:
        The raw TCP segment, or :data:`None` if the packet does not carry a
        TCP payload long enough to hold a header.

    """
    if ipv4.p != Enum_TransType.TCP:
        return None

    segment = ipv4.payload
    if not _is_raw(segment):
        return None

    segment = _maybe_unhex(bytes(segment))
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
          if it contains an IPv4 layer (:class:`pcapfile.protocols.network.ip.IP`) and the
          **DF** flag is :data:`False`.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for IPv4
          reassembly (:term:`reasm.ipv4.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    See Also:
        :class:`pcapkit.foundation.reassembly.ipv4.IPv4`

    """
    ipv4 = _network(packet)
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
          if it contains an IPv4 layer carrying a TCP segment.
        * If the ``packet`` can be reassembled, then the :obj:`dict` mapping of data for TCP
          reassembly (:term:`reasm.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    See Also:
        :class:`pcapkit.foundation.reassembly.tcp.TCP`

    """
    ipv4 = _network(packet)
    if ipv4 is None:
        return None

    segment = _transport(ipv4)
    if segment is None:
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
        first=tcp.seqnum,                     # this sequence number
        last=tcp.seqnum + len(payload),       # next (wanted) sequence number
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
          if it contains an IPv4 layer carrying a TCP segment.
        * If the ``packet`` can be traced, then the :obj:`dict` mapping of data for TCP
          flow tracing (:term:`trace.tcp.packet`) will be returned; otherwise, returns :data:`None`.

    Raises:
        ProtocolError: If ``ipv4.src`` or ``ipv4.dst`` cannot be parsed as an
            IPv4 address.

    See Also:
        :class:`pcapkit.foundation.traceflow.tcp.TCP`

    """
    ipv4 = _network(packet)
    if ipv4 is None:
        return None

    segment = _transport(ipv4)
    if segment is None:
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
