"""Unit tests for :mod:`pcapkit.toolkit.pypcapfile`.

The adapters that only walk decoded layers are tested against stand-ins, so they
run without `pypcapfile`_ installed. The ones that reconstruct or re-split raw
bytes -- :func:`~pcapkit.toolkit.pypcapfile.ipv4_header`,
:func:`~pcapkit.toolkit.pypcapfile.tcp_reassembly` and
:func:`~pcapkit.toolkit.pypcapfile.tcp_traceflow` -- are tested against
`pypcapfile`_'s real decoders and real packet bytes, because "byte-exact" is the
claim being made and a stand-in cannot check it.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""
from __future__ import annotations

import binascii
import ctypes
import importlib.util
import ipaddress
import os
import struct
import tempfile
import types
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class
from tests.foundation import _roundtrip as wire

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


def _has_pypcapfile() -> bool:
    """Test if :mod:`pcapfile` is importable.

    A plain :func:`importlib.util.find_spec` is not enough: the released
    ``pypcapfile`` 0.12.0 imports the :mod:`imp` module, which was removed in
    Python 3.12, so the distribution can be present and still unusable.

    """
    try:
        importlib.import_module('pcapfile.savefile')
        importlib.import_module('pcapfile.protocols.transport.tcp')
    except ImportError:
        return False
    return True


HAS_PYPCAPFILE = _has_pypcapfile()


def make_ipv4(payload: bytes, *, src: str = '10.1.1.2', dst: str = '10.1.1.3',
              protocol: int = 6, ident: int = 4660, flags: int = 0, offset: int = 0,
              options: bytes = b'') -> bytes:
    """Build a raw IPv4 packet, options included."""
    assert len(options) % 4 == 0, 'IPv4 options must be a whole number of words'
    ihl = 5 + len(options) // 4
    header = struct.pack(
        '!BBHHHBBHII',
        (4 << 4) | ihl,
        0x10,
        20 + len(options) + len(payload),
        ident,
        (flags << 13) | offset,
        64,
        protocol,
        0xBEEF,
        int(ipaddress.IPv4Address(src)),
        int(ipaddress.IPv4Address(dst)),
    ) + options
    return header + payload


def make_tcp(payload: bytes, *, src_port: int = 51000, dst_port: int = 22,
             seq: int = 1000, ack: int = 2000, flags: int = 0x12,
             options: bytes = b'') -> bytes:
    """Build a raw TCP segment, options included."""
    assert len(options) % 4 == 0, 'TCP options must be a whole number of words'
    offset = 5 + len(options) // 4
    header = struct.pack('!HHIIBBHHH', src_port, dst_port, seq, ack,
                         offset << 4, flags, 8192, 0xCAFE, 0) + options
    return header + payload


class FakeIP:
    """Stand-in for :class:`pcapfile.protocols.network.ip.IP`."""

    # NOTE: the class must be *named* ``IP``, since that is how the toolkit
    # recognises a decoded network layer.
    def __init__(self, payload, **fields) -> None:
        self.v = 4
        self.hl = 5
        self.tos = 0x10
        self.len = 20 + (len(payload) if isinstance(payload, bytes) else 0)
        self.id = 4660
        self.flags = 0
        self.off = 0
        self.ttl = 64
        self.p = 6
        self.sum = 0xBEEF
        # Dotted-decimal ASCII bytes, PyPCAPFile 0.12.0's actual ``IP.src``/``.dst``
        # form (see GH#743) -- not an ``int``, so this stand-in exercises the same
        # parsing path the real decoder does instead of hiding behind a shortcut.
        self.src = b'10.1.1.2'
        self.dst = b'10.1.1.3'
        self.opt = b''
        self.payload = payload
        self.__dict__.update(fields)


FakeIP.__name__ = 'IP'
FakeIP.__qualname__ = 'IP'


class FakeEthernet:
    """Stand-in for :class:`pcapfile.protocols.linklayer.ethernet.Ethernet`."""

    def __init__(self, payload) -> None:
        self.dst = bytearray(b'\x40\x33\x1a\xd1\x85\x1c')
        self.src = bytearray(b'\xa4\x5e\x60\xd9\x6b\x97')
        self.type = 0x0800
        self.payload = payload


FakeEthernet.__name__ = 'Ethernet'
FakeEthernet.__qualname__ = 'Ethernet'


def make_packet(layer, *, timestamp: int = 1511106545, timestamp_us: int = 471719,
                ns_resolution: bool = False, capture_len: int = 86, packet_len: int = 86):
    """Build a stand-in for :class:`pcapfile.structs.pcap_packet`."""
    return types.SimpleNamespace(
        header=[types.SimpleNamespace(ns_resolution=ns_resolution)],
        timestamp=timestamp,
        timestamp_us=timestamp_us,
        capture_len=capture_len,
        packet_len=packet_len,
        packet=layer,
    )


def ipv6_frame(packet: bytes) -> FakeEthernet:
    """An Ethernet frame carrying IPv6, as PyPCAPFile leaves it: payload hex-encoded."""
    frame = FakeEthernet(binascii.hexlify(packet))
    frame.type = 0x86DD
    return frame


#: A TCP segment with a full header and a payload.
TCP_SEGMENT = wire.tcp(b'payload', seq=1, syn=True)

#: An IPv6 jumbogram carrying :data:`TCP_SEGMENT`: a Payload Length of 0, and a
#: Hop-by-Hop Options header whose Jumbo Payload option gives the real one (RFC 2675).
JUMBOGRAM = (wire.ipv6(b'', nxt=0)
             + bytes([6, 0, 0xC2, 4]) + (8 + len(TCP_SEGMENT)).to_bytes(4, 'big') + TCP_SEGMENT)

#: TPIDs of the 802.1Q customer tag and the 802.1ad service tag.
C_TAG, S_TAG = 0x8100, 0x88A8


def vlan_tags(ethertype: int, *tpids: int) -> bytes:
    """The octets after the first TPID of an Ethernet frame tagged once per ``tpids``.

    That is, each tag's control information and the EtherType after it -- the
    next tag's TPID, or ``ethertype`` after the last tag.

    """
    return b''.join((100 + number).to_bytes(2, 'big') + kind.to_bytes(2, 'big')
                    for number, kind in enumerate((*tpids[1:], ethertype)))


def tagged(packet: bytes, ethertype: int, *tpids: int) -> bytes:
    """A raw Ethernet frame carrying ``packet`` behind one VLAN tag per ``tpids``."""
    return wire.ethernet(vlan_tags(ethertype, *tpids) + packet, tpids[0])


def tagged_frame(packet: bytes, ethertype: int, *tpids: int) -> FakeEthernet:
    """A tagged frame as PyPCAPFile leaves it: type the first TPID, payload hex-encoded."""
    frame = FakeEthernet(binascii.hexlify(vlan_tags(ethertype, *tpids) + packet))
    frame.type = tpids[0]
    return frame


def fake_ip_decoder() -> dict[str, types.ModuleType]:
    """Stand-in modules for :mod:`pcapfile.protocols.network.ip`, for :data:`sys.modules`.

    Their ``IP`` records what it was given, and refuses what is not an IPv4
    header of at least 20 octets as the real decoder does.

    """
    class IP:
        """Stand-in for :class:`pcapfile.protocols.network.ip.IP`."""

        calls: list = []

        def __init__(self, packet: bytes, layers: int = 0) -> None:
            self.calls.append((packet, layers))
            if packet[0] >> 4 != 4 or packet[0] & 0x0F <= 4:
                raise AssertionError('not an IPv4 packet.')
            struct.unpack('!BBHHHBBHII', packet[:20])
            # the header length and options, sliced without a bounds check, as the real one does
            self.hl = packet[0] & 0x0F
            self.opt = packet[20:self.hl * 4]

    modules = {name: types.ModuleType(name) for name in (
        'pcapfile', 'pcapfile.protocols', 'pcapfile.protocols.network',
        'pcapfile.protocols.network.ip')}
    modules['pcapfile.protocols.network.ip'].IP = IP
    return modules


def data_offset(segment: bytes, words: int) -> bytes:
    """``segment``, a TCP segment, with its Data Offset set to ``words``."""
    return segment[:12] + bytes([words << 4 | segment[12] & 0x0F]) + segment[13:]


def total_length(packet: bytes, value: int) -> bytes:
    """``packet``, an IPv4 packet with no options, with its Total Length set to ``value``."""
    header = bytearray(packet[:20])
    header[2:4], header[10:12] = value.to_bytes(2, 'big'), b'\x00\x00'
    header[10:12] = wire.checksum(bytes(header)).to_bytes(2, 'big')
    return bytes(header) + packet[20:]


def tunnel(packet: bytes, protocol: int, **fields) -> FakeEthernet:
    """An IPv4 frame tunnelling ``packet``, as PyPCAPFile decodes it: payload hex-encoded."""
    return FakeEthernet(FakeIP(binascii.hexlify(packet), p=protocol, **fields))


#: IPv4 options the default engine's IPv4 parser rejects: a Record Route of
#: length 1, one whose length runs past the option area, and a Router Alert of
#: length 2.
BAD_IPV4_OPTIONS = (b'\x07\x01\x00\x00', b'\x07\x08\x00\x00', b'\x94\x02\x00\x00')

#: IPv4 options it accepts: four No Operations, a Router Alert, and an End of
#: Option List followed by octets it leaves as padding.
GOOD_IPV4_OPTIONS = (b'\x01' * 4, b'\x94\x04\x00\x00', b'\x00\xff\xff\xff')


def ah(nxt: int, words: int = 4) -> bytes:
    """An IP Authentication Header whose Payload Length is ``words``, then next header ``nxt``."""
    icv = b'\xaa' * max((words + 2) * 4 - 12, 0)
    return bytes([nxt, words, 0, 0]) + (0x100).to_bytes(4, 'big') + (1).to_bytes(4, 'big') + icv


def options_header(nxt: int, padn: bytes = b'\x01\x04\x00\x00\x00\x00') -> bytes:
    """An IPv6 Hop-by-Hop or Destination Options header of 8 octets, then next header ``nxt``."""
    return bytes([nxt, 0]) + padn


#: IPv6 extension headers the default engine reads past inside IPv4, each with
#: its protocol number, then TCP: Hop-by-Hop and Destination Options, Routing
#: (type 0, then type 2), a Fragment header (a later fragment), Mobility (a
#: Binding Refresh Request) and HIP (an I1, with no parameters).
IPV4_EXTENSION_HEADERS = (
    ('hop-by-hop', 0, options_header(6)),
    ('destination options', 60, options_header(6)),
    ('routing type 0', 43, bytes([6, 0, 0, 0]) + bytes(4)),
    ('routing type 2', 43, bytes([6, 2, 2, 1]) + bytes(20)),
    ('later fragment', 44, bytes([6, 0, 0, 0x10]) + (1).to_bytes(4, 'big')),
    ('mobility', 135, bytes([6, 1, 0, 0]) + bytes(12)),
    ('hip', 139, bytes([6, 4, 0x01, 0x21]) + bytes(36)),
)


def ihl(packet: bytes, words: int) -> bytes:
    """``packet``, an IPv4 packet, with its IHL set to ``words``."""
    return bytes([0x40 | words]) + packet[1:]


def udp_fragment(**fields) -> bytes:
    """A first IPv4 fragment of a UDP datagram, more to come."""
    return wire.ipv4(wire.udp(b'u' * 24)[:16], proto=17, mf=True, **fields)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    ##########################################################################
    # Auxiliary functions.
    ##########################################################################

    def test_packet2timestamp_honours_the_nanosecond_flag(self) -> None:
        from pcapkit.toolkit.pypcapfile import packet2timestamp

        micro = make_packet(b'raw', timestamp=1000, timestamp_us=500000)
        self.assertEqual(packet2timestamp(micro), 1000.5)

        nano = make_packet(b'raw', timestamp=1000, timestamp_us=500000000,
                           ns_resolution=True)
        self.assertEqual(packet2timestamp(nano), 1000.5)

    def test_packet2chain_walks_the_decoded_layers(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2chain

        self.assertEqual(
            packet2chain(make_packet(b'raw'), data_link=LinkType.ETHERNET),
            'ETHERNET:Raw',
        )
        self.assertEqual(
            packet2chain(make_packet(FakeEthernet(b'raw')), data_link=LinkType.ETHERNET),
            'Ethernet:Raw',
        )
        self.assertEqual(
            packet2chain(make_packet(FakeEthernet(FakeIP(b'segment'))),
                         data_link=LinkType.ETHERNET),
            'Ethernet:IP:Raw',
        )

    def test_packet2dict_reports_the_decoded_tree(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2dict

        info = packet2dict(make_packet(FakeEthernet(FakeIP(b'segment'))),
                           data_link=LinkType.ETHERNET)
        self.assertEqual(info['timestamp'], 1511106545.471719)
        self.assertEqual(info['capture_len'], 86)
        self.assertEqual(info['packet_len'], 86)

        ethernet = info['ETHERNET']
        self.assertEqual(ethernet['src'], 'a4:5e:60:d9:6b:97')
        self.assertEqual(ethernet['dst'], '40:33:1a:d1:85:1c')
        self.assertEqual(ethernet['type'], 0x0800)

        network = ethernet['IP']
        self.assertEqual(network['src'], '10.1.1.2')
        self.assertEqual(network['dst'], '10.1.1.3')
        self.assertEqual(network['p'], 6)
        self.assertEqual(network['Raw'], {'raw_len': 7, 'raw': b'segment'})

    def test_packet2dict_falls_back_to_ctypes_fields_for_unknown_layers(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2dict

        class Wifi:
            _fields_ = [('flags', None), ('missing', None)]

            def __init__(self) -> None:
                self.flags = 3
                self.payload = None

        info = packet2dict(make_packet(Wifi()), data_link=LinkType.IEEE802_11)
        self.assertEqual(info[LinkType.IEEE802_11.name], {'flags': 3, 'missing': None})

    def test_packet2dict_and_chain_tolerate_an_undecoded_frame(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2chain, packet2dict

        info = packet2dict(make_packet(b'\x01\x02'), data_link=LinkType.ETHERNET)
        self.assertEqual(info['ETHERNET'], {'raw_len': 2, 'raw': b'\x01\x02'})
        self.assertEqual(packet2chain(make_packet(bytearray(b'\x01')),
                                      data_link=LinkType.ETHERNET), 'ETHERNET:Raw')

    ##########################################################################
    # Address and hex-text parsing helpers (see GH#743).
    ##########################################################################

    def test_parse_ipv4_address_decodes_dotted_decimal_ascii_bytes(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_ipv4_address

        # PyPCAPFile 0.12.0's actual ``IP.src``/``IP.dst`` representation: a
        # ``ctypes.c_char_p`` holding dotted-decimal ASCII text, not a packed
        # 4-byte value.
        self.assertEqual(_parse_ipv4_address(b'10.1.1.2'), ipaddress.IPv4Address('10.1.1.2'))
        self.assertEqual(_parse_ipv4_address(b'255.255.255.255'),
                         ipaddress.IPv4Address('255.255.255.255'))

    def test_parse_ipv4_address_also_accepts_packed_bytes(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_ipv4_address

        # Defensive acceptance for a differently-represented PyPCAPFile release
        # or fork -- a packed 4-byte value is never a valid dotted-quad string,
        # so the two forms cannot be confused with each other.
        self.assertEqual(_parse_ipv4_address(b'\n\x01\x01\x02'),
                         ipaddress.IPv4Address('10.1.1.2'))

    def test_parse_ipv4_address_wraps_invalid_input(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_ipv4_address
        from pcapkit.utilities.exceptions import ProtocolError

        for label, value in (
            ('not an address', b'not-an-ip'),
            ('not ASCII', b'\xff\xff\xff\xff\xff'),
            ('none', None),
            # ``int`` is deliberately rejected, not merely unparsed: an earlier
            # revision accepted it only to keep ``FakeIP``'s int-typed stand-in
            # passing, which is exactly the fixture that hid GH#743 in the
            # first place. See ``_parse_ipv4_address``'s docstring.
            ('int', int(ipaddress.IPv4Address('10.1.1.2'))),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError):
                    _parse_ipv4_address(value)

    def test_maybe_unhex_decodes_hex_ascii_text(self) -> None:
        from pcapkit.toolkit.pypcapfile import _maybe_unhex

        # PyPCAPFile 0.12.0 stores ``IP.opt``/``IP.payload`` as hex-ASCII text
        # too, once decoding stops short of the transport layer -- which is
        # exactly how the PyPCAPFile engine calls it.
        self.assertEqual(_maybe_unhex(b'94040000'), b'\x94\x04\x00\x00')
        self.assertEqual(_maybe_unhex(b''), b'')

    def test_maybe_unhex_leaves_already_raw_bytes_alone(self) -> None:
        from pcapkit.toolkit.pypcapfile import _maybe_unhex

        self.assertEqual(_maybe_unhex(b'segment'), b'segment')          # odd length
        self.assertEqual(_maybe_unhex(b'\x01\x01\x01\x00'), b'\x01\x01\x01\x00')  # non-hex bytes

    def test_maybe_unhex_has_a_false_positive_on_all_hex_digit_raw_bytes(self) -> None:
        from pcapkit.toolkit.pypcapfile import _maybe_unhex

        # Documents the residual risk called out in ``_maybe_unhex``'s docstring
        # rather than a desired behaviour: this 24-byte value is a plausible raw
        # TCP header (data offset 6, NS+ACK+FIN, ports 12336/12593) whose every
        # byte happens to fall in the ASCII hex-digit range, so it is
        # indistinguishable from real hex text and gets halved.
        raw_header = b'001122223333aA4455660000'
        self.assertEqual(_maybe_unhex(raw_header), binascii.unhexlify(raw_header))
        self.assertNotEqual(_maybe_unhex(raw_header), raw_header)

    def test_parse_mac_address_decodes_colon_ascii_text(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_mac_address

        # PyPCAPFile 0.12.0's actual ``Ethernet.src``/``.dst`` representation:
        # already colon-separated ASCII hex text, not a raw 6-byte value.
        self.assertEqual(_parse_mac_address(b'01:00:5e:01:03:03'), '01:00:5e:01:03:03')

    def test_parse_mac_address_also_accepts_raw_six_bytes(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_mac_address

        # Defensive acceptance for a differently-represented PyPCAPFile release
        # or fork, and for the raw-bytes stand-ins used in this module.
        self.assertEqual(_parse_mac_address(b'\x01\x00\x5e\x01\x03\x03'), '01:00:5e:01:03:03')
        self.assertEqual(_parse_mac_address(bytearray(b'\x01\x00\x5e\x01\x03\x03')),
                         '01:00:5e:01:03:03')

    def test_parse_mac_address_wraps_invalid_input(self) -> None:
        from pcapkit.toolkit.pypcapfile import _parse_mac_address
        from pcapkit.utilities.exceptions import ProtocolError

        for label, value in (
            ('not ASCII', b'\xff\xff\xff\xff\xff'),
            ('none', None),
            ('int', 42),
        ):
            with self.subTest(case=label):
                with self.assertRaises(ProtocolError):
                    _parse_mac_address(value)

    ##########################################################################
    # Reassembly and flow tracing.
    ##########################################################################

    def test_ipv6_reassembly_refuses_loudly(self) -> None:
        from pcapkit.toolkit.pypcapfile import ipv6_reassembly
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall) as caught:
            ipv6_reassembly(make_packet(b'raw'), count=1)
        self.assertIn('no IPv6 decoder', str(caught.exception))

    def test_ipv4_reassembly_declines_undecoded_and_unfragmented_frames(self) -> None:
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        # undecoded link layer
        self.assertIsNone(ipv4_reassembly(make_packet(b'raw'), count=1))
        # decoded link layer, undecoded network layer (e.g. IPv6)
        self.assertIsNone(ipv4_reassembly(make_packet(FakeEthernet(b'raw')), count=1))
        # decoded IPv4, but the DF flag is set
        packet = make_packet(FakeEthernet(FakeIP(b'segment', flags=0b010)))
        self.assertIsNone(ipv4_reassembly(packet, count=1))

    def test_ipv4_reassembly_reports_offsets_in_octets(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        ipv4 = FakeIP(b'fragment-payload', flags=0b001, off=185, len=36)
        data = ipv4_reassembly(make_packet(FakeEthernet(ipv4)), count=7)

        self.assertIsNotNone(data)
        self.assertEqual(data.num, 7)
        self.assertEqual(data.fo, 185 * 8)
        self.assertEqual(data.ihl, 20)
        self.assertTrue(data.mf)
        self.assertEqual(data.tl, 36)
        self.assertEqual(data.payload, bytearray(b'fragment-payload'))
        self.assertEqual(data.bufid, (
            ipaddress.IPv4Address('10.1.1.2'),
            ipaddress.IPv4Address('10.1.1.3'),
            4660,
            TransType.TCP,
        ))

    def test_ipv4_reassembly_counts_options_into_the_header_length(self) -> None:
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        ipv4 = FakeIP(b'payload', flags=0b001, hl=6, opt=b'\x01\x01\x01\x00')
        data = ipv4_reassembly(make_packet(FakeEthernet(ipv4)), count=1)
        self.assertEqual(data.ihl, 24)
        self.assertEqual(len(data.header), 24)
        self.assertEqual(data.header[20:], b'\x01\x01\x01\x00')

    def test_tcp_adapters_decline_non_tcp_and_truncated_segments(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow

        for label, packet in (
            ('undecoded link', make_packet(b'raw')),
            ('undecoded network', make_packet(FakeEthernet(b'raw'))),
            ('not tcp', make_packet(FakeEthernet(FakeIP(b'x' * 40, p=17)))),
            ('too short', make_packet(FakeEthernet(FakeIP(b'short')))),
            ('already decoded', make_packet(FakeEthernet(FakeIP(object())))),
            # data from mid-datagram, which only looks like a TCP header (#1576)
            ('later fragment', make_packet(FakeEthernet(FakeIP(make_tcp(b'x' * 20), off=185)))),
        ):
            with self.subTest(case=label):
                self.assertIsNone(tcp_reassembly(packet, count=1))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=1))

    def test_transport_takes_the_first_fragment_to_the_total_length(self) -> None:
        from pcapkit.toolkit.pypcapfile import _transport

        segment = make_tcp(b'x')
        for label, ipv4, want in (
            # #1577: octets past the Total Length, e.g. Ethernet padding, are not payload
            ('padded', FakeIP(binascii.hexlify(segment + bytes(5)), len=20 + len(segment)), segment),
            ('options, padded',
             FakeIP(binascii.hexlify(segment + bytes(3)), hl=6, len=24 + len(segment)), segment),
            ('total length 0, as TSO leaves it',
             FakeIP(binascii.hexlify(segment + b'more'), len=0), segment + b'more'),
            ('total length past the capture', FakeIP(binascii.hexlify(segment), len=200), segment),
            ('total length shorter than the header', FakeIP(binascii.hexlify(segment), len=12), None),
            ('total length cuts the tcp header short', FakeIP(binascii.hexlify(segment), len=30), None),
            # #1576: a later fragment carries no TCP header, however it looks
            ('last fragment', FakeIP(binascii.hexlify(segment), off=1), None),
            ('later fragment, more to follow',
             FakeIP(binascii.hexlify(segment), off=185, flags=0b001), None),
            ('first fragment', FakeIP(binascii.hexlify(segment), flags=0b001), segment),
        ):
            with self.subTest(case=label):
                self.assertEqual(_transport(ipv4), want)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileTCPOverIPv6Tests(unittest.TestCase):
    """TCP over IPv6 is left out, with one warning per capture. C.f. #1513."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def decline(self, *packets) -> list[str]:
        """Feed ``packets`` to both TCP adapters, frame 1 first; return their warnings."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow
        from pcapkit.utilities.warnings import AttributeWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for count, packet in enumerate(packets, start=1):
                self.assertIsNone(tcp_reassembly(packet, count=count))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count))
        return [str(item.message) for item in caught if issubclass(item.category, AttributeWarning)]

    def test_tcp_over_ipv6_warns_once_per_capture(self) -> None:
        first, second = (make_packet(ipv6_frame(wire.ipv6(TCP_SEGMENT, nxt=6))) for _ in range(2))
        second.header = first.header  # both frames of one capture

        with self.assertLogs('pcapkit', level='WARNING') as logs:
            messages = self.decline(first, second)
        self.assertEqual(len(messages), 1, messages)
        self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6 is left out'), messages)
        self.assertIn("'pypcapfile' has no IPv6 decoder", messages[0])
        self.assertEqual(len(logs.records), 1)

    def test_interleaved_captures_each_warn_once(self) -> None:
        one, other, one_again, other_again = (
            make_packet(ipv6_frame(wire.ipv6(TCP_SEGMENT, nxt=6))) for _ in range(4))
        one_again.header, other_again.header = one.header, other.header

        messages = self.decline(one, other, one_again, other_again)
        self.assertEqual([message.split(':')[0] for message in messages], ['Frame 1', 'Frame 2'])

    def test_the_oldest_capture_is_forgotten_beyond_the_limit(self) -> None:
        from unittest import mock

        from pcapkit.toolkit import pypcapfile as toolkit

        first, second, third, first_again, third_again = (
            make_packet(ipv6_frame(wire.ipv6(TCP_SEGMENT, nxt=6))) for _ in range(5))
        first_again.header, third_again.header = first.header, third.header

        # Two remembered at most: the third capture pushes the first out, so the
        # first warns a second time -- repeated, never omitted -- while the
        # third is still remembered.
        with mock.patch.object(toolkit, 'TCP_WARNED_LIMIT', 2), \
                mock.patch.object(toolkit, '_tcp_warned', type(toolkit._tcp_warned)()):
            messages = self.decline(first, second, third, first_again, third_again)
            self.assertEqual(len(toolkit._tcp_warned), 2)
        self.assertEqual([message.split(':')[0] for message in messages],
                         ['Frame 1', 'Frame 2', 'Frame 3', 'Frame 4'])

    def test_tcp_behind_extension_headers_warns(self) -> None:
        hop_by_hop = bytes([6, 0]) + b'\x01\x04' + bytes(4)        # PadN, 8 octets
        long_hop_by_hop = bytes([6, 1]) + b'\x01\x0c' + bytes(12)  # PadN, 16 octets
        options_then_routing = bytes([43, 0]) + b'\x01\x04' + bytes(4) + bytes([6, 0]) + bytes(6)
        auth = struct.pack('!BBHII', 6, 4, 0, 0x100, 1) + bytes(12)  # (4 + 2) * 4 octets
        mobility = bytes([6, 1]) + bytes(14)          # payload proto, 16 octets
        hip = bytes([6, 4, 0x01, 0x21]) + bytes(36)   # next header, 40 octets
        shim6 = bytes([6, 0]) + bytes(6)              # next header, 8 octets
        for label, packet in (
            ('hop-by-hop', wire.ipv6(hop_by_hop + TCP_SEGMENT, nxt=0)),
            ('16-octet hop-by-hop', wire.ipv6(long_hop_by_hop + TCP_SEGMENT, nxt=0)),
            ('destination options, routing', wire.ipv6(options_then_routing + TCP_SEGMENT, nxt=60)),
            ('authentication header', wire.ipv6(auth + TCP_SEGMENT, nxt=51)),
            ('first fragment', wire.ipv6_fragment(TCP_SEGMENT, mf=True, nxt=6)),
            ('mobility', wire.ipv6(mobility + TCP_SEGMENT, nxt=135)),
            ('hip', wire.ipv6(hip + TCP_SEGMENT, nxt=139)),
            ('shim6', wire.ipv6(shim6 + TCP_SEGMENT, nxt=140)),
            ('hop-by-hop, mobility', wire.ipv6(bytes([135, 0]) + bytes(6) + mobility + TCP_SEGMENT,
                                               nxt=0)),
            ('first fragment, shim6', wire.ipv6_fragment(shim6 + TCP_SEGMENT, mf=True, nxt=140)),
        ):
            with self.subTest(case=label):
                messages = self.decline(make_packet(ipv6_frame(packet)))
                self.assertEqual(len(messages), 1, messages)

    def test_no_warning_without_tcp_over_ipv6(self) -> None:
        arp = FakeEthernet(binascii.hexlify(b'\x00\x01\x08\x00' + bytes(24)))
        arp.type = 0x0806
        decoded = ipv6_frame(b'')
        decoded.payload = object()  # a decoder PyPCAPFile does not have yet
        for label, layer in (
            ('undecoded link', b'raw'),
            ('arp', arp),
            ('ipv6 payload decoded', decoded),
            ('icmpv6', ipv6_frame(wire.ipv6(b'\x80\x00' + bytes(6), nxt=58))),
            ('udp', ipv6_frame(wire.ipv6(wire.udp(b'x'), nxt=17))),
            ('esp', ipv6_frame(wire.ipv6(b'\x00\x00\x01\x00' + bytes(4) + TCP_SEGMENT, nxt=50))),
            # the header's own length runs to the end of the packet, so nothing
            # follows it -- as in options-internet.pcap's HIP frames
            ('hip filling the packet', ipv6_frame(wire.ipv6(bytes([6, 6, 0x01, 0x21]) + bytes(52),
                                                            nxt=139))),
            ('mobility, no next header', ipv6_frame(wire.ipv6(bytes([59, 0]) + bytes(6)
                                                              + TCP_SEGMENT, nxt=135))),
            ('experimental 253', ipv6_frame(wire.ipv6(bytes([6, 0]) + bytes(6) + TCP_SEGMENT,
                                                      nxt=253))),
            ('truncated ipv6 header', ipv6_frame(wire.ipv6(b'', nxt=6)[:39])),
            ('truncated extension header', ipv6_frame(wire.ipv6(b'\x06\x00\x01', nxt=0))),
            ('truncated tcp header', ipv6_frame(wire.ipv6(TCP_SEGMENT[:19], nxt=6))),
            ('extension header overruns the frame',
             ipv6_frame(wire.ipv6(bytes([6, 200]) + bytes(6) + TCP_SEGMENT, nxt=0))),
            # a later fragment's data is a slice of the payload, not a header,
            # even when it happens to look like one
            ('later fragment', ipv6_frame(wire.ipv6_fragment(TCP_SEGMENT, offset=8, nxt=6))),
            ('later fragment, shim6',
             ipv6_frame(wire.ipv6_fragment(bytes([6, 0]) + bytes(6) + TCP_SEGMENT, offset=8,
                                           nxt=140))),
            ('first fragment, then a later one', ipv6_frame(wire.ipv6_fragment(
                struct.pack('!BBHI', 6, 0, 8, 7) + TCP_SEGMENT, mf=True, nxt=44))),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.decline(make_packet(layer)), [])

    def test_capture_of_keys_a_ctypes_header_by_its_address(self) -> None:
        from pcapkit.toolkit.pypcapfile import _capture_of

        header, other = ctypes.c_int(1), ctypes.c_int(2)
        # Every read of a ``ctypes`` pointer field builds a new pointer object,
        # so the key must not be the pointer's identity.
        one, same = make_packet(b''), make_packet(b'')
        one.header, same.header = ctypes.pointer(header), ctypes.pointer(header)
        another = make_packet(b'')
        another.header = ctypes.pointer(other)

        key, anchor = _capture_of(one)
        self.assertIs(anchor, one.header)
        self.assertEqual(key, ctypes.addressof(header))
        self.assertEqual(_capture_of(same)[0], key)
        self.assertNotEqual(_capture_of(another)[0], key)

        for label, value in (('null pointer', ctypes.POINTER(ctypes.c_int)()),
                             ('stand-in list', [types.SimpleNamespace(ns_resolution=False)])):
            with self.subTest(case=label):
                packet = make_packet(b'')
                packet.header = value
                self.assertEqual(_capture_of(packet), (id(value), value))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileEncapsulatedTCPTests(unittest.TestCase):
    """TCP behind VLAN tags or in IP tunnels is read or warned about. C.f. #1537."""

    decline = PyPCAPFileTCPOverIPv6Tests.decline

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_vlan_tagged_tcp_over_ipv6_warns(self) -> None:
        hop_by_hop = bytes([6, 0]) + b'\x01\x04' + bytes(4)
        for label, frame in (
            ('802.1Q', tagged_frame(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, C_TAG)),
            ('802.1ad', tagged_frame(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, S_TAG)),
            ('QinQ', tagged_frame(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, S_TAG, C_TAG)),
            ('two customer tags', tagged_frame(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, C_TAG, C_TAG)),
            ('802.1Q, hop-by-hop', tagged_frame(wire.ipv6(hop_by_hop + TCP_SEGMENT, nxt=0), 0x86DD,
                                                C_TAG)),
        ):
            with self.subTest(case=label):
                messages = self.decline(make_packet(frame))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6 is left out'),
                                messages)

    def test_tunnelled_tcp_warns(self) -> None:
        tcp4, tcp6 = wire.ipv4(TCP_SEGMENT, proto=6), wire.ipv6(TCP_SEGMENT, nxt=6)
        hop_by_hop = bytes([6, 0]) + b'\x01\x04' + bytes(4)
        for label, frame in (
            ('4in4', tunnel(tcp4, 4)),
            ('6in4', tunnel(tcp6, 41)),
            ('6in6', ipv6_frame(wire.ipv6(tcp6, nxt=41))),
            ('4in6', ipv6_frame(wire.ipv6(tcp4, nxt=4))),
            ('4in4in4', tunnel(wire.ipv4(tcp4, proto=4), 4)),
            ('6in4in6', ipv6_frame(wire.ipv6(wire.ipv4(tcp6, proto=41), nxt=4))),
            ('outer first fragment', tunnel(tcp4, 4, flags=0b001)),
            ('inner ipv4 options', tunnel(make_ipv4(TCP_SEGMENT, options=b'\x01\x01\x01\x00'), 4)),
            ('inner first fragment', tunnel(wire.ipv4(TCP_SEGMENT, proto=6, mf=True), 4)),
            ('inner total length 0', tunnel(total_length(tcp4, 0), 4)),
            ('outer padded', tunnel(tcp4 + bytes(6), 4, len=20 + len(tcp4))),
            ('inner hop-by-hop', tunnel(wire.ipv6(hop_by_hop + TCP_SEGMENT, nxt=0), 41)),
            ('tunnel behind hop-by-hop',
             ipv6_frame(wire.ipv6(bytes([41, 0]) + b'\x01\x04' + bytes(4) + tcp6, nxt=0))),
            ('6in6 behind 802.1Q', tagged_frame(wire.ipv6(tcp6, nxt=41), 0x86DD, C_TAG)),
            ('4in6 behind QinQ', tagged_frame(wire.ipv6(tcp4, nxt=4), 0x86DD, S_TAG, C_TAG)),
            # the default engine's TCP parser accepts these headers
            ('tcp options', tunnel(wire.ipv4(make_tcp(b'x', options=b'\x02\x04\x05\xb4'), proto=6), 4)),
            ('an unknown tcp option', tunnel(wire.ipv4(make_tcp(b'x', options=b'\xfe\x04\x00\x00'),
                                                       proto=6), 4)),
            ('inner ipv6 jumbogram', tunnel(JUMBOGRAM, 41)),
            ('outer ipv4 option', tunnel(tcp4, 4, hl=6, opt=b'\x94\x04\x00\x00')),  # router alert
        ):
            with self.subTest(case=label):
                messages = self.decline(make_packet(frame))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP tunnelled in IP'), messages)
                self.assertIn("'pypcapfile' decodes no tunnel", messages[0])

    def test_no_warning_where_the_default_engine_finds_no_tcp(self) -> None:
        tcp4, tcp6 = wire.ipv4(TCP_SEGMENT, proto=6), wire.ipv6(TCP_SEGMENT, nxt=6)
        arp = b'\x00\x01\x08\x00' + bytes(24)
        decoded = tagged_frame(b'', 0x86DD, C_TAG)
        decoded.payload = object()  # a decoder PyPCAPFile does not have yet
        cut_short = FakeEthernet(binascii.hexlify(b'\x00\x64\x86'))  # three octets of a tag
        cut_short.type = C_TAG
        for label, frame in (
            ('not tunnelled', FakeEthernet(FakeIP(b'x' * 40, p=17))),
            ('tunnelled udp', tunnel(wire.ipv4(wire.udp(b'x'), proto=17), 4)),
            ('gre', tunnel(bytes(4) + tcp4, 47)),
            ('ipv4 payload decoded', FakeEthernet(FakeIP(object(), p=4))),
            # a later fragment's data is a slice of the payload, not a header
            ('outer later fragment', tunnel(tcp4, 4, off=3)),
            ('inner later fragment', tunnel(wire.ipv4(TCP_SEGMENT, proto=6, offset=8), 4)),
            ('inner ipv6 later fragment', tunnel(wire.ipv6_fragment(TCP_SEGMENT, offset=8, nxt=6), 41)),
            ('inner not version 4', tunnel(b'\x65' + tcp4[1:], 4)),
            ('inner header under 20 octets', tunnel(b'\x44' + tcp4[1:], 4)),
            ('inner header overruns the packet', tunnel(b'\x4f' + tcp4[1:], 4)),
            ('inner ipv4 truncated', tunnel(tcp4[:19], 4)),
            ('inner ipv6 truncated', tunnel(tcp6[:39], 41)),
            ('inner tcp truncated', tunnel(wire.ipv4(TCP_SEGMENT[:19], proto=6), 4)),
            # the Total Length ends the packet inside the TCP header, though more was captured
            ('inner total length cuts the tcp header short', tunnel(total_length(tcp4, 30), 4)),
            ('outer total length cuts the tunnel short', tunnel(tcp4, 4, len=40)),
            ('inner payload length cuts the tcp header short',
             tunnel(tcp6[:4] + (10).to_bytes(2, 'big') + tcp6[6:], 41)),
            # a Payload Length of 0 with no Jumbo Payload option leaves no payload
            ('inner payload length 0, no jumbo option', tunnel(tcp6[:4] + b'\x00\x00' + tcp6[6:], 41)),
            ('ipv6 payload length 0, no jumbo option', ipv6_frame(tcp6[:4] + b'\x00\x00' + tcp6[6:])),
            # in a tunnel, a header the default engine's TCP parser rejects is no TCP
            ('tunnelled data offset past the capture',
             tunnel(wire.ipv4(data_offset(TCP_SEGMENT, 9), proto=6), 4)),
            ('tunnelled data offset past the inner total length',
             tunnel(total_length(wire.ipv4(make_tcp(b'', options=b'\x02\x04\x05\xb4'), proto=6), 40)
                    + bytes(8), 4)),
            ('tunnelled data offset 4', tunnel(wire.ipv4(data_offset(TCP_SEGMENT, 4), proto=6), 4)),
            # nor is a tunnel whose outer IPv4 header the default engine rejects (#1591, #1596)
            ('outer ipv4 option', tunnel(tcp4, 4, hl=6, opt=b'\x94\x02\x00\x00')),  # router alert, length 2
            ('outer ipv4 header overruns the packet', tunnel(tcp4, 4, hl=6, opt=b'\x94\x04')),
            # nor is one whose Data Offset is under 5 words, over IPv6 alone too
            ('ipv6 data offset 4', ipv6_frame(wire.ipv6(data_offset(TCP_SEGMENT, 4), nxt=6))),
            ('802.1Q, ipv6 data offset 0', tagged_frame(wire.ipv6(data_offset(TCP_SEGMENT, 0), nxt=6),
                                                        0x86DD, C_TAG)),
            ('inner esp', ipv6_frame(wire.ipv6(wire.ipv6(bytes(8) + TCP_SEGMENT, nxt=50), nxt=41))),
            ('tunnel header overruns the frame',
             ipv6_frame(wire.ipv6(bytes([41, 200]) + bytes(6) + tcp6, nxt=0))),
            ('802.1Q, then arp', tagged_frame(arp, 0x0806, C_TAG)),
            ('802.1Q, payload decoded', decoded),
            ('802.1Q cut short', cut_short),
            # 0x9100 is a pre-standard QinQ TPID, which the default engine does not dissect
            ('0x9100 tag', tagged_frame(tcp6, 0x86DD, 0x9100)),
        ):
            with self.subTest(case=label):
                self.assertEqual(self.decline(make_packet(frame)), [])

    def test_network_decodes_the_ipv4_behind_the_tags(self) -> None:
        from unittest import mock

        from pcapkit.toolkit.pypcapfile import _network

        packet = wire.ipv4(TCP_SEGMENT, proto=6)
        with mock.patch.dict('sys.modules', fake_ip_decoder()) as modules:
            IP = modules['pcapfile.protocols.network.ip'].IP
            ipv4 = _network(make_packet(tagged_frame(packet, 0x0800, S_TAG, C_TAG)))
            self.assertIsInstance(ipv4, IP)
            self.assertEqual(IP.calls, [(packet, 0)])  # every tag stripped, network layer only

    def test_malformed_ipv4_behind_tags_warns_once_per_frame(self) -> None:
        # As PyPCAPFile._decode warns of an untagged frame it cannot decode,
        # however many adapters then fetch the tagged frame's network layer.
        from unittest import mock

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly, tcp_reassembly, tcp_traceflow
        from pcapkit.utilities.warnings import AttributeWarning

        bad = tagged_frame(b'\x44' + wire.ipv4(TCP_SEGMENT, proto=6)[1:], 0x0800, C_TAG)  # IHL 4
        other = FakeEthernet(FakeIP(b'x' * 40, p=17, flags=0b010))  # decoded, nothing to warn of
        packets = [make_packet(frame) for frame in (bad, bad, other, bad)]
        for packet in packets[1:]:
            packet.header = packets[0].header  # one capture
        with mock.patch.dict('sys.modules', fake_ip_decoder()), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for count, packet in enumerate(packets, start=1):
                self.assertIsNone(ipv4_reassembly(packet, count=count))
                self.assertIsNone(tcp_reassembly(packet, count=count))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count))
        messages = [str(item.message) for item in caught if issubclass(item.category, AttributeWarning)]
        self.assertEqual(messages, [
            f"Frame {count}: <LinkType.ETHERNET: 1> decoding failed (AssertionError('not an IPv4 "
            "packet.')); frame left undecoded" for count in (1, 2, 4)
        ])

    def test_tcp_over_ipv6_the_tcp_parser_rejects_still_warns(self) -> None:
        # Over IPv6, unlike in a tunnel, the default engine reads such a header
        # out of the raw octets its TCP parser leaves.
        for label, frame in (
            ('data offset past the capture', ipv6_frame(wire.ipv6(data_offset(TCP_SEGMENT, 9), nxt=6))),
            ('option of length 0', ipv6_frame(wire.ipv6(make_tcp(b'x', options=b'\x02\x00\x05\xb4'),
                                                        nxt=6))),
            ('jumbogram', ipv6_frame(JUMBOGRAM)),
        ):
            with self.subTest(case=label):
                messages = self.decline(make_packet(frame))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6'), messages)

    def test_malformed_tunnelled_tcp_the_header_walk_cannot_see_into_still_warns(self) -> None:
        # The residual _upper_layer documents: the default engine rejects these
        # options, and so finds no TCP, but nothing short of dissecting the frame
        # would show that -- the warning errs on the side of being given.
        tcp4 = wire.ipv4(TCP_SEGMENT, proto=6)
        for label, frame in (
            ('tunnelled tcp option of length 0',
             tunnel(wire.ipv4(make_tcp(b'x', options=b'\x02\x00\x05\xb4'), proto=6), 4)),
            ('tunnelled tcp option past its area',
             ipv6_frame(wire.ipv6(wire.ipv6(make_tcp(b'x', options=b'\x08\x0a\x00\x00'), nxt=6), nxt=41))),
            ('inner ipv4 option', tunnel(make_ipv4(TCP_SEGMENT, options=b'\x94\x02\x00\x00'), 4)),
        ):
            with self.subTest(case=label):
                messages = self.decline(make_packet(frame))
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 1: TCP tunnelled in IP'), messages)

    def test_detection_leaves_the_warnings_filters_and_the_logger_alone(self) -> None:
        # The warnings filters and the logger are process-wide state of the
        # caller's: telling a frame apart must neither change them nor reset
        # what they have already seen.
        import logging

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow

        logger = logging.getLogger('pcapkit')
        level = logger.level
        frames = (ipv6_frame(wire.ipv6(wire.ipv6(data_offset(TCP_SEGMENT, 9), nxt=6), nxt=41)),
                  tunnel(wire.ipv4(make_tcp(b'x', options=b'\x02\x00\x05\xb4'), proto=6), 4),
                  ipv6_frame(wire.ipv6(TCP_SEGMENT, nxt=6)))

        def user_warning() -> None:
            warnings.warn('a warning of the caller', UserWarning)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('default')
            filters = list(warnings.filters)
            user_warning()
            # the adapters called as the engine calls them, with nothing between
            for count, frame in enumerate(frames, start=1):
                packet = make_packet(frame)
                tcp_reassembly(packet, count=count)
                tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count)
                self.assertEqual(warnings.filters, filters)
                self.assertEqual(logger.level, level)
            user_warning()  # the same call site, so the 'default' action shows it only once
        self.assertEqual([str(item.message) for item in caught if item.category is UserWarning],
                         ['a warning of the caller'])

    def test_each_frame_is_walked_once_per_adapter_call(self) -> None:
        # Declining costs one header walk per frame and adapter, however the
        # frame is malformed: nothing is retried or dissected again.
        from unittest import mock

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.toolkit import pypcapfile as toolkit

        built = []  # type: list[str]
        init = ProtocolBase.__init__

        def spy_init(this, *args, **kwargs):
            built.append(type(this).__name__)
            return init(this, *args, **kwargs)

        cut = wire.ipv6(wire.ipv6(make_tcp(b'', options=b'\x02\x04\x05\xb4'), nxt=6), nxt=41)[:-4]
        packets = [make_packet(ipv6_frame(cut)) for _ in range(10)]  # a TCP header cut short in a tunnel
        for packet in packets[1:]:
            packet.header = packets[0].header  # one capture, which never warns
        with mock.patch.object(toolkit, '_upper_layer', wraps=toolkit._upper_layer) as walk, \
                mock.patch.object(ProtocolBase, '__init__', spy_init), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for count, packet in enumerate(packets, start=1):
                self.assertIsNone(toolkit.tcp_reassembly(packet, count=count))
                self.assertIsNone(toolkit.tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count))
        self.assertEqual([str(item.message) for item in caught], [])
        # the outer IPv6 header and the inner one, per frame and adapter ...
        self.assertEqual(walk.call_count, 2 * 2 * len(packets))
        # ... and no protocol of the default engine's dissected along the way
        self.assertEqual(built, [])

    def test_each_kind_warns_once_per_capture(self) -> None:
        frames = (ipv6_frame(wire.ipv6(TCP_SEGMENT, nxt=6)),
                  ipv6_frame(wire.ipv6(wire.ipv6(TCP_SEGMENT, nxt=6), nxt=41)),
                  tagged_frame(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, C_TAG),
                  tunnel(wire.ipv4(TCP_SEGMENT, proto=6), 4))
        packets = [make_packet(frame) for frame in frames]
        for packet in packets[1:]:
            packet.header = packets[0].header  # all four frames of one capture

        messages = self.decline(*packets)
        self.assertEqual(len(messages), 2, messages)
        self.assertTrue(messages[0].startswith('Frame 1: TCP over IPv6'), messages)
        self.assertTrue(messages[1].startswith('Frame 2: TCP tunnelled in IP'), messages)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed or not importable')
class PyPCAPFileToolkitAgainstRealDecodersTests(unittest.TestCase):
    """Tests that need :mod:`pcapfile`'s own decoders to be meaningful."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ipv4_header_reconstruction_is_byte_exact(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import ipv4_header

        for label, options in (('no options', b''), ('with options', b'\x94\x04\x00\x00')):
            with self.subTest(case=label):
                raw = make_ipv4(b'payload' * 4, options=options)
                ihl = 20 + len(options)
                decoded = IP(raw)
                self.assertEqual(ipv4_header(decoded), raw[:ihl])

    def test_ipv4_header_reconstruction_survives_fragment_flags(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import ipv4_header

        raw = make_ipv4(b'x' * 32, flags=0b001, offset=185)
        self.assertEqual(ipv4_header(IP(raw)), raw[:20])

    def test_tcp_reassembly_splits_the_real_segment_exactly(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import tcp_reassembly

        options = b'\x02\x04\x05\xb4'
        segment = make_tcp(b'SSH-2.0-OpenSSH_9.3\r\n', flags=0b00010011, options=options)
        packet = make_packet(FakeEthernet(IP(make_ipv4(segment))))

        data = tcp_reassembly(packet, count=3)
        self.assertIsNotNone(data)
        self.assertEqual(data.num, 3)
        self.assertEqual(data.header, segment[:24])
        self.assertEqual(data.header[20:], options)
        self.assertEqual(bytes(data.payload), b'SSH-2.0-OpenSSH_9.3\r\n')
        self.assertEqual(data.len, 21)
        self.assertEqual(data.dsn, 1000)
        self.assertEqual(data.ack, 2000)
        self.assertEqual(data.first, 1000)
        self.assertEqual(data.last, 1020)
        self.assertTrue(data.syn)
        self.assertTrue(data.fin)
        self.assertFalse(data.rst)
        self.assertEqual(data.bufid, (
            ipaddress.IPv4Address('10.1.1.2'), 51000,
            ipaddress.IPv4Address('10.1.1.3'), 22,
        ))

    def test_tcp_traceflow_reports_the_flow_endpoints(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_traceflow

        segment = make_tcp(b'body', flags=0b00000010)
        packet = make_packet(FakeEthernet(IP(make_ipv4(segment))))

        data = tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=5)
        self.assertIsNotNone(data)
        self.assertEqual(data.protocol, LinkType.ETHERNET)
        self.assertEqual(data.index, 5)
        self.assertTrue(data.syn)
        self.assertFalse(data.fin)
        self.assertEqual(data.src, ipaddress.IPv4Address('10.1.1.2'))
        self.assertEqual(data.dst, ipaddress.IPv4Address('10.1.1.3'))
        self.assertEqual(data.srcport, 51000)
        self.assertEqual(data.dstport, 22)
        self.assertEqual(data.timestamp, 1511106545.471719)
        self.assertEqual(data.frame['ETHERNET']['IP']['src'], '10.1.1.2')

    def test_ipv4_2dict_unhexes_the_options_field(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import _ipv4_2dict

        raw = make_ipv4(b'payload', options=b'\x94\x04\x00\x00')
        info = _ipv4_2dict(IP(raw))
        self.assertEqual(info['opt'], b'\x94\x04\x00\x00')

    def test_ipv4_reassembly_unhexes_the_fragment_payload(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import ipv4_reassembly

        payload = b'fragment-body-bytes'
        raw = make_ipv4(payload, flags=0b001)
        packet = make_packet(FakeEthernet(IP(raw)))

        data = ipv4_reassembly(packet, count=1)
        self.assertIsNotNone(data)
        self.assertEqual(bytes(data.payload), payload)

    def test_layer2dict_keeps_opt_and_nested_payload_length_consistent(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.toolkit.pypcapfile import _layer2dict

        # Regression for the inconsistency a partial fix left behind: ``opt``
        # correctly un-hexed while the nested ``'Raw'`` payload stayed
        # hex-encoded (and twice its true length) in the very same dict.
        payload = b'x' * 32
        raw = make_ipv4(payload, options=b'\x94\x04\x00\x00')
        info = _layer2dict(IP(raw))
        self.assertEqual(info['opt'], b'\x94\x04\x00\x00')
        self.assertEqual(info['Raw'], {'raw_len': 32, 'raw': payload})

    def test_layer2dict_unhexes_an_undecoded_ethernet_payload(self) -> None:
        from pcapfile.protocols.linklayer.ethernet import Ethernet

        from pcapkit.toolkit.pypcapfile import _layer2dict

        # PyPCAPFile hex-encodes an Ethernet frame's payload too, whenever the
        # ethertype has no decoder of its own (e.g. ARP, which PyPCAPFile does
        # not decode) -- the same defect class as the IP layer's, one class over.
        body = b'unknown-ethertype-body'
        frame = struct.pack('!6s6sH', b'\x01\x00\x5e\x01\x03\x03',
                            b'\x00\x0c\x29\x3f\x1a\x07', 0x0806) + body
        info = _layer2dict(Ethernet(frame))
        self.assertEqual(info['Raw'], {'raw_len': len(body), 'raw': body})

    def test_ethernet2dict_reports_the_default_engines_mac_format(self) -> None:
        from pcapfile.protocols.linklayer.ethernet import Ethernet

        from pcapkit.toolkit.pypcapfile import _ethernet2dict

        # Against PyPCAPFile's real decoder: confirms ``_ethernet2dict`` reports
        # the same lowercase colon-separated form the default engine's own
        # ``Ethernet._read_mac_addr`` does, not PyPCAPFile's ASCII bytes as-is.
        frame = struct.pack('!6s6sH', b'\x01\x00\x5e\x01\x03\x03',
                            b'\x00\x0c\x29\x3f\x1a\x07', 0x0800) + b'\x00' * 20
        info = _ethernet2dict(Ethernet(frame))
        self.assertEqual(info['dst'], '01:00:5e:01:03:03')
        self.assertEqual(info['src'], '00:0c:29:3f:1a:07')

    def test_engine_warns_once_per_capture_on_tcp_over_ipv6(self) -> None:
        from pcapkit import extract

        # One IPv4 TCP frame, then two IPv6 TCP frames and an IPv6 UDP one. The
        # engine builds a new ``pcap_packet`` per frame, so this also checks that
        # the real savefile header keys one capture -- see ``_capture_of``.
        frames = (
            wire.ethernet(wire.ipv4(TCP_SEGMENT, proto=6), 0x0800),
            wire.ethernet(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD),
            wire.ethernet(wire.ipv6(wire.tcp(b'more', seq=8, ack=1), nxt=6), 0x86DD),
            wire.ethernet(wire.ipv6(wire.udp(b'x'), nxt=17), 0x86DD),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'mixed.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))

            for read in ('first', 'second'):  # reading it again is another capture
                with self.subTest(read=read), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    extractor = extract(fin=path, nofile=True, engine='pypcapfile',
                                        reassembly=True, tcp=True, trace=True,
                                        trace_fout=os.path.join(tmp, read), trace_format='json')
                    try:
                        messages = [str(item.message) for item in caught
                                    if 'TCP over IPv6' in str(item.message)]
                        self.assertEqual(extractor._exnam, 'pypcapfile')
                        self.assertEqual(len(messages), 1, messages)
                        self.assertTrue(messages[0].startswith('Frame 2: '), messages)
                        # ...while the IPv4 frame is still reassembled and traced
                        self.assertEqual([tuple(flow.index) for flow in extractor.trace.tcp],
                                         [(1,)])
                        self.assertEqual(len(extractor.reassembly.tcp), 1)
                    finally:
                        close_extractor(extractor)

    def test_network_decodes_behind_vlan_tags_as_untagged(self) -> None:
        from pcapfile.protocols.linklayer.ethernet import Ethernet

        from pcapkit.toolkit.pypcapfile import _ipv4_2dict, _maybe_unhex, _network

        packet = make_ipv4(make_tcp(b'body'), options=b'\x94\x04\x00\x00')
        untagged = Ethernet(wire.ethernet(packet, 0x0800), 1).payload
        want = _ipv4_2dict(untagged), _maybe_unhex(bytes(untagged.payload))
        for label, tpids in (('802.1Q', (C_TAG,)), ('802.1ad', (S_TAG,)), ('QinQ', (S_TAG, C_TAG)),
                             ('two customer tags', (C_TAG, C_TAG))):
            with self.subTest(case=label):
                ipv4 = _network(make_packet(Ethernet(tagged(packet, 0x0800, *tpids), 1)))
                self.assertEqual(type(ipv4).__name__, 'IP')
                self.assertEqual((_ipv4_2dict(ipv4), _maybe_unhex(bytes(ipv4.payload))), want)

        for label, frame, undecoded in (
            ('802.1Q, then ipv6', tagged(wire.ipv6(TCP_SEGMENT, nxt=6), 0x86DD, C_TAG), False),
            ('802.1Q, then not ipv4', tagged(b'\x65' + packet[1:], 0x0800, C_TAG), True),
            ('802.1Q, then a truncated ipv4 header', tagged(packet[:19], 0x0800, C_TAG), True),
            ('802.1Q cut short', wire.ethernet(b'\x00\x64\x08', C_TAG), False),
            ('0x9100 tag', tagged(packet, 0x0800, 0x9100), False),
        ):
            with self.subTest(case=label), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertIsNone(_network(make_packet(Ethernet(frame, 1)), 7))
                self.assertEqual([str(item.message).split(' decoding failed')[0] for item in caught],
                                 ['Frame 7: <LinkType.ETHERNET: 1>'] if undecoded else [])

    def test_engine_warns_alike_of_tagged_and_untagged_ipv4_it_cannot_decode(self) -> None:
        from pcapkit import extract

        bad = b'\x44' + wire.ipv4(TCP_SEGMENT, proto=6)[1:]  # IHL 4
        frames = (wire.ethernet(bad, 0x0800), tagged(bad, 0x0800, S_TAG, C_TAG),
                  wire.ethernet(wire.ipv4(TCP_SEGMENT, proto=6), 0x0800))
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'undecodable.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                extractor = extract(fin=path, nofile=True, engine='pypcapfile', reassembly=True,
                                    ipv4=True, tcp=True, trace=True,
                                    trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
            try:
                self.assertEqual(extractor._exnam, 'pypcapfile')
                messages = [str(item.message) for item in caught if 'decoding failed' in str(item.message)]
                # one each, the untagged from the engine and the tagged from the toolkit,
                # in the same words after the frame number
                self.assertEqual([message.split(': ', 1)[0] for message in messages],
                                 ['Frame 1', 'Frame 2'])
                self.assertEqual(messages[0].split(': ', 1)[1], messages[1].split(': ', 1)[1])
                self.assertEqual([tuple(flow.index) for flow in extractor.trace.tcp], [(3,)])
            finally:
                close_extractor(extractor)

    #: What :meth:`read_both` compares between the two engines.
    ASPECTS = ('ipv4', 'tcp', 'trace', 'ipv4 datagrams', 'tcp datagrams', 'flows')

    def read(self, engine: str, path: str, tracedir: str) -> dict:
        """Every field ``engine`` hands IPv4 and TCP reassembly and TCP flow tracing for ``path``.

        Inputs are keyed by frame number, and a trace input leaves out ``frame``,
        the engine's own frame object -- as in ``test_engine_agreement_runtime``.

        """
        from unittest import mock

        from pcapkit import extract
        from pcapkit.foundation.reassembly.reassembly import ReassemblyBase
        from pcapkit.foundation.traceflow.traceflow import TraceFlowBase

        seen = {'ipv4': {}, 'tcp': {}, 'trace': {}}  # type: dict
        reassemble, trace = ReassemblyBase.__call__, TraceFlowBase.__call__

        def fields(packet, skip=()):
            return {key: bytes(value) if isinstance(value, bytearray) else value
                    for key, value in packet.items() if key not in skip}

        def spy_reassembly(this, packet):
            seen[type(this).__name__.lower()][packet.num] = fields(packet)
            return reassemble(this, packet)

        def spy_trace(this, packet):
            seen['trace'][packet.index] = fields(packet, ('frame',))
            return trace(this, packet)

        with warnings.catch_warnings(record=True) as caught, \
                mock.patch.object(ReassemblyBase, '__call__', spy_reassembly), \
                mock.patch.object(TraceFlowBase, '__call__', spy_trace):
            warnings.simplefilter('always')
            extractor = extract(fin=path, nofile=True, engine=engine, reassembly=True,
                                ipv4=True, ipv6=False, tcp=True, trace=True,
                                trace_fout=tracedir, trace_format='json')
        try:
            self.assertEqual(extractor._exnam, engine)
            self.assertEqual([str(item.message) for item in caught
                              if 'left out' in str(item.message)], [])
            for kind in ('ipv4', 'tcp'):
                seen[f'{kind} datagrams'] = [fields(datagram, ('packet',))
                                             for datagram in getattr(extractor.reassembly, kind)]
            seen['flows'] = [(flow.label, tuple(flow.index)) for flow in extractor.trace.tcp]
        finally:
            close_extractor(extractor)
        return seen

    def read_both(self, frames) -> tuple[dict, dict]:
        """:meth:`read` a capture of ``frames`` with ``pypcapfile``, then with ``default``."""
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'capture.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))
            return (self.read('pypcapfile', path, os.path.join(tmp, 'pypcapfile')),
                    self.read('default', path, os.path.join(tmp, 'default')))

    def test_vlan_tagged_ipv4_agrees_with_the_default_engine(self) -> None:
        datagram = wire.udp(b'u' * 24)
        frames = (
            tagged(wire.ipv4(wire.tcp(b'hello', seq=100, syn=True), proto=6), 0x0800, C_TAG),
            tagged(wire.ipv4(wire.tcp(b'ok', seq=500, ack=106, sport=9, dport=40000),
                             proto=6, reverse=True), 0x0800, C_TAG),
            tagged(wire.ipv4(wire.tcp(b'world', seq=106, ack=501), proto=6), 0x0800, S_TAG, C_TAG),
            tagged(wire.ipv4(wire.tcp(b'!', seq=111, ack=501), proto=6), 0x0800, C_TAG, C_TAG),
            tagged(wire.ipv4(wire.tcp(b'bye', seq=112, ack=501, fin=True), proto=6), 0x0800, S_TAG),
            wire.ethernet(wire.ipv4(wire.tcp(b'late', seq=115, ack=501), proto=6), 0x0800),
            # an IPv4 datagram in two tagged fragments, for IPv4 reassembly
            tagged(wire.ipv4(datagram[:16], proto=17, mf=True, ident=0x99), 0x0800, C_TAG),
            tagged(wire.ipv4(datagram[16:], proto=17, offset=16, ident=0x99), 0x0800, S_TAG, C_TAG),
            # IPv4 and TCP options, on a flow of their own
            tagged(make_ipv4(make_tcp(b'opts', options=b'\x02\x04\x05\xb4'),
                             options=b'\x94\x04\x00\x00'), 0x0800, C_TAG),
        )
        mine, theirs = self.read_both(frames)

        self.assertEqual(sorted(mine['tcp']), [1, 2, 3, 4, 5, 6, 9])
        self.assertEqual(sorted(mine['ipv4']), [1, 2, 3, 4, 5, 6, 7, 8, 9])
        self.assertIn(datagram, [bytes(item['payload']) for item in mine['ipv4 datagrams']])
        self.assertEqual(len(mine['flows']), 2)
        for aspect in self.ASPECTS:
            with self.subTest(aspect=aspect):
                self.assertEqual(mine[aspect], theirs[aspect])

    def test_later_fragment_is_not_read_as_tcp(self) -> None:
        # C.f. #1576: a SYN, then later fragments whose data merely looks like a
        # TCP header -- untagged and tagged -- and a first fragment, which does
        # carry one.
        data = b'A' * 20 + b'B' * 20
        frames = (
            wire.ethernet(wire.ipv4(wire.tcp(b'', seq=0, syn=True), proto=6, df=True), 0x0800),
            wire.ethernet(wire.ipv4(data, proto=6, offset=1480, ident=9), 0x0800),
            tagged(wire.ipv4(data, proto=6, offset=8, mf=True, ident=10), 0x0800, C_TAG),
            wire.ethernet(wire.ipv4(wire.tcp(b'first', seq=1, ack=1), proto=6, mf=True, ident=11),
                          0x0800),
        )
        mine, theirs = self.read_both(frames)

        self.assertEqual(sorted(mine['tcp']), [1, 4])
        for aspect in self.ASPECTS:
            with self.subTest(aspect=aspect):
                self.assertEqual(mine[aspect], theirs[aspect])

    def test_tcp_payload_ends_at_the_total_length(self) -> None:
        # C.f. #1577: Ethernet padding past the Total Length is not TCP payload.
        frames = (
            wire.ethernet(wire.ipv4(wire.tcp(b'x', seq=100, ack=1), proto=6), 0x0800) + bytes(5),
            tagged(wire.ipv4(wire.tcp(b'y', seq=101, ack=1), proto=6), 0x0800, C_TAG) + bytes(1),
            # 0, as TCP segmentation offload leaves it: the rest of the frame
            wire.ethernet(total_length(wire.ipv4(wire.tcp(b'tso', seq=102, ack=1), proto=6), 0),
                          0x0800),
            # shorter than the header: no payload at all
            wire.ethernet(total_length(wire.ipv4(wire.tcp(b'bogus', seq=105, ack=1), proto=6), 12),
                          0x0800),
            # past the end of the capture: what was captured
            wire.ethernet(total_length(wire.ipv4(wire.tcp(b'cut', seq=105, ack=1), proto=6), 200),
                          0x0800),
        )
        mine, theirs = self.read_both(frames)

        self.assertEqual(sorted(mine['tcp']), [1, 2, 3, 5])
        self.assertEqual([mine['tcp'][number]['payload'] for number in (1, 2, 3, 5)],
                         [b'x', b'y', b'tso', b'cut'])
        for aspect in self.ASPECTS:
            with self.subTest(aspect=aspect):
                self.assertEqual(mine[aspect], theirs[aspect])

    def test_engine_does_not_warn_of_tunnelled_tcp_headers_the_default_engine_rejects(self) -> None:
        from pcapkit import extract

        tcp4 = wire.ipv4(TCP_SEGMENT, proto=6)
        syn = make_tcp(b'', flags=0x02, options=b'\x02\x04\x05\xb4')
        frames = (
            # a tunnelled SYN whose options the snapshot length cut off
            wire.ethernet(wire.ipv6(wire.ipv6(syn, nxt=6), nxt=41), 0x86DD)[:-2],
            # a tunnelled TCP header with a Data Offset under 5 words
            wire.ethernet(wire.ipv4(wire.ipv4(data_offset(TCP_SEGMENT, 4), proto=6), proto=4), 0x0800),
            wire.ethernet(wire.ipv4(tcp4, proto=4), 0x0800),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'tunnels.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                extractor = extract(fin=path, nofile=True, engine='pypcapfile', reassembly=True,
                                    tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'),
                                    trace_format='json')
            try:
                self.assertEqual(extractor._exnam, 'pypcapfile')
                self.assertEqual([str(item.message).split(': ', 1)[0] for item in caught
                                  if 'left out' in str(item.message)], ['Frame 3'])
            finally:
                close_extractor(extractor)

    def test_engine_warns_once_per_capture_on_tunnelled_tcp(self) -> None:
        from pcapkit import extract

        tcp4, tcp6 = wire.ipv4(TCP_SEGMENT, proto=6), wire.ipv6(TCP_SEGMENT, nxt=6)
        frames = (
            wire.ethernet(tcp4, 0x0800),
            wire.ethernet(wire.ipv4(tcp4, proto=4), 0x0800),
            wire.ethernet(wire.ipv4(tcp6, proto=41), 0x0800),
            wire.ethernet(wire.ipv6(tcp6, nxt=41), 0x86DD),
            tagged(tcp6, 0x86DD, C_TAG),
            tagged(wire.ipv4(tcp4, proto=4), 0x0800, C_TAG),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'tunnels.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                extractor = extract(fin=path, nofile=True, engine='pypcapfile',
                                    reassembly=True, tcp=True, trace=True,
                                    trace_fout=os.path.join(tmp, 'trace'), trace_format='json')
            try:
                messages = [str(item.message) for item in caught
                            if 'left out' in str(item.message)]
                self.assertEqual(extractor._exnam, 'pypcapfile')
                self.assertEqual(len(messages), 2, messages)
                self.assertTrue(messages[0].startswith('Frame 2: TCP tunnelled in IP'), messages)
                self.assertTrue(messages[1].startswith('Frame 5: TCP over IPv6'), messages)
                self.assertEqual([tuple(flow.index) for flow in extractor.trace.tcp], [(1,)])
            finally:
                close_extractor(extractor)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed or not importable')
class PyPCAPFileHeaderCheckAgreementTests(unittest.TestCase):
    """Frames whose headers PyPCAPFile reads but does not check, against the default engine.

    C.f. #1590 (Data Offset below 5), #1591 (IHL past the packet), #1592 (IPv4 in
    IPv6), #1593 (TCP behind AH over IPv4), #1596 (IPv4 options) and #1597 (TCP
    behind IPv6 extension headers in IPv4).

    """

    ASPECTS = PyPCAPFileToolkitAgainstRealDecodersTests.ASPECTS
    read = PyPCAPFileToolkitAgainstRealDecodersTests.read
    read_both = PyPCAPFileToolkitAgainstRealDecodersTests.read_both

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def agree(self, frames, **want) -> dict:
        """:meth:`read_both` ``frames``; check each aspect agrees, and pypcapfile's inputs are ``want``."""
        mine, theirs = self.read_both(frames)
        for kind, numbers in want.items():
            self.assertEqual(sorted(mine[kind]), numbers, kind)
        for aspect in self.ASPECTS:
            with self.subTest(aspect=aspect):
                self.assertEqual(mine[aspect], theirs[aspect])
        return mine

    def test_data_offset_below_5_agrees(self) -> None:
        segment = wire.tcp(b'data', seq=1)
        self.agree([
            wire.ethernet(wire.ipv4(data_offset(segment, 4), proto=6), 0x0800),
            tagged(wire.ipv4(data_offset(segment, 0), proto=6), 0x0800, C_TAG),
            wire.ethernet(wire.ipv4(segment, proto=6), 0x0800),
        ], tcp=[3], trace=[3])

    def test_ipv4_header_past_the_packet_agrees(self) -> None:
        self.agree([
            wire.ethernet(ihl(wire.ipv4(wire.tcp(b'', seq=1), proto=6), 15), 0x0800),
            tagged(ihl(wire.ipv4(wire.tcp(b'', seq=1), proto=6), 15), 0x0800, C_TAG),
            wire.ethernet(ihl(wire.ipv4(b'', proto=17), 6), 0x0800),
            wire.ethernet(wire.ipv4(b'', proto=17), 0x0800),
        ], ipv4=[4], tcp=[])

    def test_ipv4_in_ipv6_agrees(self) -> None:
        datagram = wire.udp(b'u' * 24)
        first = wire.ipv4(datagram[:16], proto=17, mf=True, ident=5)
        frames = [
            # one datagram, in two fragments, each in IPv6
            wire.ethernet(wire.ipv6(first, nxt=4), 0x86DD),
            tagged(wire.ipv6(wire.ipv4(datagram[16:], proto=17, offset=16, ident=5), nxt=4),
                   0x86DD, C_TAG),
            wire.ethernet(wire.ipv6(bytes([4, 0, 1, 4, 0, 0, 0, 0]) + udp_fragment(), nxt=0), 0x86DD),
            wire.ethernet(wire.ipv6(wire.ipv6(udp_fragment(), nxt=4), nxt=41), 0x86DD),
            wire.ethernet(wire.ipv6(udp_fragment(), nxt=4), 0x86DD) + bytes(9),
            wire.ethernet(wire.ipv6(make_ipv4(b'u' * 8, protocol=17, flags=1,
                                              options=b'\x94\x04\x00\x00'), nxt=4), 0x86DD),
            # none: DF set, a later IPv6 fragment, an IHL past the packet, options it rejects
            wire.ethernet(wire.ipv6(wire.ipv4(wire.udp(b'x'), proto=17, df=True), nxt=4), 0x86DD),
            wire.ethernet(wire.ipv6_fragment(udp_fragment(), offset=8, nxt=4), 0x86DD),
            wire.ethernet(wire.ipv6(ihl(udp_fragment(), 15), nxt=4), 0x86DD),
            wire.ethernet(wire.ipv6(make_ipv4(b'u' * 8, protocol=17, flags=1,
                                              options=BAD_IPV4_OPTIONS[0]), nxt=4), 0x86DD),
        ]
        mine = self.agree(frames, ipv4=[1, 2, 3, 4, 5, 6])
        self.assertIn(datagram, [item['payload'] for item in mine['ipv4 datagrams'] if item['completed']])

    def test_tcp_behind_ah_agrees(self) -> None:
        def over_ah(segment: bytes, header: bytes = ah(6), **fields) -> bytes:
            return wire.ethernet(wire.ipv4(header + segment, proto=51, **fields), 0x0800)

        frames = [
            # a flow behind AH, then behind two, tagged, and with Ethernet padding
            over_ah(wire.tcp(b'', seq=0, syn=True)),
            over_ah(wire.tcp(b'hello', seq=1, ack=1), ah(51) + ah(6, 1)),
            tagged(wire.ipv4(ah(6) + wire.tcp(b'!', seq=6, ack=1), proto=51), 0x0800, C_TAG),
            over_ah(wire.tcp(b'', seq=7, ack=1, fin=True)) + bytes(7),
            over_ah(make_tcp(b'opts', options=b'\x02\x04\x05\xb4')),
            # none: a Payload Length of 0, a Data Offset past the capture or below
            # 5, an option the TCP parser rejects, a later fragment
            over_ah(wire.tcp(b'x', seq=0), ah(6, 0)),
            over_ah(data_offset(wire.tcp(b'x', seq=0), 9)),
            over_ah(data_offset(wire.tcp(b'x', seq=0), 4)),
            over_ah(make_tcp(b'x', options=b'\x02\x03\x00\x00')),
            over_ah(wire.tcp(b'x', seq=0), offset=8),
        ]
        mine = self.agree(frames, tcp=[1, 2, 3, 4, 5], trace=[1, 2, 3, 4, 5])
        self.assertEqual(mine['tcp'][2]['payload'], b'hello')

    def test_tcp_behind_ipv6_extension_headers_in_ipv4_agrees(self) -> None:
        # C.f. #1597: the default engine reads IPv4's protocol as IPv6 reads a
        # Next Header, so dissects these headers there too, and the TCP after them.
        def over(protocol: int, header: bytes, segment: bytes) -> bytes:
            return wire.ethernet(wire.ipv4(header + segment, proto=protocol), 0x0800)

        frames = [over(protocol, header, wire.tcp(b'data', seq=number, sport=1000 + number))
                  for number, (_, protocol, header) in enumerate(IPV4_EXTENSION_HEADERS)]
        frames += [
            # two, then AH after one, tagged
            over(0, options_header(60) + options_header(6), wire.tcp(b'data', seq=7)),
            over(60, options_header(51) + ah(6), wire.tcp(b'data', seq=8)),
            tagged(wire.ipv4(options_header(6) + wire.tcp(b'data', seq=9), proto=60), 0x0800, C_TAG),
            # none: an option the default engine rejects, a header cut short, a HIP
            # Header Length under 4, Shim6, and a TCP option behind it the TCP parser rejects
            over(60, options_header(6, b'\x01\x09' + bytes(4)), wire.tcp(b'data', seq=10)),
            wire.ethernet(wire.ipv4(options_header(6)[:4], proto=60), 0x0800),
            wire.ethernet(wire.ipv4(bytes([6, 0, 0, 0]), proto=43), 0x0800),
            over(139, bytes([6, 3, 0x01, 0x21]) + bytes(28), wire.tcp(b'data', seq=11)),
            over(140, bytes([6, 0, 0x80, 0]) + bytes(4), wire.tcp(b'data', seq=12)),
            over(60, options_header(6), make_tcp(b'x', options=b'\x02\x03\x00\x00')),
        ]
        self.agree(frames, tcp=list(range(1, 11)), trace=list(range(1, 11)))

    def test_ipv4_options_agree(self) -> None:
        frames = []
        for options in (*GOOD_IPV4_OPTIONS, *BAD_IPV4_OPTIONS):
            segment = make_tcp(b'data', src_port=1000 + len(frames))
            frames += [
                wire.ethernet(make_ipv4(segment, options=options), 0x0800),
                tagged(make_ipv4(segment, options=options), 0x0800, C_TAG),
                wire.ethernet(make_ipv4(b'x' * 16, protocol=17, flags=1, options=options), 0x0800),
            ]
        self.agree(frames, ipv4=list(range(1, 10)), tcp=[1, 2, 4, 5, 7, 8])

    def test_engine_warns_of_a_tunnel_behind_ah(self) -> None:
        from pcapkit import extract

        frames = (
            # a TCP header behind AH that the TCP parser rejects is no TCP at all
            wire.ethernet(wire.ipv4(ah(6) + data_offset(TCP_SEGMENT, 9), proto=51), 0x0800),
            wire.ethernet(wire.ipv4(ah(4) + wire.ipv4(TCP_SEGMENT, proto=6), proto=51), 0x0800),
        )
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'ah.pcap')
            with open(path, 'wb') as file:
                file.write(wire.pcap([(1, number, frame) for number, frame in enumerate(frames)]))
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                extractor = extract(fin=path, nofile=True, engine='pypcapfile', reassembly=True,
                                    tcp=True, trace=True, trace_fout=os.path.join(tmp, 'trace'),
                                    trace_format='json')
            try:
                self.assertEqual(extractor._exnam, 'pypcapfile')
                messages = [str(item.message) for item in caught if 'left out' in str(item.message)]
                self.assertEqual(len(messages), 1, messages)
                self.assertTrue(messages[0].startswith('Frame 2: TCP tunnelled in IP'), messages)
                self.assertEqual(len(extractor.reassembly.tcp), 0)
            finally:
                close_extractor(extractor)


if __name__ == '__main__':
    unittest.main()
