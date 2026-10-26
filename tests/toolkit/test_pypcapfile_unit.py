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
import struct
import types
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): drives a third-party engine whose installable releases vary by
#: interpreter.
__tier__ = 'ALL'

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
        # form (see #743) -- not an ``int``, so this stand-in exercises the same
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
                ns_resolution: bool = False, capture_len: int = 86, packet_len: int = 86,
                header=None):
    """Build a stand-in for :class:`pcapfile.structs.pcap_packet`.

    Packets given the same ``header`` are of one capture; by default each is of its own.

    """
    return types.SimpleNamespace(
        header=[types.SimpleNamespace(ns_resolution=ns_resolution)] if header is None else header,
        timestamp=timestamp,
        timestamp_us=timestamp_us,
        capture_len=capture_len,
        packet_len=packet_len,
        packet=layer,
    )


def ipv6_frame(nxt: int, payload: bytes = b'\x00' * 20) -> FakeEthernet:
    """An Ethernet frame carrying IPv6 whose Next Header is ``nxt``, as PyPCAPFile leaves it."""
    packet = (b'\x60\x00\x00\x00' + len(payload).to_bytes(2, 'big') + bytes([nxt, 64])
              + bytes(range(32)) + payload)
    frame = FakeEthernet(binascii.hexlify(packet))
    frame.type = 0x86DD
    return frame


def with_data_offset(segment: bytes, words: int) -> bytes:
    """``segment``, a TCP segment, with its Data Offset set to ``words``."""
    return segment[:12] + bytes([words << 4 | segment[12] & 0x0F]) + segment[13:]


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

    def test_packet2dict_reports_an_undecoded_frames_octets(self) -> None:
        # #1667: the engine hands a frame left undecoded over hex-encoded
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import packet2dict

        frame = make_ipv4(make_tcp(b'x' * 7))
        self.assertEqual(len(frame), 47)
        for link in (LinkType.RAW, LinkType.LINUX_SLL, LinkType.ETHERNET):
            with self.subTest(link=link):
                info = packet2dict(make_packet(binascii.hexlify(frame)), data_link=link)
                self.assertEqual(info[link.name], {'raw_len': 47, 'raw': frame})

    ##########################################################################
    # Address and hex-text parsing helpers (see #743).
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
            # ``int`` is deliberately rejected, not merely unparsed: accepting it
            # would only keep an int-typed stand-in passing, the kind of fixture
            # that hides #743. See ``_parse_ipv4_address``'s docstring.
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
        ):
            with self.subTest(case=label):
                self.assertIsNone(tcp_reassembly(packet, count=1))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=1))

    def test_a_later_fragment_carries_no_tcp_header(self) -> None:
        # #1576: from its offset on, a fragment's data is no TCP header
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import _transport, tcp_reassembly, tcp_traceflow

        segment = make_tcp(b'A' * 20)
        later = make_packet(FakeEthernet(FakeIP(segment, off=185)))
        self.assertIsNone(_transport(later.packet.payload))
        self.assertIsNone(tcp_reassembly(later, count=1))
        self.assertIsNone(tcp_traceflow(later, data_link=LinkType.ETHERNET, count=1))
        self.assertEqual(_transport(FakeIP(segment, flags=0b001)), segment)  # a first fragment

    def test_the_tcp_segment_ends_at_the_total_length(self) -> None:
        # #1577: the Ethernet padding after the datagram is no part of the segment
        from pcapkit.toolkit.pypcapfile import _transport

        segment = make_tcp(b'x')
        padded = segment + b'\x00' * 5
        for label, fields, expected in (
            ('padded', {'len': 41}, segment),
            ('with options', {'len': 45, 'hl': 6, 'opt': b'\x01' * 4}, segment),
            ('total length 0, as TSO leaves it (GH#1547)', {'len': 0}, padded),
            ('total length short of the header', {'len': 19}, None),
        ):
            with self.subTest(case=label):
                self.assertEqual(_transport(FakeIP(padded, **fields)), expected)

    def test_a_data_offset_below_five_words_is_no_tcp_header(self) -> None:
        # #1590: the header is not read as 20 octets
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import _transport, tcp_reassembly, tcp_traceflow

        segment = make_tcp(b'data')
        for words in range(5):
            with self.subTest(data_offset=words):
                packet = make_packet(FakeEthernet(FakeIP(with_data_offset(segment, words))))
                self.assertIsNone(_transport(packet.packet.payload))
                self.assertIsNone(tcp_reassembly(packet, count=1))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=1))
        self.assertEqual(_transport(FakeIP(segment)), segment)

    def test_an_ihl_past_the_captured_octets_is_no_ipv4_layer(self) -> None:
        # #1591: pypcapfile slices the options at the IHL, however few octets
        # there are -- here up to 20 short of a declared 60
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import _network, ipv4_reassembly, tcp_reassembly, tcp_traceflow

        for short in (1, 4, 8, 20):
            with self.subTest(octets_short=short):
                options = binascii.hexlify(bytes(40 - short))
                cut = make_packet(FakeEthernet(FakeIP(b'', hl=15, flags=0b001, opt=options)))
                self.assertIsNone(_network(cut))
                self.assertIsNone(ipv4_reassembly(cut, count=1))
                self.assertIsNone(tcp_reassembly(cut, count=1))
                self.assertIsNone(tcp_traceflow(cut, data_link=LinkType.ETHERNET, count=1))

        whole = FakeIP(b'', hl=15, flags=0b001, opt=binascii.hexlify(bytes(40)))
        self.assertIs(_network(make_packet(FakeEthernet(whole))), whole)

    def test_tcp_over_ipv6_warns_once_per_capture(self) -> None:
        # #1513
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow
        from pcapkit.utilities.warnings import AttributeWarning

        first, second = [types.SimpleNamespace(ns_resolution=False)], [types.SimpleNamespace(ns_resolution=False)]
        frames = (
            (first, ipv6_frame(17)),                    # UDP over IPv6
            (first, FakeEthernet(FakeIP(b'x' * 40, p=17))),
            (first, ipv6_frame(6)),                     # TCP over IPv6: warns
            (second, ipv6_frame(6)),                    # another capture: warns of its own
            (first, ipv6_frame(6)),
            (second, ipv6_frame(6)),
        )
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for count, (header, frame) in enumerate(frames, 1):
                packet = make_packet(frame, header=header)
                self.assertIsNone(tcp_reassembly(packet, count=count))
                self.assertIsNone(tcp_traceflow(packet, data_link=LinkType.ETHERNET, count=count))
        self.assertEqual([str(item.message) for item in caught if item.category is AttributeWarning], [
            f"Frame {count}: TCP over IPv6 is left out of TCP reassembly and flow tracing, as 'pypcapfile' "
            'has no IPv6 decoder; later such frames of this capture are left out without another warning'
            for count in (3, 4)])

    def test_either_tcp_adapter_alone_warns_of_tcp_over_ipv6(self) -> None:
        # #1513: a capture whose TCP over IPv6 reaches only one of the two
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import tcp_reassembly, tcp_traceflow
        from pcapkit.utilities.warnings import AttributeWarning

        for adapter, kwargs in ((tcp_reassembly, {}), (tcp_traceflow, {'data_link': LinkType.ETHERNET})):
            with self.subTest(adapter=adapter.__name__):
                header = [types.SimpleNamespace(ns_resolution=False)]
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    for count in (1, 2):
                        self.assertIsNone(adapter(make_packet(ipv6_frame(6), header=header), count=count,
                                                  **kwargs))
                self.assertEqual([(item.category, str(item.message)[:37]) for item in caught],
                                 [(AttributeWarning, 'Frame 1: TCP over IPv6 is left out of')])

    def test_tcp_over_ipv6_is_read_off_a_whole_ipv6_header_only(self) -> None:
        # #1513: the Next Header of an IPv6 frame, whose 40-octet header was captured
        from pcapkit.toolkit.pypcapfile import tcp_reassembly

        whole = binascii.unhexlify(ipv6_frame(6).payload)[:40]
        cases = [(f'{cut} octets', 0x86DD, whole[:cut], 0) for cut in (0, 6, 7, 39)]
        cases += [(f'ethertype {ethertype:#06x}', ethertype, whole, 0) for ethertype in (0x0800, 0x0806, 0x8100)]
        cases.append(('whole', 0x86DD, whole, 1))
        for label, ethertype, data, warns in cases:
            with self.subTest(case=label):
                frame = FakeEthernet(binascii.hexlify(data))
                frame.type = ethertype
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    self.assertIsNone(tcp_reassembly(make_packet(frame), count=1))
                self.assertEqual(len(caught), warns, [str(item.message) for item in caught])

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

    def test_tcp_over_ipv6_warns_once_per_capture_of_ctypes_records(self) -> None:
        # #1513: pypcapfile's record reaches its savefile header through a
        # ``ctypes`` pointer field, which builds a new pointer on every read
        from pcapkit.toolkit.pypcapfile import tcp_reassembly

        class Header(ctypes.Structure):
            _fields_ = [('ns_resolution', ctypes.c_bool)]

        class Record(ctypes.Structure):  # as pcapfile.structs.pcap_packet
            _fields_ = [('header', ctypes.POINTER(Header))]

        first, second = Header(), Header()
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for count, header in enumerate((first, first, second, first, second), 1):
                record = Record(ctypes.pointer(header))
                record.packet = ipv6_frame(6)
                self.assertIsNone(tcp_reassembly(record, count=count))
        self.assertEqual([str(item.message)[:8] for item in caught], ['Frame 1:', 'Frame 3:'])

    def test_the_captures_warned_of_tcp_over_ipv6_are_bounded(self) -> None:
        from pcapkit.toolkit import pypcapfile as toolkit

        from pcapkit.utilities import config

        self.assertEqual(config.IPV6_TCP_WARNED_LIMIT, 32)
        headers = [[types.SimpleNamespace(ns_resolution=False)] for _ in range(33)]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            for header in headers:
                toolkit.tcp_reassembly(make_packet(ipv6_frame(6), header=header), count=1)
            toolkit.tcp_reassembly(make_packet(ipv6_frame(6), header=headers[0]), count=2)   # forgotten
            toolkit.tcp_reassembly(make_packet(ipv6_frame(6), header=headers[-1]), count=3)  # remembered
        self.assertEqual([str(item.message)[:8] for item in caught], ['Frame 1:'] * 33 + ['Frame 2:'])
        self.assertEqual(len(toolkit._ipv6_tcp_warned), 32)  # pylint: disable=protected-access


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
        self.assertEqual(data.header, segment[:20])
        self.assertEqual(bytes(data.payload), b'body')
        self.assertEqual(data.index, 5)
        self.assertTrue(data.syn)
        self.assertFalse(data.fin)
        self.assertEqual(data.src, ipaddress.IPv4Address('10.1.1.2'))
        self.assertEqual(data.dst, ipaddress.IPv4Address('10.1.1.3'))
        self.assertEqual(data.srcport, 51000)
        self.assertEqual(data.dstport, 22)
        self.assertEqual(data.timestamp, 1511106545.471719)
        self.assertEqual(data.frame['ETHERNET']['IP']['src'], '10.1.1.2')

    def test_the_adapters_own_checks_hold_on_the_real_decoder(self) -> None:
        from pcapfile.protocols.network.ip import IP

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcapfile import ipv4_reassembly, tcp_reassembly, tcp_traceflow

        def packet(raw: bytes):
            return make_packet(FakeEthernet(IP(raw)))

        segment = make_tcp(b'x', flags=0b00011000)
        # #1577: a datagram padded to the Ethernet minimum
        padded = packet(make_ipv4(segment) + b'\x00' * 5)
        data = tcp_reassembly(padded, count=1)
        self.assertEqual((data.header, bytes(data.payload), data.len), (segment[:20], b'x', 1))
        self.assertEqual(bytes(tcp_traceflow(padded, data_link=LinkType.ETHERNET, count=1).payload), b'x')
        # #1576, #1590: a later fragment, and a Data Offset of 4
        for label, raw in (('later fragment', make_ipv4(b'A' * 40, offset=185)),
                           ('data offset 4', make_ipv4(with_data_offset(segment, 4)))):
            with self.subTest(case=label):
                self.assertIsNone(tcp_reassembly(packet(raw), count=2))
                self.assertIsNone(tcp_traceflow(packet(raw), data_link=LinkType.ETHERNET, count=2))
        # #1591: an IHL of 15 in a 40-octet packet
        cut = bytes([0x4F]) + make_ipv4(bytes(20), protocol=17, flags=0b001)[1:]
        self.assertIsNone(ipv4_reassembly(packet(cut), count=3))

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

        # Guards against a partial un-hexing: ``opt`` un-hexed while the nested
        # ``'Raw'`` payload stays hex-encoded (and twice its true length) in the
        # very same dict.
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


if __name__ == '__main__':
    unittest.main()
