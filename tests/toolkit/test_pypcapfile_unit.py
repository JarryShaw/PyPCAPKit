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

import importlib.util
import ipaddress
import struct
import types
import unittest

from tests._support import purge_modules

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
        self.src = int(ipaddress.IPv4Address('10.1.1.2'))
        self.dst = int(ipaddress.IPv4Address('10.1.1.3'))
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


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

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
        self.assertEqual(ethernet['src'], b'\xa4\x5e\x60\xd9\x6b\x97')
        self.assertEqual(ethernet['dst'], b'\x40\x33\x1a\xd1\x85\x1c')
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


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_PYPCAPFILE, 'pypcapfile not installed or not importable')
class PyPCAPFileToolkitAgainstRealDecodersTests(unittest.TestCase):
    """Tests that need :mod:`pcapfile`'s own decoders to be meaningful."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

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
        self.assertEqual(data.last, 1021)
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


if __name__ == '__main__':
    unittest.main()
