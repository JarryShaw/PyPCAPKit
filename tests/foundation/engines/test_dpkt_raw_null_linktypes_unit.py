# -*- coding: utf-8 -*-
"""The DPKT engine reads raw-IP and BSD loopback frames as the default engine does.

GitHub issues #1502 and #1574. :meth:`DPKT._get_protocol
<pcapkit.foundation.engines.dpkt.DPKT._get_protocol>` knew Ethernet, IPv4 and
IPv6 only, so a ``LINKTYPE_RAW`` (101), ``LINKTYPE_NULL`` (0) or
``LINKTYPE_LOOP`` (108) frame was kept as raw data with a warning. Raw IP is now
read as IPv4 or IPv6 by its version nibble, and both loopback link types by the
address family, as :class:`~pcapkit.protocols.link.loopback.Loopback` reads
them, with the network layer where :mod:`pcapkit.toolkit.dpkt` looks for it.

Each case writes a capture built here to a temporary directory. Everything from
:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import os
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.protocols.link.test_loopback_unit import IPV4, IPV6, _pcap

HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: ``(link type, records, dpkt class name per record)``.
CAPTURES = (
    (101, [IPV4, IPV6, b'\x50' + IPV4[1:]], ['IP', 'IP6', 'RawPacket']),
    (0, [b'\x02\x00\x00\x00' + IPV4, b'\x00\x00\x00\x02' + IPV4, b'\x1e\x00\x00\x00' + IPV6,
         b'\x07\x00\x00\x00' + IPV4], ['Loopback'] * 4),
    # LINKTYPE_LOOP is network byte order, so a little-endian family 2 is not IPv4
    (108, [b'\x00\x00\x00\x02' + IPV4, b'\x00\x00\x00\x18' + IPV6, b'\x02\x00\x00\x00' + IPV4],
     ['Loopback'] * 3),
)


@unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
class TestDPKTRawAndLoopback(unittest.TestCase):
    """Pin the DPKT engine's raw-IP and loopback link types against the default engine's."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self._tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self._tmp.cleanup)

    def _extract(self, linktype: int, records: 'list[bytes]', engine: str):  # type: ignore[no-untyped-def]
        import pcapkit

        path = os.path.join(self._tmp.name, f'{linktype}.pcap')
        with open(path, 'wb') as file:
            file.write(_pcap(linktype, records))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return pcapkit.extract(fin=path, engine=engine, nofile=True, store=True,
                                   reassembly=True, ip=True)

    def test_frames_parse_into_their_network_layer(self) -> None:
        import dpkt

        from pcapkit.toolkit.dpkt import ipv4_reassembly

        for linktype, records, names in CAPTURES:
            with self.subTest(linktype=linktype):
                extractor = self._extract(linktype, records, 'dpkt')
                self.assertEqual([type(frame).__name__ for frame in extractor.frame], names)
                for frame, record in zip(extractor.frame, records):
                    loopback = type(frame).__name__ == 'Loopback'
                    network = frame.data if loopback else frame
                    if isinstance(network, (dpkt.ip.IP, dpkt.ip6.IP6)):
                        if loopback:  # named as dpkt.ethernet.Ethernet names it
                            self.assertIs(getattr(frame, type(network).__name__.lower()), network)
                        if isinstance(network, dpkt.ip.IP):
                            self.assertIsNotNone(ipv4_reassembly(frame, 0.0, count=1))
                    else:  # any other family or version is kept as octets
                        self.assertEqual(network if loopback else frame.data,
                                         record[4:] if loopback else record)

    def test_reassembly_inputs_match_the_default_engine(self) -> None:
        for linktype, records, _ in CAPTURES:
            with self.subTest(linktype=linktype):
                default = self._extract(linktype, records, 'default')
                dpkt = self._extract(linktype, records, 'dpkt')
                self.assertEqual(len(dpkt.reassembly.ipv4), len(default.reassembly.ipv4))
                self.assertEqual([datagram.packet for datagram in dpkt.reassembly.ipv4],
                                 [datagram.packet for datagram in default.reassembly.ipv4])

    def test_get_protocol_by_link_type(self) -> None:
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.dpkt import DPKT

        engine = DPKT.__new__(DPKT)
        engine._expkg = dpkt
        engine._extmp = None
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertIs(engine._get_protocol(LinkType.RAW, IPV4), dpkt.ip.IP)
            self.assertIs(engine._get_protocol(LinkType.RAW, IPV6), dpkt.ip6.IP6)
            self.assertEqual(engine._get_protocol(LinkType.RAW, b'\x50').__name__, 'RawPacket')
            self.assertEqual(engine._get_protocol(LinkType.RAW).__name__, 'RawPacket')
            for code in (LinkType.NULL, LinkType.LOOP):
                with self.subTest(code=code):
                    self.assertTrue(issubclass(engine._get_protocol(code), dpkt.loopback.Loopback))
                    # built once, not once per packet
                    self.assertIs(engine._get_protocol(code), engine._get_protocol(code))
            self.assertIsNot(engine._get_protocol(LinkType.NULL), engine._get_protocol(LinkType.LOOP))

    def test_loopback_class_is_keyed_by_every_class_it_holds(self) -> None:
        """A new ``dpkt.ip.IP`` -- e.g. after a reload -- gets a class that parses into it."""
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.dpkt import _loopback_protocol

        base, ip, ip6 = dpkt.loopback.Loopback, dpkt.ip.IP, dpkt.ip6.IP6
        for layer, record in ((ip, b'\x02\x00\x00\x00' + IPV4), (ip6, b'\x1e\x00\x00\x00' + IPV6)):
            other = type(layer.__name__, (layer,), {})
            args = (base, other, ip6) if layer is ip else (base, ip, other)
            with self.subTest(layer=layer.__name__):
                cls = _loopback_protocol(*args, LinkType.NULL.value)
                self.assertIsNot(cls, _loopback_protocol(base, ip, ip6, LinkType.NULL.value))
                self.assertIs(type(cls(record).data), other)

    def test_loop_family_is_network_byte_order(self) -> None:
        import dpkt

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.dpkt import DPKT

        engine = DPKT.__new__(DPKT)
        engine._expkg = dpkt
        engine._extmp = None
        little = b'\x02\x00\x00\x00' + IPV4
        null = engine._get_protocol(LinkType.NULL)(little)
        loop = engine._get_protocol(LinkType.LOOP)(little)
        self.assertEqual((null.family, type(null.data)), (2, dpkt.ip.IP))
        self.assertEqual((loop.family, loop.data), (0x0200_0000, IPV4))


if __name__ == '__main__':
    unittest.main()
