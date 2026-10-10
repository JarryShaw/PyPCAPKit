# -*- coding: utf-8 -*-
"""GitHub issue #1574: the BSD loopback encapsulation is dissected.

A frame on a ``LINKTYPE_NULL`` (0) or ``LINKTYPE_LOOP`` (108) interface was
kept whole as :class:`~pcapkit.protocols.misc.raw.Raw`, because neither link
type had a dissector: frames 3 and 4 of ``many_interfaces.pcapng`` read ``NULL``
where scapy reads IPv4. :class:`~pcapkit.protocols.link.loopback.Loopback`
reads the 4-octet address family -- in the capturing host's byte order for
``NULL``, in network byte order for ``LOOP`` -- and dispatches 2 to IPv4 and 24,
28 and 30 to IPv6. Both link types are registered against it for PCAP and
PCAP-NG.

Every layer is rebuilt byte-exactly in both byte orders: parse then rebuild,
make then parse, and ``from_data(info.to_dict())``. Each case builds its own
octets, and captures are written to a temporary directory. Everything from
:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import sys
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: An IPv6 header (next header UDP) and an 8-octet UDP header.
IPV6 = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
        + bytes.fromhex('3039003500080000'))

#: ``(family, payload, next layer class name)`` for every registered family.
FAMILIES = ((2, IPV4, 'IPv4'), (24, IPV6, 'IPv6'), (28, IPV6, 'IPv6'), (30, IPV6, 'IPv6'))


def _header(family: int, byteorder: str) -> bytes:
    return family.to_bytes(4, byteorder)  # type: ignore[arg-type]


def _pcap(linktype: int, records: 'list[bytes]') -> bytes:
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for record in records:
        data += struct.pack('<IIII', 1500000000, 0, len(record), len(record)) + record
    return data


def _block(kind: int, body: bytes) -> bytes:
    body += bytes(-len(body) % 4)
    length = len(body) + 12
    return struct.pack('<II', kind, length) + body + struct.pack('<I', length)


def _pcapng(linktype: int, records: 'list[bytes]') -> bytes:
    data = (_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
            + _block(1, struct.pack('<HHI', linktype, 0, 65535)))
    for record in records:
        data += _block(6, struct.pack('<IIIII', 0, 0, 0, len(record), len(record)) + record)
    return data


class TestLoopback(unittest.TestCase):
    """Pin the BSD loopback layer, alone and under both capture formats."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_each_family_in_both_byte_orders(self) -> None:
        from pcapkit.protocols.link.loopback import Loopback

        for family, payload, name in FAMILIES:
            for byteorder in ('little', 'big'):
                with self.subTest(family=family, byteorder=byteorder):
                    raw = _header(family, byteorder) + payload
                    parsed = Loopback(raw, len(raw))
                    self.assertEqual(parsed.info.family, family)
                    self.assertEqual(parsed.info.byteorder, byteorder)
                    self.assertEqual(parsed.protocol, family)
                    self.assertEqual((parsed.name, parsed.length), ('BSD Loopback Encapsulation', 4))
                    self.assertEqual(type(parsed.payload).__name__, name)
                    self.assertEqual(parsed.protochain.chain, f'Loopback:{name}:UDP')
                    self.assertEqual(parsed.data, raw)
                    self._assert_rebuilds(parsed)

    def test_other_family_is_kept_raw(self) -> None:
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.misc.raw import Raw

        for family, byteorder in ((7, 'little'), (23, 'big'), (0, 'little'), (0x0102, 'big')):
            with self.subTest(family=family, byteorder=byteorder):
                raw = _header(family, byteorder) + IPV4
                parsed = Loopback(raw, len(raw))
                self.assertEqual(parsed.info.family, family)
                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_make_then_parse(self) -> None:
        from pcapkit.protocols.link.loopback import Loopback

        for family, payload, name in FAMILIES:
            for byteorder in ('little', 'big'):
                with self.subTest(family=family, byteorder=byteorder):
                    made = Loopback(family=family, byteorder=byteorder, payload=payload).data
                    self.assertEqual(made, _header(family, byteorder) + payload)
                    parsed = Loopback(made, len(made))
                    self.assertEqual((parsed.info.family, parsed.info.byteorder), (family, byteorder))
                    self.assertEqual(type(parsed.payload).__name__, name)
                    self._assert_rebuilds(parsed)
        self.assertEqual(Loopback().data, _header(2, sys.byteorder))

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in ({'byteorder': 'native'}, {'family': -1}, {'family': 0x1_0000_0000}):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                Loopback(**kwargs)

    def test_registered_for_null_and_loop(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for cls in (Frame, PCAPNG):
            for code in (LinkType.NULL, LinkType.LOOP):
                with self.subTest(table=cls.__name__, code=code):
                    self.assertEqual(cls.__proto__[code], ModuleDescriptor('pcapkit.protocols.link', 'Loopback'))
                    self.assertIs(cls._lookup_next_layer(cls.__proto__, code), Loopback)
        self.assertEqual(Loopback.__index__(), LinkType.NULL)

    def _extract(self, octets: bytes, suffix: str):  # type: ignore[no-untyped-def]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'loopback{suffix}')
            with open(path, 'wb') as file:
                file.write(octets)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                return pcapkit.extract(fin=path, nofile=True, store=True, reassembly=True, ip=True)

    def _assert_capture(self, linktype: int, records: 'list[tuple[bytes, str]]', ipv4: int) -> 'list':
        """Extract ``records`` under ``linktype`` in both formats; check chains and rebuilds."""
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.pcap.frame import Frame

        frames = []
        for build, suffix in ((_pcap, '.pcap'), (_pcapng, '.pcapng')):
            with self.subTest(linktype=linktype, format=suffix):
                extractor = self._extract(build(linktype, [record for record, _ in records]), suffix)
                self.assertEqual([frame.protochain.chain for frame in extractor.frame],
                                 [chain for _, chain in records])
                self.assertEqual(len(extractor.reassembly.ipv4), ipv4)
                for frame in extractor.frame:
                    if isinstance(frame, Frame):
                        self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)
                    else:
                        self._assert_rebuilds(frame, num=frame._fnum, sct=frame._sect, ctx=frame._ctx)
                    layer = frame.payload
                    while not isinstance(layer, NoPayload):
                        self._assert_rebuilds(layer)
                        layer = layer.payload
                frames.extend(extractor.frame)
        return frames

    def test_null_captures_dissect_in_either_byte_order(self) -> None:
        self._assert_capture(0, [
            (_header(2, 'little') + IPV4, 'Loopback:IPv4:UDP'),
            (_header(30, 'little') + IPV6, 'Loopback:IPv6:UDP'),
            (_header(2, 'big') + IPV4, 'Loopback:IPv4:UDP'),
            (_header(24, 'big') + IPV6, 'Loopback:IPv6:UDP'),
            (_header(7, 'little') + IPV4, 'Loopback:Raw'),
        ], ipv4=2)

    def test_loop_captures_dissect_in_network_byte_order(self) -> None:
        self._assert_capture(108, [
            (_header(2, 'big') + IPV4, 'Loopback:IPv4:UDP'),
            (_header(24, 'big') + IPV6, 'Loopback:IPv6:UDP'),
            (_header(30, 'big') + IPV6, 'Loopback:IPv6:UDP'),
            (_header(7, 'big') + IPV4, 'Loopback:Raw'),
        ], ipv4=1)

    def test_little_endian_loop_family_is_not_ipv4(self) -> None:
        """``LINKTYPE_LOOP`` is network byte order: ``02 00 00 00`` is family 0x02000000."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.protocols.misc.raw import Raw

        raw = _header(2, 'little') + IPV4
        frames = self._assert_capture(108, [(raw, 'Loopback:Raw')], ipv4=0)
        parsed = Loopback(raw, len(raw), alias=LinkType.LOOP)
        for layer in [frame.payload for frame in frames] + [parsed]:
            with self.subTest(layer=layer):
                self.assertEqual((layer.info.family, layer.info.byteorder), (0x0200_0000, 'big'))
                self.assertIsInstance(layer.payload, Raw)
        self._assert_rebuilds_info(parsed)

    def _assert_rebuilds_info(self, layer) -> None:  # type: ignore[no-untyped-def]
        """``from_data`` of ``layer``'s info, or of its dict, yields that same info and octets."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(data=type(data).__name__):
                rebuilt = type(layer).from_data(data)
                self.assertEqual(rebuilt.info, layer.info)
                self.assertEqual(rebuilt.data.hex(), layer.data.hex())

    def test_rebuild_keeps_the_parsed_info(self) -> None:
        """Every family, in either byte order, under every link-type hint, rebuilds to its own info."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.loopback import Loopback

        for family in (0, 2, 7, 23, 24, 28, 30):
            payload = IPV6 if family in (24, 28, 30) else IPV4
            for byteorder in ('little', 'big'):
                raw = _header(family, byteorder) + payload
                for hint in ({}, {'alias': LinkType.NULL}, {'alias': LinkType.LOOP}):
                    with self.subTest(family=family, byteorder=byteorder, **hint):
                        parsed = Loopback(raw, len(raw), **hint)
                        if hint.get('alias') == LinkType.LOOP:
                            expected = (int.from_bytes(raw[:4], 'big'), 'big')
                        else:  # inferred; a family of 0 reads the same either way
                            expected = (family, 'little' if family == 0 else byteorder)
                        self.assertEqual((parsed.info.family, parsed.info.byteorder), expected)
                        self.assertEqual(parsed.data, raw)
                        self._assert_rebuilds_info(parsed)

    def test_read_rejects_an_unknown_byteorder(self) -> None:
        from pcapkit.protocols.link.loopback import Loopback
        from pcapkit.utilities.exceptions import ProtocolError

        raw = _header(2, 'little') + IPV4
        with self.assertRaises(ProtocolError):
            Loopback(raw, len(raw), byteorder='native')

    def test_family_byteorder(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.link.loopback import family_byteorder

        for octets, null in ((b'\x02\x00\x00\x00', 'little'), (b'\x00\x00\x00\x02', 'big'),
                             (bytes(4), 'little'), (b'\x02\x00\x02\x00', 'little')):
            with self.subTest(octets=octets.hex()):
                self.assertEqual(family_byteorder(octets), null)
                self.assertEqual(family_byteorder(octets, LinkType.NULL), null)
                self.assertEqual(family_byteorder(octets, LinkType.LOOP), 'big')

    def test_short_header_is_kept_raw(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        extractor = self._extract(_pcap(0, [b'\x02\x00\x00']), '.pcap')
        frame = extractor.frame[0]
        self.assertIsInstance(frame.payload, Raw)
        self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)


if __name__ == '__main__':
    unittest.main()
