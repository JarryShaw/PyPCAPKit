# -*- coding: utf-8 -*-
"""GitHub issue #2649: link type 107 reaches FRAD, and IP protocol 47 reaches GRE.

:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame` and
:class:`~pcapkit.protocols.misc.pcapng.protocol.PCAPNG` bind ``LinkType.FRELAY`` (107) to
:class:`~pcapkit.protocols.link.frad.protocol.FRAD`, and
:class:`~pcapkit.protocols.internet.internet.Internet` binds ``TransType.GRE`` (47)
to :class:`~pcapkit.protocols.link.gre.protocol.GRE`, so IPv4 and IPv6 dispatch it. The
captures and datagrams here are built octet by octet, from :rfc:`2427` and
:rfc:`2784`/:rfc:`2890`; each parses through the dissector, every frame and layer
rebuilds byte-exactly, GRE's checksum (#2618) is verified behind IPv4 and IPv6, and
flow tracing and reassembly follow the tunnel's inner flow.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: UDP 12345 to 9 (discard) carrying ``abcd``, its checksum zero (absent over IPv4).
UDP = struct.pack('>HHHH', 12345, 9, 12, 0) + b'abcd'


#: The tunnel's endpoints, and those of the datagram it carries.
OUTER, TUNNELLED = ((192, 0, 2, 1), (198, 51, 100, 1)), ((10, 0, 0, 1), (10, 0, 0, 2))


def _ipv4(proto: int, payload: bytes, *, mf: bool = False, offset: int = 0, ident: int = 1,
          ends: 'tuple[tuple[int, ...], tuple[int, ...]]' = OUTER) -> bytes:
    """An option-less IPv4 header (RFC 791) with a right header checksum."""
    head = struct.pack('>BBHHHBBH4s4s', 0x45, 0, 20 + len(payload), ident, (0x2000 if mf else 0) | offset,
                       64, proto, 0, bytes(ends[0]), bytes(ends[1]))
    return head[:10] + struct.pack('>H', wire.checksum(head)) + head[12:] + payload


def _tcp(seq: int, flags: int, data: bytes = b'') -> bytes:
    """A TCP segment from port 40000 to 80, its checksum left zero."""
    return struct.pack('>HHIIBBHHH', 40000, 80, seq, 0, 0x50, flags, 8192, 0, 0) + data


def _ipv6(nxt: int, payload: bytes) -> bytes:
    """A fixed IPv6 header (RFC 8200) carrying ``payload``."""
    return (struct.pack('>IHBB', 0x6000_0000, len(payload), nxt, 64)
            + bytes.fromhex('20010db8000000000000000000000001')
            + bytes.fromhex('20010db8000000000000000000000002') + payload)


#: The datagram the tunnels and Frame Relay frames carry: IPv4 over UDP.
INNER = _ipv4(17, UDP, ident=20, ends=TUNNELLED)


def _gre(payload: bytes, *, checksum: 'int | bool' = False, key: 'int | None' = None,
         seq: 'int | None' = None, version: int = 0) -> bytes:
    """A GRE header carrying IPv4; ``checksum`` is :data:`True` for the right one."""
    flags = ((0x8000 if checksum is not False else 0) | (0x2000 if key is not None else 0)
             | (0x1000 if seq is not None else 0) | version)
    head = struct.pack('>HH', flags, 0x0800)
    extra = b''.join(struct.pack('>I', value) for value in (key, seq) if value is not None)
    if checksum is False:
        return head + extra + payload
    value = wire.checksum(head + bytes(4) + extra + payload) if checksum is True else checksum
    return head + struct.pack('>HH', value, 0) + extra + payload


#: A Q.922 address for DLCI 16, EA set on its second octet, then UI (0x03).
Q922 = bytes.fromhex('0401') + b'\x03'

#: LinkType 107 records: direct NLPID IPv4 and IPv6, SNAP with an EtherType, Q.933.
FRELAY = (
    Q922 + b'\xcc' + INNER,
    Q922 + b'\x8e' + _ipv6(17, UDP),
    Q922 + b'\x00\x80' + bytes(3) + struct.pack('>H', 0x0800) + INNER,
    Q922 + b'\x08' + b'\x00\x01\x02\x03',
)


def _ether(ethertype: int, payload: bytes) -> bytes:
    return bytes.fromhex('020000000002' '020000000001') + struct.pack('>H', ethertype) + payload


def _pcap(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP v2.4 file of ``records`` on ``linktype``."""
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for index, record in enumerate(records):
        data += struct.pack('<IIII', 1500000000 + index, 0, len(record), len(record)) + record
    return data


def _pcapng(linktype: int, records: 'tuple[bytes, ...]') -> bytes:
    """A little-endian PCAP-NG file: one section, one interface on ``linktype``."""
    out = struct.pack('<IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28)
    out += struct.pack('<IIHHII', 1, 20, linktype, 0, 262144, 20)
    for index, record in enumerate(records):
        padded = record + bytes(-len(record) % 4)
        length = 32 + len(padded)
        out += struct.pack('<IIIIIII', 6, length, 0, 0, 1500000000 + index, len(record), len(record))
        out += padded + struct.pack('<I', length)
    return out


class TestFRADAndGREBindings(unittest.TestCase):
    """Pin LinkType 107 in both capture formats, and protocol 47 under IPv4 and IPv6."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, data: bytes, suffix: str) -> 'list':  # type: ignore[type-arg]
        import pcapkit

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, f'probe{suffix}')
            with open(path, 'wb') as file:
                file.write(data)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=path, nofile=True, store=True)
        return list(extractor.frame)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` and each layer under it rebuild byte-exactly from their info."""
        while type(layer).__name__ not in ('Raw', 'NoPayload'):
            for data in (layer.info, layer.info.to_dict()):
                with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                    self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())
            layer, kwargs = layer.payload, {}

    def _parse(self, cls: 'type', octets: bytes) -> 'tuple[object, list[tuple[type, str]]]':
        """``octets`` parsed as ``cls`` with checksums verified, and the ProtocolWarnings."""
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        with mock.patch.object(config, 'CHECKSUM_VERIFY', True), \
                warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            layer = cls(octets)
        return layer, [(item.category, str(item.message))
                       for item in caught if issubclass(item.category, ProtocolWarning)]

    def test_registered(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.link.frad.protocol import FRAD
        from pcapkit.protocols.link.gre.protocol import GRE
        from pcapkit.protocols.misc.pcap.frame.protocol import Frame
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for cls in (Frame, PCAPNG):
            with self.subTest(table=cls.__name__):
                self.assertEqual(cls.__proto__[LinkType.FRELAY], ModuleDescriptor('pcapkit.protocols.link', 'FRAD'))
                self.assertIs(cls._lookup_next_layer(cls.__proto__, FRAD.__index__()), FRAD)
        self.assertEqual(Internet.__proto__[TransType.GRE], ModuleDescriptor('pcapkit.protocols.link.gre.protocol', 'GRE'))
        for cls in (IPv4, IPv6):
            with self.subTest(table=cls.__name__):
                self.assertIs(cls.__proto__, Internet.__proto__)
                self.assertIs(cls._lookup_next_layer(cls.__proto__, GRE.__index__()), GRE)
        self.assertEqual((int(LinkType.FRELAY), int(TransType.GRE)), (107, 47))

    def test_frelay_capture(self) -> None:
        """Link type 107 carries the Q.922 address onward, with no FCS."""
        from pcapkit.const.reg.linktype import LinkType

        chains = ['FRAD:IPv4:UDP:Raw', 'FRAD:IPv6:UDP:Raw', 'FRAD:IPv4:UDP:Raw', 'FRAD:Raw']
        for pcapng, (data, suffix) in enumerate(((_pcap(LinkType.FRELAY, FRELAY), '.pcap'),
                                                 (_pcapng(LinkType.FRELAY, FRELAY), '.pcapng'))):
            with self.subTest(format=suffix):
                frames = self._extract(data, suffix)
                self.assertEqual([frame.protochain.chain for frame in frames], chains)
                for frame, record in zip(frames, FRELAY):
                    self.assertEqual(bytes(frame.payload.data), record)
                    if pcapng:
                        self._assert_rebuilds(frame, num=frame._fnum, sct=frame._sect, ctx=frame._ctx)
                    else:
                        self._assert_rebuilds(frame, num=frame._fnum, header=frame._ghdr)

                infos = [frame.payload.info for frame in frames]
                self.assertEqual([(info.dlci, info.control, info.nlpid) for info in infos],
                                 [(16, 0x03, 0xCC), (16, 0x03, 0x8E), (16, 0x03, 0x80), (16, 0x03, 0x08)])
                self.assertEqual((infos[2].snap_oui, infos[2].snap_pid), (bytes(3), 0x0800))
                self.assertEqual(bytes(frames[3].payload.payload.data), b'\x00\x01\x02\x03')

    def test_gre_over_ip(self) -> None:
        """IPv4 and IPv6 hand protocol 47 to GRE, which hands its EtherType on."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        cases = [
            (IPv4, _ipv4(47, _gre(INNER)), 4, None, None),
            (IPv4, _ipv4(47, _gre(INNER, checksum=True, key=0x11223344, seq=7)), 16, 0x11223344, 7),
            (IPv6, _ipv6(47, _gre(INNER, checksum=True)), 8, None, None),
        ]
        for cls, octets, length, key, seq in cases:
            with self.subTest(carrier=cls.__name__, length=length):
                layer, messages = self._parse(cls, octets)
                self.assertEqual(messages, [])
                self.assertEqual(layer.protochain.chain, f'{cls.__name__}:GRE:IPv4:UDP:Raw')
                info = layer.payload.info
                self.assertEqual((info.len, info.key, info.sequence_number), (length, key, seq))
                self.assertEqual(int(info.protocol_type), 0x0800)
                self.assertEqual(bytes(layer.payload.payload.data), INNER)
                self._assert_rebuilds(layer)

        data = _pcap(1, (_ether(0x0800, _ipv4(47, _gre(INNER))),))
        self.assertEqual([frame.protochain.chain for frame in self._extract(data, '.pcap')],
                         ['Ethernet:IPv4:GRE:IPv4:UDP:Raw'])

    def test_gre_checksum_over_ip(self) -> None:
        """The RFC 2784 checksum is verified behind IPv4 and IPv6, and not in a fragment."""
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.warnings import ChecksumWarning

        good = _gre(INNER, checksum=True)
        value = int.from_bytes(good[4:6], 'big')
        bad = _gre(INNER, checksum=value ^ 0x0101)
        warning = (ChecksumWarning, f'GRE: checksum {value ^ 0x0101:#06x} is wrong; {value:#06x} expected')
        cases = {
            'valid': (IPv4, _ipv4(47, good), ChecksumStatus.VALID, []),
            'valid over IPv6': (IPv6, _ipv6(47, good), ChecksumStatus.VALID, []),
            'invalid': (IPv4, _ipv4(47, bad), ChecksumStatus.INVALID, [warning]),
            'C clear': (IPv4, _ipv4(47, _gre(INNER)), ChecksumStatus.NOT_COMPUTED, []),
            'fragment': (IPv4, _ipv4(47, bad, mf=True), ChecksumStatus.NO_PSEUDO_HEADER, []),
            # The IP header states the payload length, which the cooked header cannot.
            'cut short': (IPv4, _ipv4(47, good)[:-6], ChecksumStatus.TRUNCATED, []),
            'cut short over IPv6': (IPv6, _ipv6(47, good)[:-6], ChecksumStatus.TRUNCATED, []),
        }
        self.assertEqual(wire.checksum(good), 0)
        for name, (cls, octets, status, expected) in cases.items():
            with self.subTest(name):
                layer, messages = self._parse(cls, octets)
                self.assertEqual(type(layer.payload).__name__, 'GRE')
                self.assertEqual((layer.payload.info.checksum_status, messages), (status, expected))
                self.assertEqual(cls.from_data(layer.info).data, octets)

    def test_a_refused_gre_header_is_kept_raw(self) -> None:
        """Version 1 is refused, and IPv4 keeps it as Raw, as LinuxSLL does (#2588)."""
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        octets = _ipv4(47, _gre(INNER, version=1))
        layer, messages = self._parse(IPv4, octets)
        self.assertEqual(messages, [])
        self.assertIsInstance(layer.payload, Raw)
        self.assertEqual(layer.payload.info.error, 'GRE: invalid version: 1')
        self.assertEqual(IPv4.from_data(layer.info).data, octets)

    def test_analysis_follows_the_inner_flow(self) -> None:
        """TCP through the tunnel is traced and reassembled under the tunnelled
        datagram's addresses (#1581), and a fragmented outer datagram
        reassembles to a parsed GRE layer.
        """
        import ipaddress

        import pcapkit

        segments = (_tcp(1000, 0x02), _tcp(1001, 0x18, b'hello '), _tcp(1007, 0x18, b'world'), _tcp(1012, 0x11))
        records = [_ether(0x0800, _ipv4(47, _gre(_ipv4(6, segment, ident=10 + index, ends=TUNNELLED)),
                                        ident=100 + index))
                   for index, segment in enumerate(segments)]
        tunnelled = _gre(INNER)
        records += [_ether(0x0800, _ipv4(47, tunnelled[:16], mf=True, ident=200)),
                    _ether(0x0800, _ipv4(47, tunnelled[16:], offset=2, ident=200))]

        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'tunnel.pcap')
            with open(path, 'wb') as file:
                file.write(_pcap(1, tuple(records)))
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                with pcapkit.extract(fin=path, nofile=True, store=True, reassembly=True, ipv4=True, tcp=True,
                                     trace=True, trace_fout=os.path.join(tmp, 'trace')) as extraction:
                    flows, reassembly = extraction.trace.tcp, extraction.reassembly

        self.assertEqual([(flow.index, flow.label.split('-')[:2]) for flow in flows],
                         [((1, 2, 3, 4), ['10.0.0.1_40000', '10.0.0.2_80'])])
        inner = (ipaddress.ip_address('10.0.0.1'), 40000), (ipaddress.ip_address('10.0.0.2'), 80)
        self.assertEqual([((datagram.id.src, datagram.id.dst), bytes(datagram.payload), bool(datagram.completed))
                          for datagram in reassembly.tcp], [(inner, b'hello world', True)])
        fragmented = [datagram for datagram in reassembly.ipv4 if datagram.id.id == 200]
        self.assertEqual([(bool(datagram.completed), datagram.packet.protochain.chain) for datagram in fragmented],
                         [(True, 'GRE:IPv4:UDP:Raw')])


if __name__ == '__main__':
    unittest.main()
