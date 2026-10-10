# -*- coding: utf-8 -*-
"""The DPKT engine resolves every PCAP-NG packet against its own interface.

GitHub issue #1379: :class:`dpkt.pcapng.Reader` reads only the first Interface
Description Block (IDB) of a file, so the DPKT engine gave every packet the
first interface's link type and ``if_tsresol`` -- a packet on a nanosecond
interface came out 1000 times too late, a raw-IP interface was dissected as
Ethernet, and a later section's interfaces were never read at all.

Each case writes a capture built here to a temporary directory: two sections of
opposite byte order, whose interfaces differ in link type, ``if_tsresol`` and
``if_tsoffset``. Everything from :mod:`pcapkit` is imported inside each test,
after :func:`~tests._support.reimport_once_per_class`, not at module load.

GitHub issue #1520: the engine's reader skipped Simple Packet Blocks, so their
packets were missing and every later frame was numbered one short.

"""

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings

from tests._support import close_extractor, reimport_once_per_class

HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: Minimal IPv4 header (no payload), protocol 59 -- usable under any IP link type.
IPV4 = bytes.fromhex('45000014000100004000') + bytes(2) + bytes([10, 0, 0, 1, 10, 0, 0, 2])
#: IPv4 header (protocol 6) followed by a bare TCP SYN, from port 1234 to 80.
IPV4_TCP = (bytes.fromhex('45000028000100004006') + bytes(2) + bytes([10, 0, 0, 1, 10, 0, 0, 2])
            + struct.pack('>HHIIBBHHH', 1234, 80, 1, 0, 0x50, 0x02, 8192, 0, 0))
#: Ethernet frame carrying :data:`IPV4`.
ETHERNET = bytes(6) + bytes([2, 0, 0, 0, 0, 1]) + b'\x08\x00' + IPV4

#: Raw timestamp written into every packet block.
TICKS = 1_500_000_000_000_123


def _pad(data: bytes) -> bytes:
    return data + bytes(-len(data) % 4)


def _block(order: str, kind: int, body: bytes) -> bytes:
    body = _pad(body)
    length = len(body) + 12
    return struct.pack(f'{order}II', kind, length) + body + struct.pack(f'{order}I', length)


def _shb(order: str) -> bytes:
    return _block(order, 0x0A0D0D0A, struct.pack(f'{order}IHHq', 0x1A2B3C4D, 1, 0, -1))


def _idb(order: str, linktype: int, *, tsresol: 'int | None' = None,
         tsoffset: 'int | None' = None, snaplen: int = 65535) -> bytes:
    options = b''
    if tsresol is not None:
        options += _pad(struct.pack(f'{order}HHB', 9, 1, tsresol))
    if tsoffset is not None:
        options += struct.pack(f'{order}HHq', 14, 8, tsoffset)
    if options:
        options += struct.pack(f'{order}HH', 0, 0)
    return _block(order, 1, struct.pack(f'{order}HHI', linktype, 0, snaplen) + options)


def _epb(order: str, iface: int, data: bytes) -> bytes:
    return _block(order, 6, struct.pack(f'{order}IIIII', iface, TICKS >> 32, TICKS & 0xFFFF_FFFF,
                                        len(data), len(data)) + data)


def _spb(order: str, data: bytes, original_len: 'int | None' = None) -> bytes:
    original_len = len(data) if original_len is None else original_len
    return _block(order, 3, struct.pack(f'{order}I', original_len) + data)


#: Packets of :func:`_capture`: (link type, parsed-as, timestamp), in file order.
EXPECTED = [
    (1, 'Ethernet', TICKS / 10**6),              # section 1, interface 0
    (101, 'IP', TICKS / 10**9),                  # section 1, interface 1, if_tsresol=9; #1502
    (1, 'Ethernet', TICKS / 10**6),              # section 1, interface 0 again
    (228, 'IP', TICKS / 2**10 + 100),            # section 2, interface 0, 2^-10 + offset
]


def _capture() -> bytes:
    """Two sections, little- then big-endian, whose interfaces all differ."""
    return b''.join([
        _shb('<'),
        _idb('<', 1),                            # Ethernet, microseconds
        _idb('<', 101, tsresol=9),               # raw IP, nanoseconds
        _epb('<', 0, ETHERNET),
        _epb('<', 1, IPV4),
        _epb('<', 0, ETHERNET),
        _shb('>'),
        _idb('>', 228, tsresol=0x8A, tsoffset=100),  # IPv4, 2^-10 s, +100 s
        _epb('>', 0, IPV4),
    ])


@unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
class TestDPKTPCAPNGInterfaces(unittest.TestCase):
    """Pin the per-interface link type and timestamp of the DPKT engine."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self._tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, 'interfaces.pcapng')
        with open(self.path, 'wb') as file:
            file.write(_capture())

    def _extract(self, engine: str):  # type: ignore[no-untyped-def]
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return pcapkit.extract(fin=self.path, engine=engine, nofile=True, store=True)

    def test_reader_resolves_each_packets_interface(self) -> None:
        from pcapkit.foundation.engines.dpkt import PCAPNGReader

        with open(self.path, 'rb') as file:
            reader = PCAPNGReader(file)
            seen = [(int(reader.datalink()), timestamp, data)
                    for timestamp, data in reader]

        self.assertEqual([(lt, ts) for lt, ts, _ in seen],
                         [(lt, ts) for lt, _, ts in EXPECTED])
        self.assertEqual([data for _, _, data in seen], [ETHERNET, IPV4, ETHERNET, IPV4])

    def _assert_engines_agree(self, count: int) -> None:
        from pcapkit.toolkit.dpkt import TIMESTAMP_ATTR

        default = self._extract('default')
        dpkt = self._extract('dpkt')

        self.assertEqual(dpkt.length, count)
        self.assertEqual([getattr(frame, TIMESTAMP_ATTR) for frame in dpkt.frame],
                         [float(frame.info.timestamp_epoch) for frame in default.frame])
        self.assertEqual([type(frame).__name__ for frame in dpkt.frame],
                         [name for _, name, _ in EXPECTED[:count]])

    def test_dpkt_engine_matches_default_engine_across_interfaces(self) -> None:
        # section 1 only: one byte order, two interfaces
        with open(self.path, 'r+b') as file:
            file.truncate(len(_capture()) - len(_shb('>') + _idb('>', 228, tsresol=0x8A, tsoffset=100)
                                                  + _epb('>', 0, IPV4)))
        self._assert_engines_agree(3)

    def test_dpkt_engine_matches_default_engine_across_sections(self) -> None:
        self._assert_engines_agree(len(EXPECTED))

    def test_unknown_interface_id_is_a_format_error(self) -> None:
        from pcapkit.foundation.engines.dpkt import PCAPNGReader
        from pcapkit.utilities.exceptions import FormatError

        with open(self.path, 'wb') as file:
            file.write(_shb('<') + _idb('<', 1) + _epb('<', 1, ETHERNET))
        with open(self.path, 'rb') as file:
            with self.assertRaisesRegex(FormatError, 'invalid interface ID: 1'):
                next(PCAPNGReader(file))



@unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
class TestDPKTSimplePacketBlock(unittest.TestCase):
    """The DPKT engine reads a Simple Packet Block, as the default engine does."""

    #: Ethernet, then raw IPv4 on nanoseconds; an SPB names no interface, so it
    #: is on the first, whose snaplen cuts it short. Big-endian, so the block's
    #: own fields are read in the section's byte order.
    CAPTURE = b''.join([
        _shb('>'),
        _idb('>', 1, snaplen=len(ETHERNET)),
        _idb('>', 101, tsresol=9),
        _epb('>', 1, IPV4),
        _spb('>', ETHERNET, original_len=len(ETHERNET) + 40),
        _epb('>', 0, ETHERNET),
    ])

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self._tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self._tmp.cleanup)
        self.path = os.path.join(self._tmp.name, 'simple.pcapng')

    def _write(self, data: bytes) -> str:
        with open(self.path, 'wb') as file:
            file.write(data)
        return self.path

    def test_reader_yields_the_block_on_the_first_interface(self) -> None:
        import decimal

        from pcapkit.foundation.engines.dpkt import PCAPNGReader

        with open(self._write(self.CAPTURE), 'rb') as file:
            reader = PCAPNGReader(file)
            seen = [(int(reader.datalink()), timestamp, data) for timestamp, data in reader]

        self.assertEqual([(lt, data) for lt, _, data in seen],
                         [(101, IPV4), (1, ETHERNET), (1, ETHERNET)])
        # no timestamp in the block: dated at the epoch, as the default engine
        # dates it; the original length is the block's, not the captured one,
        # and the data stops at the snaplen, short of the block's padding
        stamp = seen[1][1]
        self.assertEqual((float(stamp), stamp.exact, stamp.orig_len),
                         (0.0, decimal.Decimal(0), len(ETHERNET) + 40))

    def test_dpkt_engine_matches_default_engine(self) -> None:
        import pcapkit
        from pcapkit.toolkit.dpkt import packet2bytes, packet2timestamp

        self._write(self.CAPTURE)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            default = pcapkit.extract(fin=self.path, engine='default', nofile=True, store=True)
            dpkt = pcapkit.extract(fin=self.path, engine='dpkt', nofile=True, store=True)

        self.assertEqual(dpkt.length, default.length)
        self.assertEqual([(float(packet2timestamp(frame)), packet2bytes(frame))
                          for frame in dpkt.frame],
                         [(float(frame.info.timestamp_epoch), bytes(frame.info.packet))
                          for frame in default.frame])

    def test_packet_data_stops_at_the_original_length(self) -> None:
        from pcapkit.foundation.engines.dpkt import PCAPNGReader

        # the octet past the original length is padding, not packet data
        capture = (_shb('<') + _idb('<', 1)
                   + _spb('<', ETHERNET + b'\x01', original_len=len(ETHERNET)))
        with open(self._write(capture), 'rb') as file:
            ((stamp, data),) = list(PCAPNGReader(file))
        self.assertEqual((data, stamp.orig_len), (ETHERNET, len(ETHERNET)))

    def test_a_raw_ipv4_interface_is_traced_as_by_the_default_engine(self) -> None:
        # #1520 and #1548 at once: on a LINKTYPE_IPV4 interface, an SPB is read
        # as a bare IP packet, which the flow tracer has to find too
        import pcapkit

        self._write(_shb('<') + _idb('<', 228) + _spb('<', IPV4_TCP) + _epb('<', 0, IPV4_TCP))
        flows = {}
        for engine in ('default', 'dpkt'):
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                extractor = pcapkit.extract(fin=self.path, engine=engine, nofile=True, tcp=True,
                                            trace=True, trace_format='pcap',
                                            trace_fout=os.path.join(self._tmp.name, engine))
            self.addCleanup(close_extractor, extractor)
            flows[engine] = []
            for flow in extractor.trace.tcp:
                with open(flow.fpout, 'rb') as file:
                    flows[engine].append((flow.label, tuple(flow.index), file.read()))

        self.assertEqual([index for _, index, _ in flows['dpkt']], [(1, 2)])
        self.assertEqual(flows['dpkt'], flows['default'])

    def test_a_section_without_an_interface_is_a_format_error(self) -> None:
        from pcapkit.foundation.engines.dpkt import PCAPNGReader
        from pcapkit.utilities.exceptions import FormatError

        with open(self._write(_shb('<') + _spb('<', ETHERNET)), 'rb') as file:
            with self.assertRaisesRegex(FormatError, r'\[SPB\] section has no interface'):
                next(PCAPNGReader(file))


if __name__ == '__main__':
    unittest.main()
