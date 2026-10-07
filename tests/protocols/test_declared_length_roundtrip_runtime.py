# -*- coding: utf-8 -*-
"""``from_data`` keeps the length a truncated capture declared.

GitHub issue #1155. :meth:`IPv4.make <pcapkit.protocols.internet.ipv4.IPv4.make>`,
:meth:`UDP.make <pcapkit.protocols.transport.udp.UDP.make>` and :meth:`IPv6.make
<pcapkit.protocols.internet.ipv6.IPv6.make>` computed their length field from the
payload they were handed. On a capture cut short by the snaplen that is the
*recorded* length rather than the declared one, so a
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` rebuild of
:file:`big_endian.pcap` frame 3 rewrote the IPv4 total length from 1186 to 82 and
the UDP length from 0x048e to 0x003e. Each ``make`` now takes the length
explicitly, and ``_make_data`` hands it the parsed one; a construction that gives
no length still computes it.

The round-trip cases read generated captures, so this module belongs to the
fixture-dependent tier. The in-memory cases pin that construction is unchanged.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, reimport_once_per_class, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Captures whose last frame is truncated by the snaplen: 1186 octets declared,
#: 82 captured.
TRUNCATED_SAMPLES = ('big_endian.pcap', 'big_endian_nanosecond.pcap', 'little_endian.pcap')

#: Captures every one of whose IPv4 and UDP packets is complete, so that
#: preserving the declared length cannot change what they rebuild to.
COMPLETE_SAMPLES = ('ipv4.pcap', 'dhcp.pcapng', 'options-ipv4.pcap')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DeclaredLengthRoundTripTests(unittest.TestCase):
    """A ``from_data`` rebuild reproduces the octets it was parsed from."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _frames(self, sample: str) -> 'list':
        from pcapkit.interface import extract

        extractor = extract(fin=sample_path(sample), fout='/tmp/out', format='tree',
                            store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return list(extractor.frame)

    def assertRoundTrips(self, sample: str) -> None:
        """Every IPv4 and UDP packet of ``sample`` rebuilds byte for byte."""
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.udp import UDP

        seen = 0
        for index, frame in enumerate(self._frames(sample)):
            for protocol in (IPv4, UDP):
                if protocol not in frame:
                    continue
                parsed = frame[protocol]
                with self.subTest(sample=sample, frame=index, protocol=protocol.__name__):
                    self.assertEqual(protocol.from_data(parsed.info).data, parsed.data)
                seen += 1
        self.assertGreater(seen, 0, f'{sample} carries no IPv4 or UDP packet')

    def test_truncated_frames_keep_their_declared_lengths(self) -> None:
        for sample in TRUNCATED_SAMPLES:
            frame = self._frames(sample)[2]

            from pcapkit.protocols.internet.ipv4 import IPv4
            from pcapkit.protocols.transport.udp import UDP

            with self.subTest(sample=sample):
                # The frame as recorded: 82 of the 1186 declared octets.
                self.assertEqual(frame[IPv4].info.len, 1186)
                self.assertEqual(len(frame[IPv4].data), 82)
                self.assertEqual(frame[UDP].info.len, 0x048e)

                rebuilt = IPv4.from_data(frame[IPv4].info)
                self.assertEqual(rebuilt.info.len, 1186)
                self.assertEqual(rebuilt.data, frame[IPv4].data)

                rebuilt_udp = UDP.from_data(frame[UDP].info)
                self.assertEqual(rebuilt_udp.info.len, 0x048e)
                self.assertEqual(rebuilt_udp.data, frame[UDP].data)

    def test_truncated_frames_round_trip(self) -> None:
        for sample in TRUNCATED_SAMPLES:
            self.assertRoundTrips(sample)

    def test_complete_frames_still_round_trip(self) -> None:
        for sample in COMPLETE_SAMPLES:
            self.assertRoundTrips(sample)

    def test_header_truncated_frame_keeps_its_total_length(self) -> None:
        """``test.pcapng`` frame 3 is cut inside the IPv4 header itself.

        Only 18 of the 20 header octets were recorded, so the rebuild cannot be
        byte for byte -- it writes a whole header. What it must not do is replace
        the declared 300 with the 18 that were kept.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4

        parsed = self._frames('test.pcapng')[2][IPv4]
        self.assertEqual(parsed.info.len, 300)
        self.assertEqual(len(parsed.data), 18)

        rebuilt = IPv4.from_data(parsed.info)
        self.assertEqual(rebuilt.info.len, 300)
        self.assertEqual(rebuilt.data[:18], parsed.data)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DeclaredLengthConstructionTests(unittest.TestCase):
    """Construction reads no capture, and is unchanged by the override."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_length_is_computed_when_not_given(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.udp import UDP

        self.assertEqual(IPv4(payload=b'\x00' * 10).info.len, 30)
        self.assertEqual(UDP(payload=b'\x00' * 10).info.len, 18)
        self.assertEqual(IPv6(payload=b'\x00' * 10).info.payload, 10)

    def test_explicit_length_is_written_as_given(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.udp import UDP

        ipv4 = IPv4(total_length=1186, payload=b'\x00' * 10)
        self.assertEqual(ipv4.info.len, 1186)
        self.assertEqual(ipv4.data[2:4], (1186).to_bytes(2, 'big'))

        udp = UDP(total_length=0x048e, payload=b'\x00' * 10)
        self.assertEqual(udp.info.len, 0x048e)
        self.assertEqual(udp.data[4:6], (0x048e).to_bytes(2, 'big'))

        ipv6 = IPv6(payload_length=1146, payload=b'\x00' * 10)
        self.assertEqual(ipv6.info.payload, 1146)
        self.assertEqual(ipv6.data[4:6], (1146).to_bytes(2, 'big'))


if __name__ == '__main__':
    unittest.main()
