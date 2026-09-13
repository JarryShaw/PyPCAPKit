from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_tcp_ipv4_syn_frame_exposes_expected_option_sequence(self) -> None:
        extractor = self._extract('sample/tcp.pcap')
        frame = extractor.frame[0]
        tcp = frame.payload.payload.payload
        options = list(tcp.info.options.items(multi=True))

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:TCP')
        self.assertEqual(tcp.name, 'Transmission Control Protocol')
        self.assertEqual(tcp.info.hdr_len, 44)
        self.assertTrue(tcp.info.flags.syn)
        self.assertTrue(tcp.info.flags.ack)
        self.assertFalse(tcp.info.flags.psh)
        self.assertEqual(
            [kind.name for kind, _ in options],
            [
                'Maximum_Segment_Size',
                'No_Operation',
                'Window_Scale',
                'No_Operation',
                'No_Operation',
                'Timestamps',
                'SACK_Permitted',
                'End_of_Option_List',
            ],
        )

        mss = options[0][1]
        window_scale = options[2][1]
        timestamps = options[5][1]
        self.assertEqual(mss.mss, 1460)
        self.assertEqual(window_scale.shift, 6)
        self.assertEqual(timestamps.timestamp, 834459645)
        self.assertEqual(timestamps.echo, 2454851095)
        self.assertEqual(type(tcp.payload).__name__, 'NoPayload')

    def test_tcp_ipv6_frame_keeps_timestamp_only_options(self) -> None:
        extractor = self._extract('sample/tcp.pcap')
        frame = extractor.frame[3]
        ip = frame.payload.payload
        tcp = ip.payload
        options = list(tcp.info.options.items(multi=True))

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:TCP')
        self.assertEqual(ip.name, 'Internet Protocol version 6')
        self.assertEqual(tcp.info.hdr_len, 32)
        self.assertTrue(tcp.info.flags.ack)
        self.assertFalse(tcp.info.flags.syn)
        self.assertEqual([kind.name for kind, _ in options], ['No_Operation', 'No_Operation', 'Timestamps'])
        self.assertEqual(options[2][1].timestamp, 1906342664)
        self.assertEqual(options[2][1].echo, 2559889017)

    def test_tcp_unregistered_application_payload_falls_back_to_raw(self) -> None:
        extractor = self._extract('sample/tcp.pcap')
        frame = extractor.frame[5]
        tcp = frame.payload.payload.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:TCP:Raw')
        self.assertTrue(tcp.info.flags.psh)
        self.assertTrue(tcp.info.flags.ack)
        self.assertEqual(type(tcp.payload).__name__, 'Raw')
        self.assertEqual(tcp.payload.name, 'Unknown')
        self.assertIsNone(tcp.payload.info.protocol)
        self.assertIsNone(tcp.payload.info.error)

    def test_stream_sample_exposes_no_payload_ack_frame(self) -> None:
        extractor = self._extract('sample/stream.pcap')
        frame = extractor.frame[3]
        tcp = frame.payload.payload.payload
        options = list(tcp.info.options.items(multi=True))

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv6:TCP')
        self.assertTrue(tcp.info.flags.ack)
        self.assertFalse(tcp.info.flags.psh)
        self.assertEqual(tcp.info.window_size, 2043)
        self.assertEqual([kind.name for kind, _ in options], ['No_Operation', 'No_Operation', 'Timestamps'])
        self.assertEqual(options[2][1].timestamp, 236969253)
        self.assertEqual(options[2][1].echo, 1144394525)
        self.assertEqual(type(tcp.payload).__name__, 'NoPayload')

    def test_stream_sample_exposes_ipv6_tcp_raw_payload_pair(self) -> None:
        extractor = self._extract('sample/stream.pcap')

        client_frame = extractor.frame[2]
        server_frame = extractor.frame[4]
        client_tcp = client_frame.payload.payload.payload
        server_tcp = server_frame.payload.payload.payload

        self.assertEqual(str(client_frame.protochain), 'Ethernet:IPv6:TCP:Raw')
        self.assertEqual(str(server_frame.protochain), 'Ethernet:IPv6:TCP:Raw')
        self.assertTrue(client_tcp.info.flags.psh)
        self.assertTrue(server_tcp.info.flags.psh)
        self.assertEqual(client_tcp.info.window_size, 45)
        self.assertEqual(server_tcp.info.window_size, 2048)
        self.assertEqual(type(client_tcp.payload).__name__, 'Raw')
        self.assertEqual(type(server_tcp.payload).__name__, 'Raw')


if __name__ == '__main__':
    unittest.main()
