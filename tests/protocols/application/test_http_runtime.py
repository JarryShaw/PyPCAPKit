from __future__ import annotations

import importlib.util
import unittest

from tests._support import close_extractor, purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _extract(self, sample: str):
        from pcapkit.interface import extract

        extractor = extract(fin=sample, fout='/tmp/out', format='tree', store=True, nofile=True)
        self.addCleanup(close_extractor, extractor)
        return extractor

    def test_http_request_frame_exposes_receipt_and_headers(self) -> None:
        extractor = self._extract('sample/http.pcap')
        frame = extractor.frame[114]
        http = frame.payload.payload.payload.payload
        receipt = http.info.receipt

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:TCP:HTTP/1.1')
        self.assertEqual(http.name, 'Hypertext Transfer Protocol')
        self.assertEqual(http.alias, 'HTTP/1.1')
        self.assertEqual(http.version, '1.1')
        self.assertEqual(type(receipt).__name__, 'RequestHeader')
        self.assertEqual(receipt.type.value, 'request')
        self.assertEqual(receipt.method.value, 'GET')
        self.assertEqual(receipt.version, '1.1')
        self.assertEqual(receipt.uri, '/litong/zhitou/sinaads/demo/wenjing8/ZaoWanBao/toutiaobaoMedia.js')
        self.assertEqual(http.info.header['Host'], 'd1.sina.com.cn')
        self.assertEqual(http.info.header['Accept-Encoding'], 'gzip, deflate')
        self.assertIsNone(http.info.body)

    def test_http_response_frame_exposes_status_headers_and_body(self) -> None:
        extractor = self._extract('sample/http.pcap')
        frame = extractor.frame[117]
        http = frame.payload.payload.payload.payload
        receipt = http.info.receipt

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:TCP:HTTP/1.1')
        self.assertEqual(type(receipt).__name__, 'ResponseHeader')
        self.assertEqual(receipt.type.value, 'response')
        self.assertEqual(receipt.version, '1.1')
        self.assertEqual(int(receipt.status), 200)
        self.assertEqual(receipt.message, 'OK')
        self.assertEqual(http.info.header['Server'], 'Tengine')
        self.assertEqual(http.info.header['Content-Type'], 'application/x-javascript')
        self.assertEqual(http.info.header['Content-Length'], '3520')
        self.assertIsInstance(http.info.body, bytes)
        self.assertTrue(http.info.body.startswith(b'\x1f\x8b\x08'))

    def test_http_request_variants_cover_additional_hosts(self) -> None:
        extractor = self._extract('sample/http.pcap')

        sports_request = extractor.frame[393].payload.payload.payload.payload
        beacon_request = extractor.frame[556].payload.payload.payload.payload

        self.assertEqual(sports_request.info.receipt.method.value, 'GET')
        self.assertEqual(sports_request.info.header['Host'], 'sports.sina.com.cn')
        self.assertEqual(sports_request.info.receipt.uri, '/')

        self.assertEqual(beacon_request.info.receipt.method.value, 'GET')
        self.assertEqual(beacon_request.info.header['Host'], 'd7.sina.com.cn')
        self.assertEqual(
            beacon_request.info.receipt.uri,
            '/litong/zhitou/sinaads/release/sinaads.js',
        )
        self.assertIsNone(beacon_request.info.body)

    def test_http_response_variants_cover_empty_and_small_bodies(self) -> None:
        extractor = self._extract('sample/http.pcap')

        empty_response = extractor.frame[629].payload.payload.payload.payload
        small_body_response = extractor.frame[587].payload.payload.payload.payload

        self.assertEqual(int(empty_response.info.receipt.status), 200)
        self.assertEqual(empty_response.info.header['Server'], 'Suda/1.12.0')
        self.assertEqual(empty_response.info.header['Content-Length'], '0')
        self.assertIsNone(empty_response.info.body)

        self.assertEqual(int(small_body_response.info.receipt.status), 200)
        self.assertEqual(small_body_response.info.header['Server'], 'Suda/1.12.0')
        self.assertEqual(small_body_response.info.header['Content-Length'], '35')
        self.assertIsInstance(small_body_response.info.body, bytes)
        self.assertEqual(len(small_body_response.info.body), 35)

    def test_malformed_http_payload_falls_back_to_raw(self) -> None:
        extractor = self._extract('sample/http.pcap')
        frame = extractor.frame[1113]
        tcp = frame.payload.payload.payload

        self.assertEqual(str(frame.protochain), 'Ethernet:IPv4:TCP:Raw')
        self.assertEqual(tcp.name, 'Transmission Control Protocol')
        self.assertEqual(type(tcp.payload).__name__, 'Raw')
        self.assertEqual(tcp.payload.name, 'Unknown')
        self.assertIsNone(tcp.payload.info.protocol)
        self.assertIsNotNone(tcp.payload.info.packet)


if __name__ == '__main__':
    unittest.main()
