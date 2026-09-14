# -*- coding: utf-8 -*-
"""End-to-end reassembly of TCP payloads and IP fragments.

Translates :file:`examples/legacy_smoke/test_reassembly.py` (TCP payloads out of
:file:`test.pcap`), :file:`test_analyse.py` (the application layer found in a
reassembled datagram, out of :file:`http6.cap`), :file:`test_ip_reasm.py` and
:file:`test_ipv6_reasm.py` (IPv4 and IPv6 datagrams). Those scripts printed
their datagrams; these assert on them.

The captures are built for this. ``test.pcap`` spreads the IPv4 response body
over four segments delivered out of order with one of them retransmitted, and
the IPv6 request body over three segments delivered in order, so a reassembled
payload that matches its own ``Content-Length`` is evidence that the ordering
and the duplicate were both handled. See the module docstring of
:file:`examples/generators/legacy.py`.

One expectation here is skipped rather than asserted: see
:class:`IPv6FragmentPayloadTests`.

"""
from __future__ import annotations

import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_RUNTIME, EndToEndTestCase


def by_direction(datagrams: 'tuple') -> 'dict[tuple[str, int, str, int], object]':
    """Key TCP datagrams by their connection and direction.

    The submission order of the datagram tuple is an implementation detail of
    when each direction sent its FIN or RST, so the tests below look each
    datagram up by its four-tuple instead of by position.

    """
    return {
        (str(datagram.id.src[0]), datagram.id.src[1],
         str(datagram.id.dst[0]), datagram.id.dst[1]): datagram
        for datagram in datagrams
    }


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPReassemblyTests(EndToEndTestCase):
    """TCP payload reassembly over :file:`test.pcap`."""

    def reassemble(self) -> 'dict':
        extractor = self.extract(fin=sample_path('test.pcap'), nofile=True, store=False,
                                 tcp=True, reassembly=True, reasm_strict=True)
        self.assertEqual(extractor.length, 34)
        return by_direction(extractor.reassembly.tcp)

    def test_every_direction_of_both_connections_yields_one_datagram(self) -> None:
        datagrams = self.reassemble()

        self.assertEqual(sorted(datagrams), sorted([
            ('10.20.30.131', 49812, '203.0.113.42', 80),
            ('203.0.113.42', 80, '10.20.30.131', 49812),
            ('2001:db8:2f10::131', 49814, '2001:db8:9c::7a', 80),
            ('2001:db8:9c::7a', 80, '2001:db8:2f10::131', 49814),
        ]))
        for key, datagram in datagrams.items():
            with self.subTest(direction=key):
                self.assertTrue(datagram.completed)
                self.assertIsInstance(datagram.payload, bytes)

    def test_out_of_order_and_retransmitted_segments_reassemble_in_order(self) -> None:
        datagram = self.reassemble()[('203.0.113.42', 80, '10.20.30.131', 49812)]

        # The four body segments arrive 3, 1, 4, 2 with the third retransmitted;
        # frames 7 and 8 carry the header and the first body segment.
        self.assertEqual(datagram.index, (7, 8, 10, 12, 14, 16, 18))

        header, separator, body = datagram.payload.partition(b'\r\n\r\n')
        self.assertEqual(separator, b'\r\n\r\n')
        self.assertTrue(header.startswith(b'HTTP/1.1 200 OK\r\n'))
        self.assertIn(b'Content-Length: 4400', header)
        # The retransmission is not counted twice and no segment is missing.
        self.assertEqual(len(body), 4400)
        self.assertEqual(len(datagram.payload), len(header) + 4 + 4400)
        self.assertTrue(body.startswith(b'<!DOCTYPE html>'))
        self.assertTrue(body.endswith(b'</html>\n'))

    def test_request_without_a_body_reassembles_from_its_two_frames(self) -> None:
        datagram = self.reassemble()[('10.20.30.131', 49812, '203.0.113.42', 80)]

        self.assertEqual(datagram.index, (5, 6))
        self.assertTrue(datagram.payload.startswith(b'GET /index.html HTTP/1.1\r\n'))
        self.assertTrue(datagram.payload.endswith(b'\r\n\r\n'))
        self.assertIn(b'Host: web.example.com\r\n', datagram.payload)

    def test_ipv6_connection_reassembles_a_three_segment_request_body(self) -> None:
        datagrams = self.reassemble()
        request = datagrams[('2001:db8:2f10::131', 49814, '2001:db8:9c::7a', 80)]
        response = datagrams[('2001:db8:9c::7a', 80, '2001:db8:2f10::131', 49814)]

        self.assertEqual(request.index, (24, 25, 27, 29))
        header, _, body = request.payload.partition(b'\r\n\r\n')
        self.assertTrue(header.startswith(b'POST /v1/telemetry HTTP/1.1\r\n'))
        self.assertIn(b'Content-Length: 3350', header)
        self.assertEqual(len(body), 3350)
        self.assertTrue(body.startswith(b'{"schema":"pcapkit.example/telemetry/1"'))

        # The client aborts this connection with an RST, which submits the
        # server's direction just as a FIN would.
        self.assertEqual(response.index, (30, 31, 33))
        self.assertTrue(response.payload.startswith(b'HTTP/1.1 204 No Content\r\n'))

    def test_reassembly_is_refused_when_it_was_not_requested(self) -> None:
        # This is the trap ``examples/legacy_smoke/test_analyse.py`` falls into:
        # it asks for ``tcp=True`` but never for ``reassembly=True``.
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self.extract(fin=sample_path('test.pcap'), nofile=True, store=False,
                                 tcp=True, reasm_strict=True)

        with self.assertRaises(UnsupportedCall):
            extractor.reassembly  # pylint: disable=pointless-statement

    def test_datagrams_are_not_retained_when_storage_is_disabled(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        extractor = self.extract(fin=sample_path('test.pcap'), nofile=True, store=False,
                                 tcp=True, reassembly=True, reasm_store=False)

        with self.assertRaises(UnsupportedCall):
            extractor.reassembly.tcp  # pylint: disable=pointless-statement


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ApplicationLayerAnalysisTests(EndToEndTestCase):
    """The application layer :mod:`pcapkit` finds in a reassembled datagram.

    :file:`http6.cap` is two HTTP/1.1 connections over IPv6 -- a page fetch
    whose response body spans three segments, and a conditional request answered
    ``304 Not Modified`` with no body -- so all four datagrams analyse as HTTP.

    """

    def analyse(self) -> 'dict':
        extractor = self.extract(fin=sample_path('http6.cap'), nofile=True, store=False,
                                 tcp=True, reassembly=True, reasm_strict=True)
        self.assertEqual(extractor.length, 26)
        return by_direction(extractor.reassembly.tcp)

    def test_all_four_datagrams_analyse_as_http(self) -> None:
        import pcapkit

        datagrams = self.analyse()
        self.assertEqual(len(datagrams), 4)

        for key, datagram in datagrams.items():
            with self.subTest(direction=key):
                self.assertTrue(datagram.completed)
                self.assertIsNotNone(datagram.packet)
                self.assertIn(pcapkit.HTTP, datagram.packet)
                self.assertEqual(datagram.packet.alias, 'HTTP/1.1')

    def test_page_fetch_is_analysed_as_a_request_and_a_response(self) -> None:
        datagrams = self.analyse()
        request = datagrams[('2001:db8:2f10::131', 49820, '2001:db8:9c::50', 80)]
        response = datagrams[('2001:db8:9c::50', 80, '2001:db8:2f10::131', 49820)]

        self.assertEqual(request.index, (3, 4))
        self.assertEqual(request.packet.info.receipt.type.value, 'request')
        self.assertEqual(request.packet.info.receipt.method.value, 'GET')
        self.assertEqual(request.packet.info.receipt.uri, '/')
        self.assertEqual(request.packet.info.header['Host'], 'www6.example.com')
        self.assertIsNone(request.packet.info.body)

        self.assertEqual(response.index, (5, 6, 8, 10, 12))
        self.assertEqual(response.packet.info.receipt.type.value, 'response')
        self.assertEqual(int(response.packet.info.receipt.status), 200)
        self.assertEqual(response.packet.info.receipt.message, 'OK')
        content_length = int(response.packet.info.header['Content-Length'])
        self.assertEqual(len(response.packet.info.body), content_length)

    def test_conditional_request_is_analysed_as_a_bodyless_304(self) -> None:
        datagrams = self.analyse()
        request = datagrams[('2001:db8:2f10::131', 49822, '2001:db8:9c::50', 80)]
        response = datagrams[('2001:db8:9c::50', 80, '2001:db8:2f10::131', 49822)]

        self.assertEqual(request.packet.info.receipt.uri, '/assets/site.css')
        self.assertIn('If-None-Match', request.packet.info.header)

        self.assertEqual(int(response.packet.info.receipt.status), 304)
        self.assertEqual(response.packet.info.receipt.message, 'Not Modified')
        self.assertNotIn('Content-Length', response.packet.info.header)
        self.assertIsNone(response.packet.info.body)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv4ReassemblyTests(EndToEndTestCase):
    """IPv4 datagram reassembly over :file:`ipv4.pcap`.

    The fixture is a multicast stream captured on the sending host, so none of
    its four datagrams is fragmented; what this covers is the path where an
    unfragmented datagram is submitted whole. No fixture in the repository
    carries IPv4 fragments, so the multi-fragment path is not reachable from
    here -- the IPv6 class below is where fragmentation is exercised.

    """

    def test_each_unfragmented_datagram_is_submitted_whole(self) -> None:
        extractor = self.extract(fin=sample_path('ipv4.pcap'), nofile=True, store=True,
                                 ipv4=True, reassembly=True, reasm_strict=True)
        datagrams = extractor.reassembly.ipv4

        self.assertEqual(extractor.length, 4)
        self.assertEqual(len(datagrams), 4)

        for number, datagram in enumerate(datagrams, start=1):
            with self.subTest(datagram=number):
                self.assertTrue(datagram.completed)
                self.assertEqual(datagram.index, (number,))
                self.assertEqual(str(datagram.id.src), '172.31.127.230')
                self.assertEqual(str(datagram.id.dst), '239.1.3.3')
                self.assertEqual(int(datagram.id.proto), 17)
                # The payload is the IPv4 payload of that very frame: the eight
                # octet UDP header plus its 1828 octet payload.
                frame_payload = bytes(extractor.frame[number - 1]['IPv4'].packet.payload)
                self.assertEqual(bytes(datagram.payload), frame_payload)
                self.assertEqual(len(datagram.payload), 1836)

    def test_datagram_identifications_are_distinct_and_consecutive(self) -> None:
        extractor = self.extract(fin=sample_path('ipv4.pcap'), nofile=True, store=False,
                                 ipv4=True, reassembly=True, reasm_strict=True)

        self.assertEqual([datagram.id.id for datagram in extractor.reassembly.ipv4],
                         [31232, 31233, 31234, 31235])

    def test_reassembled_datagram_analyses_as_udp(self) -> None:
        extractor = self.extract(fin=sample_path('ipv4.pcap'), nofile=True, store=False,
                                 ipv4=True, reassembly=True, reasm_strict=True)
        datagram = extractor.reassembly.ipv4[0]

        self.assertEqual(type(datagram.packet).__name__, 'UDP')
        self.assertEqual(len(bytes(datagram.packet.packet.payload)), 1828)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6FragmentReassemblyTests(EndToEndTestCase):
    """IPv6 fragment reassembly over :file:`ipv6.pcap`.

    Frames 13 to 16 are one 4778 octet UDP datagram fragmented into
    1448/1448/1448/434 octets. What is asserted here is which frames were
    collected and that the datagram is reported complete -- both of which are
    right. Its *contents* are not, so they live in the skipped test below.

    """

    def reassemble(self) -> 'tuple':
        extractor = self.extract(fin=sample_path('ipv6.pcap'), nofile=True, store=False,
                                 ipv6=True, reassembly=True, reasm_strict=True)
        self.assertEqual(extractor.length, 16)
        return extractor.reassembly.ipv6

    def test_only_the_fragmented_datagram_is_submitted(self) -> None:
        datagrams = self.reassemble()

        # Twelve of the sixteen frames are neighbour discovery and ICMPv6
        # echoes, which carry no fragment header and are dismissed.
        self.assertEqual(len(datagrams), 1)
        self.assertEqual(datagrams[0].index, (13, 14, 15, 16))

    def test_the_datagram_is_reported_complete(self) -> None:
        datagram = self.reassemble()[0]

        self.assertTrue(datagram.completed)
        self.assertIsInstance(datagram.payload, bytes)
        self.assertEqual(str(datagram.id.src), 'fe80::a423:b61d:7c92:70c6')
        self.assertEqual(str(datagram.id.dst), 'fe80::821f:12ff:fec9:d13d')
        self.assertEqual(int(datagram.id.proto), 17)


class IPv6FragmentPayloadTests(EndToEndTestCase):
    """What the reassembled IPv6 datagram should contain.

    Kept apart from :class:`IPv6FragmentReassemblyTests` so the skip covers only
    the payload, and the assertions that are correct today keep running.

    """

    @unittest.skip('blocked on IPv6 fragment offsets being used as byte offsets while the '
                   'field is in eight-octet units (pcapkit/protocols/internet/ipv6_frag.py:141)')
    def test_the_four_fragments_reassemble_into_the_whole_datagram(self) -> None:
        """The reassembled payload should be the four fragments, in order.

        It is not. ``pcapkit/protocols/internet/ipv4.py:274`` scales the IPv4
        fragment offset into octets (``int(schema.flags['offset']) * 8``), but
        ``pcapkit/protocols/internet/ipv6_frag.py:141`` passes the IPv6 one
        through unscaled (``offset=schema.flags['offset']``), and
        ``pcapkit/toolkit/pcap.py:115`` then hands it to the reassembly
        machinery as ``fo``, which is a byte offset. The four fragments are
        therefore placed at octets 0, 181, 362 and 543 instead of 0, 1448, 2896
        and 4344, so they overwrite one another and the datagram comes out 977
        octets long -- ``543 + 434`` -- while still reporting
        ``completed=True``.

        Measured on this fixture: ``len(datagram.payload)`` is 977, and the
        assertion below expects 4778.

        A second defect is visible in the same call and is left alone here:
        ``pcapkit/toolkit/pcap.py:111`` keys the reassembly buffer on the IPv6
        header's flow label rather than on the fragment header's identification,
        so ``datagram.id.id`` is 0 where the fixture's identification is 110308.
        One fragmented datagram cannot show the consequence, so no assertion is
        made about it either way.

        """
        extractor = self.extract(fin=sample_path('ipv6.pcap'), nofile=True, store=True,
                                 ipv6=True, reassembly=True, reasm_strict=True)
        datagram = extractor.reassembly.ipv6[0]

        fragments = [
            bytes(extractor.frame[number - 1]['IPv6'].info.fragment.payload)
            for number in (13, 14, 15, 16)
        ]
        self.assertEqual([len(fragment) for fragment in fragments], [1448, 1448, 1448, 434])
        self.assertEqual(len(datagram.payload), 4778)
        self.assertEqual(bytes(datagram.payload), b''.join(fragments))


if __name__ == '__main__':
    unittest.main()
