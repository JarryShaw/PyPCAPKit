# -*- coding: utf-8 -*-
"""A dispatched HTTP payload is parsed by its version's class. C.f. #2524.

The HTTP ports bind the family base
:class:`~pcapkit.protocols.application.http.HTTP`, and ``HTTP._dispatch`` picks
``HTTPv1`` or ``HTTPv2`` from the payload, as ``IGMP._dispatch`` picks an IGMP
message's class. So a segment's HTTP layer is never the base: its data sits under
``httpv1`` or ``httpv2``, a payload neither version identifies is kept as
:class:`~pcapkit.protocols.misc.raw.Raw`, and every round trip still reproduces
its octets.

This module is unit-tier: the segments are built in memory.

"""

from __future__ import annotations

import importlib.util
import io
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 80.
_TCP_TO_80 = bytes.fromhex('c350005000000001000000015010ffff00000000')

#: The HTTP/2 connection preface (RFC 9113, section 3.4).
_PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'

#: An empty ``SETTINGS`` frame on stream 0, as a client sends after the preface.
_SETTINGS = bytes.fromhex('000000040000000000')

#: Each payload, with the class name that parses it.
PAYLOADS = {
    'request': (b'GET / HTTP/1.1\r\nHost: example.invalid\r\n\r\n', 'HTTPv1'),
    'response': (b'HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi', 'HTTPv1'),
    'frame': (bytes.fromhex('000000000000000001'), 'HTTPv2'),
    'two frames': (bytes.fromhex('000000000000000001') * 2, 'HTTPv2'),
    'preface': (_PREFACE + _SETTINGS, 'HTTPv2'),
}

#: Payloads that neither version identifies.
UNIDENTIFIED = {
    'zeros': b'\x00' * 9,
    'text': b'not an http message',
    'truncated preface': _PREFACE[:18],
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class HTTPDispatchTests(unittest.TestCase):
    """``HTTP._dispatch``, the transport layers' use of it, and the round trips."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def member(class_name: str) -> 'Any':
        import importlib

        return getattr(importlib.import_module(
            f'pcapkit.protocols.application.{class_name.lower()}'), class_name)

    @staticmethod
    def tcp(payload: bytes) -> 'Any':
        from pcapkit.protocols.transport.tcp import TCP

        data = _TCP_TO_80 + payload
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return TCP(io.BytesIO(data), len(data))

    @staticmethod
    def udp(payload: bytes) -> 'Any':
        from pcapkit.protocols.transport.udp import UDP

        data = bytes.fromhex('c3500050') + (8 + len(payload)).to_bytes(2, 'big') + b'\x00\x00' + payload
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return UDP(io.BytesIO(data), len(data))

    def test_dispatch_picks_the_member_the_payload_identifies(self) -> None:
        from pcapkit.protocols.application.http import HTTP
        from pcapkit.protocols.misc.raw import Raw

        for label, (payload, class_name) in PAYLOADS.items():
            with self.subTest(payload=label):
                self.assertIs(HTTP._dispatch(payload, len(payload)), self.member(class_name))
        for label, payload in UNIDENTIFIED.items():
            with self.subTest(payload=label):
                self.assertIs(HTTP._dispatch(payload, len(payload)), Raw)
        with self.subTest(payload='bounded by length'):
            request = PAYLOADS['request'][0]
            self.assertIs(HTTP._dispatch(request + b'\x00' * 9, len(request)), self.member('HTTPv1'))

    def test_tcp_and_udp_parse_with_the_member_under_its_key(self) -> None:
        for transport in (self.tcp, self.udp):
            for label, (payload, class_name) in PAYLOADS.items():
                with self.subTest(transport=transport.__name__, payload=label):
                    outer = transport(payload)
                    self.assertIs(type(outer.payload), self.member(class_name))
                    self.assertIs(outer.info[class_name.lower()], outer.payload.info)
                    self.assertNotIn('http', outer.info)

    def test_reassembly_analysis_parses_with_the_member(self) -> None:
        """``Transport.analyze``, which TCP reassembly reaches, dispatches alike."""
        from pcapkit.protocols.transport.tcp import TCP

        for label, (payload, class_name) in PAYLOADS.items():
            with self.subTest(payload=label):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    layer = TCP.analyze((50000, 80), payload)
                self.assertIs(type(layer), self.member(class_name))
                self.assertEqual(layer.data, payload)

    def test_an_unidentified_payload_is_kept_raw(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for label, payload in {**UNIDENTIFIED, 'preface alone': _PREFACE}.items():
            with self.subTest(payload=label):
                tcp = self.tcp(payload)
                self.assertIs(type(tcp.payload), Raw)
                self.assertEqual(tcp.payload.data, payload)

    def test_a_preface_counts_as_header_and_is_kept(self) -> None:
        tcp = self.tcp(_PREFACE + _SETTINGS)
        layer = tcp.payload
        self.assertEqual(layer.length, len(_PREFACE) + 9)
        self.assertEqual(layer.info.preface, _PREFACE)
        self.assertEqual(int(layer.info.type), 0x4)
        self.assertEqual(layer.data, _PREFACE + _SETTINGS)

    def test_parse_then_rebuild_reproduces_the_octets(self) -> None:
        for label, (payload, class_name) in PAYLOADS.items():
            with self.subTest(payload=label):
                tcp = self.tcp(payload)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(type(tcp).from_data(tcp.info).data, tcp.data)
                    self.assertEqual(self.member(class_name).from_data(tcp.payload.info).data,
                                     payload)

    def test_make_then_parse_reproduces_the_octets(self) -> None:
        from pcapkit.const.http.frame import Frame

        HTTPv1, HTTPv2 = self.member('HTTPv1'), self.member('HTTPv2')
        made = {
            'HTTPv1': HTTPv1(method='GET', uri='/', http_version='1.1'),
            'HTTPv2': HTTPv2(type=Frame.DATA, sid=1, frame={'data': b'x'}),
            'HTTPv2 preface': HTTPv2(type=Frame.SETTINGS, sid=0, frame={}, preface=True),
        }
        for label, layer in made.items():
            klass = type(layer)
            with self.subTest(made=label):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = klass(io.BytesIO(layer.data), len(layer.data))
                    self.assertEqual(parsed.data, layer.data)
                    self.assertEqual(klass.from_data(parsed.info).data, layer.data)
                    self.assertIs(type(self.tcp(layer.data).payload), klass)
        self.assertTrue(made['HTTPv2 preface'].data.startswith(_PREFACE))


if __name__ == '__main__':
    unittest.main()
