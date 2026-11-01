# -*- coding: utf-8 -*-
"""A DTLS handshake message read and written on its own (#2496).

:meth:`DTLS.read_handshake <pcapkit.protocols.application.dtls.DTLS.read_handshake>`
reads one handshake message outside any record, so a message longer than a
record's 16-bit ``length`` still decodes. A fragmented message is written with
exactly ``fragment_length`` body octets (RFC 6347, section 4.2.3): a body that is
the whole message is cut down to the fragment's range, and any other length is
refused.

Every case builds its own octets; no sample capture is read.

"""
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def _client_hello_body(extensions: bytes = b'') -> bytes:
    """A DTLS ``ClientHello`` body, its ``cookie`` included."""
    return (b'\xfe\xfd' + bytes(range(32)) + b'\x00' + b'\x04\xab\xcd\xef\x01'
            + b'\x00\x02\x13\x01' + b'\x01\x00' + len(extensions).to_bytes(2, 'big') + extensions)


def _server_hello_body() -> bytes:
    return b'\xfe\xfd' + bytes(range(32, 64)) + b'\x00' + b'\x13\x01' + b'\x00' + b'\x00\x00'


def _handshake(msg_type: int, body: bytes, *, message_seq: int = 3, fragment_offset: int = 0,
               fragment_length: 'int | None' = None, length: 'int | None' = None) -> bytes:
    fragment_length = len(body) if fragment_length is None else fragment_length
    length = len(body) if length is None else length
    return (bytes([msg_type]) + length.to_bytes(3, 'big') + message_seq.to_bytes(2, 'big')
            + fragment_offset.to_bytes(3, 'big') + fragment_length.to_bytes(3, 'big') + body)


def _record(fragment: bytes) -> bytes:
    """A cleartext DTLS 1.2 ``handshake`` record, epoch and sequence number 0."""
    return b'\x16\xfe\xfd' + bytes(8) + len(fragment).to_bytes(2, 'big') + fragment


#: The ``ClientHello`` body the fragment cases cut, and where they cut it.
BODY = _client_hello_body()
HALF = len(BODY) // 2


class ReadHandshakeTests(unittest.TestCase):
    """:meth:`DTLS.read_handshake` reads exactly one message, of any length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_message_reads_as_it_does_in_a_record(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for name, message in {
                'ClientHello': _handshake(1, BODY),
                'ServerHello': _handshake(2, _server_hello_body()),
                'other type': _handshake(11, b'C' * 40),
                'fragment': _handshake(1, BODY[:HALF], fragment_length=HALF, length=len(BODY)),
        }.items():
            with self.subTest(case=name):
                record = _record(message)
                expected, = DTLS(record, len(record)).info.content
                self.assertEqual(DTLS.read_handshake(message), expected)

    def test_a_message_longer_than_a_record_holds_decodes(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.tls import ClientHello, Extension

        body = _client_hello_body(b'\x00\x15' + (65500).to_bytes(2, 'big') + bytes(65500))
        message = _handshake(1, body)
        self.assertGreater(len(message), 0xFFFF)
        decoded = DTLS.read_handshake(message)
        self.assertIsInstance(decoded.body, ClientHello)
        self.assertEqual(decoded.body.extensions, (Extension(type=21, data=bytes(65500)),))
        self.assertEqual((decoded.length, decoded.message_seq, decoded.is_fragmented),
                         (len(body), 3, False))

    def test_anything_but_one_message_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        whole = _handshake(1, BODY)
        for name, octets in {
                'empty': b'',
                'two messages': whole + whole,
                'trailing octets': whole + b'\x00',
                'truncated body': whole[:-1],
                'malformed ClientHello': _handshake(1, b'\x01\x02'),
        }.items():
            with self.subTest(case=name), self.assertRaisesRegex(ProtocolError, '^DTLS: '):
                DTLS.read_handshake(octets)


class FragmentBodyTests(unittest.TestCase):
    """A fragment is written with exactly ``fragment_length`` body octets."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _fragment(body: 'object', fragment_offset: int, fragment_length: int) -> 'object':
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.data.application.dtls import DTLSHandshake

        return DTLSHandshake(msg_type=HandshakeType.client_hello, length=len(BODY), body=body,
                             message_seq=3, fragment_offset=fragment_offset,
                             fragment_length=fragment_length, is_fragmented=True)

    def test_a_whole_message_body_is_cut_to_the_fragment(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        hello = DTLS.read_handshake(_handshake(1, BODY)).body
        for body in (hello, BODY):
            for offset, length in ((0, HALF), (HALF, len(BODY) - HALF)):
                with self.subTest(decoded=body is hello, fragment_offset=offset):
                    wire = _record(_handshake(1, BODY[offset:offset + length],
                                              fragment_offset=offset, fragment_length=length,
                                              length=len(BODY)))
                    made = DTLS(content_type=22, content=(self._fragment(body, offset, length),))
                    self.assertEqual(bytes(made), wire)
                    self.assertEqual(DTLS(wire, len(wire)).info.content[0].body,
                                     BODY[offset:offset + length])

    def test_a_body_of_any_other_length_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        for name, (body, offset, length) in {
                'short': (BODY[:HALF - 1], 0, HALF),
                'long': (BODY[:HALF + 1], 0, HALF),
                'whole message, range overruns it': (BODY, HALF, len(BODY) - HALF + 1),
        }.items():
            with self.subTest(case=name), self.assertRaisesRegex(ProtocolError, 'fragment_length'):
                DTLS(content_type=22, content=(self._fragment(body, offset, length),))

    def test_a_parsed_fragment_rebuilds_byte_exact(self) -> None:
        """A fragment's own body is never cut, even one whose range overruns
        its message (offset 5 + 10 > length 10)."""
        from pcapkit.protocols.application.dtls import DTLS

        for name, message in {
                'first half': _handshake(1, BODY[:HALF], fragment_length=HALF, length=len(BODY)),
                'overrunning': _handshake(11, b'B' * 10, fragment_offset=5, fragment_length=10,
                                          length=10),
        }.items():
            with self.subTest(case=name):
                wire = _record(message)
                self.assertEqual(bytes(DTLS.from_data(DTLS(wire, len(wire)).info)), wire)


if __name__ == '__main__':
    unittest.main()
