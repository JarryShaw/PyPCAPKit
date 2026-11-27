# -*- coding: utf-8 -*-
"""A TLS or DTLS record declaring more than its RFCs allow is no record (#2938).

A TLSCiphertext of SSLv3 to TLS 1.2 holds at most ``2 ** 14 + 2048`` octets (RFC 6101
section 5.2.3, RFC 5246 section 6.2.3), and DTLS 1.0 and 1.2 change none of it (RFC 4347
and RFC 6347, section 4); the legacy header cannot tell TLS 1.3's ``2 ** 14 + 256`` (RFC
9846 section 5.2) from it. A DTLS 1.3 unified header's length is a TLS 1.3 record's (RFC
9147 section 4). A record past its bound is refused, first in its segment or datagram or
after another, so the parser decodes no superset of the RFCs.

"""

from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): pure-Python header checks, the same on every interpreter.
__tier__ = 'LATEST'

#: The largest fragment a legacy record header may declare.
LIMIT = 2 ** 14 + 2048
#: The largest ciphertext a DTLS 1.3 unified-header record may carry.
UNIFIED_LIMIT = 2 ** 14 + 256


def _tls(fragment: bytes, content_type: int = 23) -> bytes:
    return bytes([content_type]) + b'\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment


def _dtls(fragment: bytes, content_type: int = 23) -> bytes:
    return (bytes([content_type]) + b'\xfe\xfd' + (1).to_bytes(2, 'big') + (1).to_bytes(6, 'big')
            + len(fragment).to_bytes(2, 'big') + fragment)


def _cid(fragment: bytes, cid: bytes = b'\xc1\xc2\xc3\xc4') -> bytes:
    """A ``tls12_cid`` record (RFC 9146 section 4)."""
    return (b'\x19\xfe\xfd' + (1).to_bytes(2, 'big') + (1).to_bytes(6, 'big') + cid
            + len(fragment).to_bytes(2, 'big') + fragment)


def _unified(fragment: bytes, *, length: bool = True) -> bytes:
    """A unified-header record with an 8-bit sequence number, its length if ``length``."""
    first = 0x25 if length else 0x21  # 001 0 0 L 01
    return bytes([first, 0x2A]) + (len(fragment).to_bytes(2, 'big') if length else b'') + fragment


class FirstRecordTests(unittest.TestCase):
    """A record opening the octets parsed is refused past its bound, and read at it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tls(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        at = _tls(b'\xa5' * LIMIT)
        self.assertEqual((TLS(at).info.length, TLS(at).data), (LIMIT, at))
        with self.assertRaisesRegex(ProtocolError, 'record_overflow'):
            TLS(_tls(b'\xa5' * (LIMIT + 1)))

    def test_tls_reassembled(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.protocols.misc.raw.protocol import Raw

        self.assertIsInstance(TLS.analyze_record((ContentType.application_data, 0x0303), b'\xa5' * LIMIT), TLS)
        packet = TLS.analyze_record((ContentType.application_data, 0x0303), b'\xa5' * (LIMIT + 1))
        self.assertIsInstance(packet, Raw)
        self.assertIn('record_overflow', packet.info.error)

    def test_dtls(self) -> None:
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        at = _dtls(b'\xa5' * LIMIT)
        self.assertEqual((DTLS(at).info.length, DTLS(at).data), (LIMIT, at))
        with self.assertRaisesRegex(ProtocolError, 'record_overflow'):
            DTLS(_dtls(b'\xa5' * (LIMIT + 1)))

    def test_dtls_tls12_cid(self) -> None:
        from pcapkit.protocols.application.dtls.protocol import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        at = _cid(b'\xa5' * LIMIT)
        self.assertEqual(DTLS(at, context=DTLSContext(cid_length=4)).info.length, LIMIT)
        with self.assertRaisesRegex(ProtocolError, 'record_overflow'):
            DTLS(_cid(b'\xa5' * (LIMIT + 1)), context=DTLSContext(cid_length=4))

    def test_dtls13_unified_header(self) -> None:
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        for length in (True, False):
            with self.subTest(length_present=length):
                at = _unified(b'\xa5' * UNIFIED_LIMIT, length=length)
                self.assertEqual(DTLS(at).data, at)
                with self.assertRaisesRegex(ProtocolError, 'record_overflow'):
                    DTLS(_unified(b'\xa5' * (UNIFIED_LIMIT + 1), length=length))


class MakeTests(unittest.TestCase):
    """``make`` builds a record at its bound and refuses one past it, as the parse does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make(self) -> None:
        from pcapkit.protocols.application.dtls.protocol import DTLS
        from pcapkit.protocols.application.tls.protocol import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            ('TLS', TLS, LIMIT, 'data', {}, _tls),
            ('DTLS', DTLS, LIMIT, 'data', {'epoch': 1, 'sequence_number': 1}, _dtls),
            ('tls12_cid', DTLS, LIMIT, 'data',
             {'content_type': 25, 'epoch': 1, 'sequence_number': 1, 'cid': b'\xc1\xc2\xc3\xc4'}, _cid),
            ('unified header', DTLS, UNIFIED_LIMIT, 'content',
             {'ciphertext': True, 'epoch': 1, 'sequence_number': 0x2A}, _unified),
            ('unified header, no length', DTLS, UNIFIED_LIMIT, 'content',
             {'ciphertext': True, 'epoch': 1, 'sequence_number': 0x2A, 'length_present': False},
             lambda fragment: _unified(fragment, length=False)),
        )
        for (name, klass, limit, field, kwargs, wire) in cases:
            maker = object.__new__(klass)
            with self.subTest(record=name, size=limit):
                made = bytes(maker.make(**kwargs, **{field: b'\xa5' * limit}))
                self.assertEqual(made, wire(b'\xa5' * limit))
            with self.subTest(record=name, size=limit + 1), self.assertRaisesRegex(ProtocolError, 'record_overflow'):
                maker.make(**kwargs, **{field: b'\xa5' * (limit + 1)})


class FurtherRecordTests(unittest.TestCase):
    """A record after another past its bound stays raw, and one at it is a further layer."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def chain(self, layer: 'object') -> 'list[str]':
        return str(layer.protochain).split(':')  # type: ignore[attr-defined]

    def test_tls(self) -> None:
        from pcapkit.protocols.application.tls.protocol import TLS

        alert = _tls(b'\x01\x00', content_type=21)
        self.assertEqual(self.chain(TLS(alert + _tls(b'\xa5' * LIMIT))), ['TLS 1.2', 'TLS 1.2'])
        self.assertEqual(self.chain(TLS(alert + _tls(b'\xa5' * (LIMIT + 1)))), ['TLS 1.2', 'Raw'])

    def test_dtls(self) -> None:
        from pcapkit.protocols.application.dtls.protocol import DTLS

        alert = _dtls(b'\x01\x00', content_type=21)
        cases = (
            ('legacy', _dtls(b'\xa5' * LIMIT), _dtls(b'\xa5' * (LIMIT + 1)), 'DTLS 1.2'),
            ('unified', _unified(b'\xa5' * UNIFIED_LIMIT), _unified(b'\xa5' * (UNIFIED_LIMIT + 1)), 'DTLS 1.3'),
            ('unified, no length', _unified(b'\xa5' * UNIFIED_LIMIT, length=False),
             _unified(b'\xa5' * (UNIFIED_LIMIT + 1), length=False), 'DTLS 1.3'),
        )
        for (name, at, past, alias) in cases:
            with self.subTest(record=name):
                self.assertEqual(self.chain(DTLS(alert + at)), ['DTLS 1.2', alias])
                self.assertEqual(self.chain(DTLS(alert + past)), ['DTLS 1.2', 'Raw'])


if __name__ == '__main__':
    unittest.main()
