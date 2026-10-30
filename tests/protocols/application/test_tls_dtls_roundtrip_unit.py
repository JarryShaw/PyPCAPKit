# -*- coding: utf-8 -*-
"""TLS and DTLS records rebuild byte for byte.

Hand-crafted wire octets for every content type and handshake-message shape
the TLS and DTLS dissectors implement (:issue:`2437`): ``handshake`` carrying a ``ClientHello``,
a ``ServerHello``, a message-TYPE-level-only type, and several messages
coalesced in one record; ``alert``; ``change_cipher_spec``;
``application_data``; and, for DTLS, both an unfragmented handshake message
(which decodes exactly as TLS's does) and a message split across two
fragments (which does not, since one is not reassembled -- see
:class:`~pcapkit.protocols.application.dtls.DTLS`).

Every case is checked two ways: parsing the wire octets and rebuilding them
through :meth:`~pcapkit.protocols.application.application.Application.from_data`
(the parse-then-rebuild direction), and building the same octets through
:meth:`~pcapkit.protocols.application.tls.TLS.make`/
:meth:`~pcapkit.protocols.application.dtls.DTLS.make` and reading them back
(the make-then-parse direction) -- so neither direction is a tautology of
the other.

"""
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'


def _tls_record(content_type: int, fragment: bytes, version: bytes = b'\x03\x03') -> bytes:
    return bytes([content_type]) + version + len(fragment).to_bytes(2, 'big') + fragment


def _handshake(msg_type: int, body: bytes) -> bytes:
    return bytes([msg_type]) + len(body).to_bytes(3, 'big') + body


def _client_hello_body(cipher_suites: bytes = b'\x13\x01', extensions: 'bytes | None' = b'') -> bytes:
    version = b'\x03\x03'
    random = bytes(range(32))
    session_id = b''
    compression = b'\x00'
    tail = b'' if extensions is None else len(extensions).to_bytes(2, 'big') + extensions
    return (version + random + bytes([len(session_id)]) + session_id
            + len(cipher_suites).to_bytes(2, 'big') + cipher_suites
            + bytes([len(compression)]) + compression
            + tail)


def _server_hello_body(extensions: 'bytes | None' = b'') -> bytes:
    version = b'\x03\x03'
    random = bytes(range(32, 64))
    session_id = b''
    cipher_suite = b'\x13\x01'
    compression = b'\x00'
    tail = b'' if extensions is None else len(extensions).to_bytes(2, 'big') + extensions
    return (version + random + bytes([len(session_id)]) + session_id
            + cipher_suite + compression + tail)


#: Wire octets that must rebuild unchanged, by case name.
TLS_RECORDS = {
    'handshake: ClientHello': _tls_record(22, _handshake(1, _client_hello_body())),
    'handshake: ClientHello with an extension': _tls_record(
        22, _handshake(1, _client_hello_body(extensions=b'\x00\x0d\x00\x02\xab\xcd'))),
    'handshake: ClientHello with no extensions field at all': _tls_record(
        22, _handshake(1, _client_hello_body(extensions=None))),
    'handshake: ServerHello': _tls_record(22, _handshake(2, _server_hello_body())),
    'handshake: ServerHello with no extensions field at all': _tls_record(
        22, _handshake(2, _server_hello_body(extensions=None))),
    'handshake: Finished (message-type-level only)': _tls_record(22, _handshake(20, b'\x01\x02\x03\x04')),
    'handshake: HelloRequest + ServerHelloDone coalesced': _tls_record(
        22, _handshake(0, b'') + _handshake(14, b'')),
    # Content type 22 after the handshake has derived keys: ciphertext, which
    # the message headers do not tile, so it stays opaque rather than being
    # decoded into fabricated messages. 40 octets, as a TLS 1.2 encrypted
    # ``Finished`` is.
    'handshake: encrypted, kept as octets': _tls_record(22, (b'\x9f\x2b\x71\xc4' * 10)[:40]),
    'alert': _tls_record(21, b'\x02\x0a'),
    'change_cipher_spec': _tls_record(20, b'\x01'),
    'application_data': _tls_record(23, b'hello'),
    # DTLS connection-ID path validation (:rfc:`9853`).
    'return_routability_check': _tls_record(27, b'\xde\xad\xbe\xef'),
    # The other legacy record versions dispatch brands: SSLv3, TLS 1.0, TLS 1.1.
    'handshake: ClientHello at record version 0x0300': _tls_record(
        22, _handshake(1, _client_hello_body()), version=b'\x03\x00'),
    'handshake: ClientHello at record version 0x0301': _tls_record(
        22, _handshake(1, _client_hello_body()), version=b'\x03\x01'),
    'alert at record version 0x0302': _tls_record(21, b'\x02\x0a', version=b'\x03\x02'),
}


def _dtls_client_hello_body(cipher_suites: bytes = b'\x13\x01', extensions: 'bytes | None' = b'',
                            cookie: bytes = b'') -> bytes:
    """A genuine DTLS ``ClientHello`` body -- TLS's shape plus the
    length-prefixed ``cookie`` DTLS inserts between ``session_id`` and
    ``cipher_suites`` (:rfc:`6347#section-4.2.1`). ``_client_hello_body``
    above is deliberately TLS-only and must not be reused for DTLS: it has no
    cookie field at all, which is exactly the shape bug this fixture exists
    to catch.

    """
    version = b'\xfe\xfd'
    random = bytes(range(32))
    session_id = b''
    compression = b'\x00'
    tail = b'' if extensions is None else len(extensions).to_bytes(2, 'big') + extensions
    return (version + random + bytes([len(session_id)]) + session_id
            + bytes([len(cookie)]) + cookie
            + len(cipher_suites).to_bytes(2, 'big') + cipher_suites
            + bytes([len(compression)]) + compression
            + tail)


def _dtls_record(content_type: int, fragment: bytes, version: bytes = b'\xfe\xfd',
                 epoch: int = 0, seq: int = 1) -> bytes:
    return (bytes([content_type]) + version + epoch.to_bytes(2, 'big') + seq.to_bytes(6, 'big')
            + len(fragment).to_bytes(2, 'big') + fragment)


def _dtls_handshake(msg_type: int, body: bytes, *, message_seq: int, fragment_offset: int,
                    fragment_length: int, total_length: 'int | None' = None) -> bytes:
    length = total_length if total_length is not None else len(body)
    header = bytes([msg_type]) + length.to_bytes(3, 'big')
    frag_header = (message_seq.to_bytes(2, 'big') + fragment_offset.to_bytes(3, 'big')
                   + fragment_length.to_bytes(3, 'big'))
    return header + frag_header + body


#: Non-empty, so the round-trip actually exercises ``cookie``'s bytes rather
#: than merely its (zero) length.
_CH_COOKIE = b'\xab\xcd\xef\x01'
_CH_BODY = _dtls_client_hello_body(cookie=_CH_COOKIE)
_CH_HALF = len(_CH_BODY) // 2

DTLS_RECORDS = {
    'handshake: unfragmented ClientHello': _dtls_record(
        22, _dtls_handshake(1, _CH_BODY, message_seq=0, fragment_offset=0, fragment_length=len(_CH_BODY))),
    'handshake: unfragmented ClientHello with an empty cookie': _dtls_record(
        22, _dtls_handshake(1, _dtls_client_hello_body(cookie=b''), message_seq=0,
                            fragment_offset=0, fragment_length=len(_dtls_client_hello_body(cookie=b'')))),
    'handshake: fragment 1 of 2': _dtls_record(
        22, _dtls_handshake(1, _CH_BODY[:_CH_HALF], message_seq=5, fragment_offset=0,
                            fragment_length=_CH_HALF, total_length=len(_CH_BODY)), seq=2),
    'handshake: fragment 2 of 2': _dtls_record(
        22, _dtls_handshake(1, _CH_BODY[_CH_HALF:], message_seq=5, fragment_offset=_CH_HALF,
                            fragment_length=len(_CH_BODY) - _CH_HALF, total_length=len(_CH_BODY)), seq=3),
    # Content type 22 at a non-zero epoch: encrypted by definition, since the
    # epoch counts cipher changes, so the fragment stays opaque. 48 octets, as
    # a DTLS encrypted ``Finished`` is.
    'handshake: post-handshake epoch, kept as octets': _dtls_record(
        22, (b'\xa3\x5d\x12\xee' * 12)[:48], epoch=1, seq=7),
    'alert': _dtls_record(21, b'\x01\x00'),
    'change_cipher_spec': _dtls_record(20, b'\x01'),
    'return_routability_check': _dtls_record(27, b'\xde\xad\xbe\xef'),
    # DTLS 1.0's legacy record version.
    'handshake: unfragmented ClientHello at record version 0xFEFF': _dtls_record(
        22, _dtls_handshake(1, _CH_BODY, message_seq=0, fragment_offset=0,
                            fragment_length=len(_CH_BODY)), version=b'\xfe\xff'),
}


class TestTLSRoundTrip(unittest.TestCase):
    """Pin the rebuild of parsed TLS records, both directions."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        for name, wire in TLS_RECORDS.items():
            with self.subTest(record=name):
                parsed = TLS(wire, len(wire))
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_make_then_parse_is_byte_exact(self) -> None:
        """``make`` fed the just-parsed content reproduces the same octets.

        This is the other direction: it would not catch a ``make`` that
        merely replays whatever ``from_data`` already proved, since ``make``
        is driven here from the parsed *content* -- not from ``info`` -- and
        the schema it returns is packed directly, without going through
        ``from_data`` at all.

        """
        from pcapkit.protocols.application.tls import TLS

        for name, wire in TLS_RECORDS.items():
            with self.subTest(record=name):
                parsed = TLS(wire, len(wire))
                maker = object.__new__(TLS)
                schema = maker.make(content_type=parsed.info.content_type,
                                    version=parsed.info.version,
                                    content=parsed.info.content)
                self.assertEqual(bytes(schema).hex(), wire.hex())

    def test_coalesced_handshake_decodes_both_messages(self) -> None:
        """Byte-exact rebuild alone does not prove the walk decoded anything.

        Opaque bytes rebuild exactly too, so a handshake-tiling walk that
        were broken to only check the first message's header (rather than
        walking all of them) would still pass
        ``test_parse_then_rebuild_is_byte_exact`` on this very fixture --
        the coalesced-record case is exactly where that gap hides, since
        the record happens to rebuild byte-for-byte regardless of whether
        the second message was actually decoded. This asserts the decoded
        message *count* and *types*, which that broken walk would get wrong.

        """
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import Handshake

        wire = TLS_RECORDS['handshake: HelloRequest + ServerHelloDone coalesced']
        parsed = TLS(wire, len(wire))

        self.assertEqual(len(parsed.info.content), 2)
        self.assertTrue(all(isinstance(message, Handshake) for message in parsed.info.content))
        self.assertEqual(
            [message.msg_type for message in parsed.info.content],
            [HandshakeType.hello_request, HandshakeType.server_hello_done],
        )

    def test_malformed_client_hello_raises_protocol_error(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        # A ClientHello whose declared body is shorter than its fixed fields
        # (version + random alone need 34 octets).
        truncated = _tls_record(22, _handshake(1, b'\x03\x03' + b'\x00' * 10))
        with self.assertRaises(ProtocolError):
            TLS(truncated, len(truncated))

    def test_alert_record_with_excess_octets_keeps_its_octets(self) -> None:
        """A 3-octet TLS ``alert`` fragment is not a malformed cleartext alert.

        An encrypted alert is never exactly 2 octets, so a non-2-octet
        fragment is kept opaque rather than raising, the same discipline
        applied to the encrypted close_notify case below.

        """
        from pcapkit.protocols.application.tls import TLS

        wire = _tls_record(21, b'\x02\x0a\x00')
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.info.content, b'\x02\x0a\x00')
        self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)


class TestDTLSRoundTrip(unittest.TestCase):
    """Pin the rebuild of parsed DTLS records, both directions."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for name, wire in DTLS_RECORDS.items():
            with self.subTest(record=name):
                parsed = DTLS(wire, len(wire))
                self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

    def test_make_then_parse_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for name, wire in DTLS_RECORDS.items():
            with self.subTest(record=name):
                parsed = DTLS(wire, len(wire))
                maker = object.__new__(DTLS)
                schema = maker.make(content_type=parsed.info.content_type,
                                    version=parsed.info.version,
                                    epoch=parsed.info.epoch,
                                    sequence_number=parsed.info.sequence_number,
                                    content=parsed.info.content)
                self.assertEqual(bytes(schema).hex(), wire.hex())

    def test_fragment_is_flagged_and_body_kept_undecoded(self) -> None:
        """The documented limitation: a fragmented message is not reassembled."""
        from pcapkit.protocols.application.dtls import DTLS

        wire = DTLS_RECORDS['handshake: fragment 1 of 2']
        parsed = DTLS(wire, len(wire))
        message = parsed.info.content[0]

        self.assertTrue(message.is_fragmented)
        self.assertIsInstance(message.body, bytes)
        self.assertEqual(message.body, _CH_BODY[:_CH_HALF])

    def test_unfragmented_message_decodes_its_client_hello(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = DTLS_RECORDS['handshake: unfragmented ClientHello']
        parsed = DTLS(wire, len(wire))
        message = parsed.info.content[0]

        self.assertFalse(message.is_fragmented)
        self.assertEqual(message.body.cipher_suites, (0x1301,))

    def test_unfragmented_client_hello_decodes_its_cookie(self) -> None:
        """RFC 6347 Sec.4.2.1 / RFC 9147 Sec.5.3's ``cookie`` field.

        The fixture this guards replaced one that was TLS-shaped -- no
        cookie field at all -- and so could not have caught a DTLS
        ``ClientHello`` reader that never looked for one.

        """
        from pcapkit.protocols.application.dtls import DTLS

        wire = DTLS_RECORDS['handshake: unfragmented ClientHello']
        parsed = DTLS(wire, len(wire))
        message = parsed.info.content[0]

        self.assertFalse(message.is_fragmented)
        self.assertEqual(message.body.cookie, _CH_COOKIE)

    def test_unfragmented_client_hello_with_an_empty_cookie(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = DTLS_RECORDS['handshake: unfragmented ClientHello with an empty cookie']
        parsed = DTLS(wire, len(wire))
        message = parsed.info.content[0]

        self.assertFalse(message.is_fragmented)
        self.assertEqual(message.body.cookie, b'')


if __name__ == '__main__':
    unittest.main()
