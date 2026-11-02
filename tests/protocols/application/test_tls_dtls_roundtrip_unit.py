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
the other. Segments of several TLS records, and datagrams of several DTLS
records, are checked the same way, each record a layer of its own (#2517,
#2535).

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


def _server_hello_body(extensions: 'bytes | None' = b'', version: bytes = b'\x03\x03') -> bytes:
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

#: A ``ServerHello`` selecting TLS 1.3 through ``supported_versions`` (type 43).
_TLS13_SERVER_HELLO = _tls_record(22, _handshake(2, _server_hello_body(extensions=b'\x00\x2b\x00\x02\x03\x04')))

#: Segments of several records each, every one dissected as a TLS layer (#2517).
TLS_SEGMENTS = {
    'change_cipher_spec + alert': _tls_record(20, b'\x01') + _tls_record(21, b'\x02\x0a'),
    # The shape of frame 2 of Wireshark's tls13-rfc8446.pcap.
    'TLS 1.3 ServerHello + change_cipher_spec + application_data x2': (
        _TLS13_SERVER_HELLO + _tls_record(20, b'\x01')
        + _tls_record(23, bytes(range(40))) + _tls_record(23, bytes(range(40, 100)))),
    'handshake coalescing two messages + application_data': (
        _tls_record(22, _handshake(0, b'') + _handshake(14, b'')) + _tls_record(23, b'hello')),
}

#: A record the segment ends inside: 20 octets of a 55-octet record.
_PARTIAL_RECORD = _tls_record(23, bytes(50))[:20]


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


def _unified_record(fragment: bytes, *, seq: int, length_present: bool = True) -> bytes:
    """A unified-header record at epoch 2, the handshake traffic keys' (RFC 9147
    section 6.1), with an 8-bit sequence number: first octet ``001 0 0 L 10``
    (RFC 9147 section 4)."""
    if length_present:
        return bytes([0x26, seq]) + len(fragment).to_bytes(2, 'big') + fragment
    return bytes([0x22, seq]) + fragment


#: A DTLS ``ServerHello`` selecting DTLS 1.3 through ``supported_versions`` (type 43),
#: at the ``legacy_version`` RFC 9147 section 5.4 gives it.
_DTLS13_SH_BODY = _server_hello_body(extensions=b'\x00\x2b\x00\x02\xfe\xfc', version=b'\xfe\xfd')
_DTLS13_SERVER_HELLO = _dtls_record(22, _dtls_handshake(
    2, _DTLS13_SH_BODY, message_seq=0, fragment_offset=0, fragment_length=len(_DTLS13_SH_BODY)), seq=0)

#: Datagrams of several records each, every one dissected as a DTLS layer (#2535).
DTLS_DATAGRAMS = {
    'change_cipher_spec + alert': _dtls_record(20, b'\x01', seq=1) + _dtls_record(21, b'\x02\x0a', seq=2),
    # A DTLS 1.2 client's second flight: ClientKeyExchange, then the epoch-1 Finished.
    'ClientKeyExchange + change_cipher_spec + encrypted Finished': (
        _dtls_record(22, _dtls_handshake(16, bytes(range(33)), message_seq=2, fragment_offset=0,
                                         fragment_length=33), seq=2)
        + _dtls_record(20, b'\x01', seq=3)
        + _dtls_record(22, (b'\x5c\x91\x0e\xd7' * 12)[:48], epoch=1, seq=0)),
    # A DTLS 1.3 server flight: the last record may omit its length (RFC 9147 section 4).
    'DTLS 1.3 ServerHello + unified-header records, the last without a length': (
        _DTLS13_SERVER_HELLO + _unified_record(bytes(range(32)), seq=0)
        + _unified_record(bytes(range(32, 80)), seq=1, length_present=False)),
}

#: A record the datagram ends inside: 20 octets of a 63-octet record.
_PARTIAL_DTLS_RECORD = _dtls_record(23, bytes(50))[:20]


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


def _split_records(wire: bytes) -> 'list[bytes]':
    """``wire`` cut at each record's declared length, as the specification frames it."""
    records = []
    while wire:
        end = 5 + int.from_bytes(wire[3:5], 'big')
        records.append(wire[:end])
        wire = wire[end:]
    return records


def _layers(proto: 'object') -> 'tuple[list, object]':
    """Each TLS layer of ``proto``'s chain, in order, and the layer that ends it."""
    from pcapkit.protocols.application.tls import TLS

    layers = []
    while isinstance(proto, TLS):
        layers.append(proto)
        proto = proto.payload
    return layers, proto


class TestTLSSegmentRoundTrip(unittest.TestCase):
    """Pin every record of a segment as its own layer, rebuilt both directions (#2517)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_record_is_a_tls_layer(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.misc.null import NoPayload

        for name, wire in TLS_SEGMENTS.items():
            with self.subTest(segment=name):
                records = _split_records(wire)
                layers, rest = _layers(TLS(wire, len(wire)))
                self.assertEqual(len(layers), len(records))
                self.assertIsInstance(rest, NoPayload)
                for layer, record in zip(layers, records):
                    self.assertEqual(int(layer.info.content_type), record[0])
                    self.assertEqual(layer.info.version, int.from_bytes(record[1:3], 'big'))
                    self.assertEqual(layer.info.length, len(record) - 5)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.transport.tcp import TCP

        tcp_to_443 = bytes.fromhex('c35001bb00000001000000015010ffff00000000')
        for name, wire in TLS_SEGMENTS.items():
            with self.subTest(segment=name):
                parsed = TLS(wire, len(wire))
                rebuilt = TLS.from_data(parsed.info)
                self.assertEqual(bytes(rebuilt).hex(), wire.hex())
                self.assertEqual(len(_layers(rebuilt)[0]), len(_split_records(wire)))

                segment = tcp_to_443 + wire
                tcp = TCP(segment, len(segment))
                self.assertEqual(str(tcp.protochain), f'TCP:{parsed.protochain}')
                self.assertEqual(bytes(TCP.from_data(tcp.info)).hex(), segment.hex())

    def test_make_then_parse_is_byte_exact(self) -> None:
        """Each record made from its parsed content, carrying the next as ``payload``."""
        from pcapkit.protocols.application.tls import TLS

        for name, wire in TLS_SEGMENTS.items():
            with self.subTest(segment=name):
                parsed = TLS(wire, len(wire))
                layers, _ = _layers(parsed)
                maker = object.__new__(TLS)
                schema = b''  # type: object
                for layer in reversed(layers):
                    schema = maker.make(content_type=layer.info.content_type, version=layer.info.version,
                                        content=layer.info.content, payload=schema)
                made = bytes(schema)  # type: ignore[call-overload]
                self.assertEqual(made.hex(), wire.hex())
                self.assertEqual(str(TLS(made, len(made)).protochain), str(parsed.protochain))

    def test_records_match_the_specification(self) -> None:
        """Each record's own tier and content, per its header (RFC 9846 section 5.1)."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        wire = TLS_SEGMENTS['TLS 1.3 ServerHello + change_cipher_spec + application_data x2']
        layers, _ = _layers(TLS(wire, len(wire)))
        self.assertEqual([layer.alias for layer in layers], ['TLS 1.3', 'TLS 1.2', 'TLS 1.2', 'TLS 1.2'])
        self.assertEqual([layer.info.content_type for layer in layers],
                         [ContentType.handshake, ContentType.change_cipher_spec,
                          ContentType.application_data, ContentType.application_data])
        self.assertEqual(layers[1].info.content.msg, 1)
        self.assertEqual([layer.info.content for layer in layers[2:]], [bytes(range(40)), bytes(range(40, 100))])

        # The issue's example: the alert decodes, rather than staying 7 raw octets.
        wire = TLS_SEGMENTS['change_cipher_spec + alert']
        layers, _ = _layers(TLS(wire, len(wire)))
        self.assertEqual((int(layers[1].info.content.level), int(layers[1].info.content.description)), (2, 10))

    def test_trailing_partial_record_stays_raw(self) -> None:
        """The record a segment ends inside is the reassembly limit, kept as its own octets."""
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.misc.raw import Raw

        for name, segment in TLS_SEGMENTS.items():
            with self.subTest(segment=name):
                wire = segment + _PARTIAL_RECORD
                parsed = TLS(wire, len(wire))
                layers, rest = _layers(parsed)
                self.assertEqual(len(layers), len(_split_records(segment)))
                self.assertIs(type(rest), Raw)
                self.assertEqual(bytes(rest), _PARTIAL_RECORD)
                self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())


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


def _split_dtls_records(wire: bytes) -> 'list[bytes]':
    """``wire`` cut at each record's end, as RFC 9147 section 4 frames it: a legacy
    header's length, a unified header's length, or the end of the datagram."""
    records = []
    while wire:
        if wire[0] >> 5 == 0b001:
            header = 1 + (2 if wire[0] & 0x08 else 1) + (2 if wire[0] & 0x04 else 0)
            end = header + int.from_bytes(wire[header - 2:header], 'big') if wire[0] & 0x04 else len(wire)
        else:
            end = 13 + int.from_bytes(wire[11:13], 'big')
        records.append(wire[:end])
        wire = wire[end:]
    return records


def _dtls_layers(proto: 'object') -> 'tuple[list, object]':
    """Each DTLS layer of ``proto``'s chain, in order, and the layer that ends it."""
    from pcapkit.protocols.application.dtls import DTLS

    layers = []
    while isinstance(proto, DTLS):
        layers.append(proto)
        proto = proto.payload
    return layers, proto


class TestDTLSDatagramRoundTrip(unittest.TestCase):
    """Pin every record of a datagram as its own layer, rebuilt both directions (#2535)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_record_is_a_dtls_layer(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.dtls import DTLSCiphertext
        from pcapkit.protocols.misc.null import NoPayload

        for name, wire in DTLS_DATAGRAMS.items():
            with self.subTest(datagram=name):
                records = _split_dtls_records(wire)
                layers, rest = _dtls_layers(DTLS(wire, len(wire)))
                self.assertEqual(len(layers), len(records))
                self.assertIsInstance(rest, NoPayload)
                for layer, record in zip(layers, records):
                    if isinstance(layer.info, DTLSCiphertext):
                        self.assertEqual(layer.info.epoch, record[0] & 0x03)
                        self.assertEqual(layer.info.content, record[layer.length:])
                        continue
                    self.assertEqual(int(layer.info.content_type), record[0])
                    self.assertEqual(layer.info.version, int.from_bytes(record[1:3], 'big'))
                    self.assertEqual(layer.info.epoch, int.from_bytes(record[3:5], 'big'))
                    self.assertEqual(layer.info.sequence_number, int.from_bytes(record[5:11], 'big'))
                    self.assertEqual(layer.info.length, len(record) - 13)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.transport.udp import UDP

        for name, wire in DTLS_DATAGRAMS.items():
            with self.subTest(datagram=name):
                parsed = DTLS(wire, len(wire))
                rebuilt = DTLS.from_data(parsed.info)
                self.assertEqual(bytes(rebuilt).hex(), wire.hex())
                self.assertEqual(len(_dtls_layers(rebuilt)[0]), len(_split_dtls_records(wire)))

                datagram = (50000).to_bytes(2, 'big') + (5684).to_bytes(2, 'big') \
                    + (8 + len(wire)).to_bytes(2, 'big') + b'\x00\x00' + wire
                udp = UDP(datagram, len(datagram))
                self.assertEqual(str(udp.protochain), f'UDP:{parsed.protochain}')
                self.assertEqual(bytes(UDP.from_data(udp.info)).hex(), datagram.hex())

    def test_make_then_parse_is_byte_exact(self) -> None:
        """Each record made from its parsed fields, carrying the next as ``payload``."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.dtls import DTLSCiphertext

        for name, wire in DTLS_DATAGRAMS.items():
            with self.subTest(datagram=name):
                parsed = DTLS(wire, len(wire))
                layers, _ = _dtls_layers(parsed)
                maker = object.__new__(DTLS)
                schema = b''  # type: object
                for layer in reversed(layers):
                    info = layer.info
                    if isinstance(info, DTLSCiphertext):
                        schema = maker.make(ciphertext=True, epoch=info.epoch,
                                            sequence_number=info.sequence_number,
                                            sequence_long=info.sequence_long,
                                            length_present=info.length is not None,
                                            content=info.content, payload=schema)
                    else:
                        schema = maker.make(content_type=info.content_type, version=info.version,
                                            epoch=info.epoch, sequence_number=info.sequence_number,
                                            content=info.content, payload=schema)
                made = bytes(schema)  # type: ignore[call-overload]
                self.assertEqual(made.hex(), wire.hex())
                self.assertEqual(str(DTLS(made, len(made)).protochain), str(parsed.protochain))

    def test_records_match_the_specification(self) -> None:
        """Each record's own tier and fields, per its header (RFC 9147 section 4)."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS

        wire = DTLS_DATAGRAMS['DTLS 1.3 ServerHello + unified-header records, the last without a length']
        layers, _ = _dtls_layers(DTLS(wire, len(wire)))
        self.assertEqual([layer.alias for layer in layers], ['DTLS 1.3'] * 3)
        self.assertEqual(layers[0].info.content_type, ContentType.handshake)
        self.assertEqual(int(layers[0].info.content[0].msg_type), 2)
        self.assertEqual([(layer.info.epoch, layer.info.sequence_number) for layer in layers[1:]],
                         [(2, 0), (2, 1)])
        self.assertEqual([layer.info.length for layer in layers[1:]], [32, None])
        self.assertEqual([layer.info.content for layer in layers[1:]], [bytes(range(32)), bytes(range(32, 80))])

        wire = DTLS_DATAGRAMS['ClientKeyExchange + change_cipher_spec + encrypted Finished']
        layers, _ = _dtls_layers(DTLS(wire, len(wire)))
        self.assertEqual([layer.alias for layer in layers], ['DTLS 1.2'] * 3)
        self.assertEqual([(layer.info.epoch, layer.info.sequence_number) for layer in layers],
                         [(0, 2), (0, 3), (1, 0)])
        self.assertEqual(int(layers[0].info.content[0].msg_type), 16)
        self.assertEqual(layers[1].info.content.msg, 1)
        self.assertEqual(layers[2].info.content, (b'\x5c\x91\x0e\xd7' * 12)[:48])

        # The alert decodes, rather than staying 15 raw octets.
        wire = DTLS_DATAGRAMS['change_cipher_spec + alert']
        layers, _ = _dtls_layers(DTLS(wire, len(wire)))
        self.assertEqual((int(layers[1].info.content.level), int(layers[1].info.content.description)), (2, 10))

    def test_trailing_partial_record_stays_raw(self) -> None:
        """A record the datagram ends inside is kept as its own octets, with no error."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.misc.raw import Raw

        for name in ('change_cipher_spec + alert', 'ClientKeyExchange + change_cipher_spec + encrypted Finished'):
            with self.subTest(datagram=name):
                wire = DTLS_DATAGRAMS[name] + _PARTIAL_DTLS_RECORD
                parsed = DTLS(wire, len(wire))
                layers, rest = _dtls_layers(parsed)
                self.assertEqual(len(layers), len(_split_dtls_records(DTLS_DATAGRAMS[name])))
                self.assertIs(type(rest), Raw)
                self.assertEqual(bytes(rest), _PARTIAL_DTLS_RECORD)
                self.assertIsNone(rest.info.error)  # type: ignore[attr-defined]
                self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())


if __name__ == '__main__':
    unittest.main()
