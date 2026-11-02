# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.sslv2`.

SSLv2's record header is 2 or 3 octets depending on the high bit of its first
octet (:issue:`2457`), so every case below is built and read back in both
header forms, for both handshake messages this package parses the body of --
``CLIENT-HELLO`` and ``SERVER-HELLO`` -- plus one message type it does not
(``CLIENT-FINISHED``), which must still round-trip as raw octets rather than
losing the record. Every case builds its own octets in memory and reads no
capture.

Round trips are checked as ``bytes(SSLv2.from_data(parsed.info)) == raw``,
which routes through ``_make_data`` and ``make``; ``parsed.data`` is the
constructor's input echoed back, so comparing it to ``raw`` checks nothing.
Segments of several records are checked both ways too, each record a layer of
its own (#2567).

"""
from __future__ import annotations

import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: A 20-octet TCP header, 50000 to 443, ACK.
TCP_TO_443 = bytes.fromhex('c35001bb00000001000000015010ffff00000000')

#: CLIENT-HELLO, 2-octet header, RECORD-LENGTH 28: CLIENT-VERSION 0x0002, one
#: cipher spec, no session id, a 16-octet challenge.
CLIENT_HELLO = bytes.fromhex('801c' '01' '0002' '0003' '0000' '0010' '010080') + bytes(16)
#: CLIENT-MASTER-KEY, 2-octet header, RECORD-LENGTH 14: CIPHER-KIND, then
#: CLEAR-KEY-LENGTH 0, ENCRYPTED-KEY-LENGTH 4, KEY-ARG-LENGTH 0 and the key.
CLIENT_MASTER_KEY = bytes.fromhex('800e' '02' '010080' '0000' '0004' '0000' 'deadbeef')
#: SERVER-HELLO, 2-octet header, RECORD-LENGTH 34 (as in ``test_ssl_tls_dtls_unit``).
SERVER_HELLO = bytes.fromhex('80220400010002000400030010aaaaaaaa010080') + b'\xbb' * 16
#: SERVER-VERIFY, 3-octet header (no escape), RECORD-LENGTH 17, PADDING 7.
SERVER_VERIFY = bytes.fromhex('001107' '05') + bytes(range(16))
#: SERVER-FINISHED, 2-octet header, RECORD-LENGTH 17.
SERVER_FINISHED = bytes.fromhex('8011' '06') + bytes(range(16, 32))
#: A 2-octet header declaring RECORD-LENGTH 0, which leaves no MSG-TYPE.
ZERO_LENGTH = b'\x80\x00'

#: Segments of several records each, every one dissected as an SSLv2 layer (#2567).
SEGMENTS = {
    'CLIENT-HELLO + CLIENT-MASTER-KEY': CLIENT_HELLO + CLIENT_MASTER_KEY,
    'SERVER-HELLO + SERVER-VERIFY (3-octet header) + SERVER-FINISHED': (
        SERVER_HELLO + SERVER_VERIFY + SERVER_FINISHED),
}


def _split_records(wire: bytes) -> 'list[tuple[int, bytes]]':
    """``wire`` cut at each record's RECORD-LENGTH, with its header length, per the draft's §4.1."""
    records = []
    while wire:
        if wire[0] & 0x80:
            header_len, record_length = 2, ((wire[0] & 0x7F) << 8) | wire[1]
        else:
            header_len, record_length = 3, ((wire[0] & 0x3F) << 8) | wire[1]
        records.append((header_len, wire[:header_len + record_length]))
        wire = wire[header_len + record_length:]
    return records


def _layers(proto: 'Any') -> 'tuple[list[Any], Any]':
    """Each SSLv2 layer of ``proto``'s chain, in order, and the layer that ends it."""
    from pcapkit.protocols.application.sslv2 import SSLv2

    layers = []
    while isinstance(proto, SSLv2):
        layers.append(proto)
        proto = proto.payload
    return layers, proto


def _behind_tcp_443(wire: bytes, **stop: 'Any') -> 'tuple[Any, Any]':
    """``wire`` parsed behind TLS's SSLv2 fallback on TCP 443, and the layer ending its SSLv2 chain."""
    from pcapkit.protocols.transport.tcp import TCP

    segment = TCP_TO_443 + wire
    tcp = TCP(segment, len(segment), **stop)
    # NOTE: The first record is a TLS layer that adopted the SSLv2 parse, so walk by alias.
    proto = tcp.payload
    while proto.alias == 'SSLv2':
        proto = proto.payload
    return tcp, proto


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestSSLv2RoundTrip(unittest.TestCase):
    """Parse-then-rebuild pins for every record shape this package builds."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_client_hello_two_byte_header_round_trips(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2(
            msg_type=HandshakeType.CLIENT_HELLO,
            two_byte_header=True,
            body={
                'cipher_specs': b'\x01\x00\x80' + b'\x02\x00\x80',
                'session_id': b'\x00' * 16,
                'challenge': b'\xab' * 16,
            },
        )
        raw = proto.data

        # The 2-octet header form: high bit of the first octet set.
        self.assertEqual(raw[0] & 0x80, 0x80)

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.length, 2)
        self.assertTrue(parsed.info.two_byte_header)
        self.assertEqual(parsed.info.msg_type, HandshakeType.CLIENT_HELLO)
        self.assertEqual(parsed.info.body.cipher_specs, b'\x01\x00\x80\x02\x00\x80')
        self.assertEqual(parsed.info.body.session_id, b'\x00' * 16)
        self.assertEqual(parsed.info.body.challenge, b'\xab' * 16)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_client_hello_three_byte_header_round_trips(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2(
            msg_type=HandshakeType.CLIENT_HELLO,
            two_byte_header=False,
            is_escape=False,
            padding=0,
            body={
                'cipher_specs': b'\x01\x00\x80',
                'session_id': b'',
                'challenge': b'\xcd' * 32,
            },
        )
        raw = proto.data

        # The 3-octet header form: high bit of the first octet clear.
        self.assertEqual(raw[0] & 0x80, 0x00)

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.length, 3)
        self.assertFalse(parsed.info.two_byte_header)
        self.assertFalse(parsed.info.is_escape)
        self.assertEqual(parsed.info.padding, 0)
        self.assertEqual(parsed.info.body.session_id, b'')
        self.assertEqual(parsed.info.body.challenge, b'\xcd' * 32)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_server_hello_two_byte_header_round_trips(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2(
            msg_type=HandshakeType.SERVER_HELLO,
            two_byte_header=True,
            body={
                'session_id_hit': False,
                'certificate_type': 1,
                'certificate': b'\xee' * 10,
                'cipher_specs': b'\x01\x00\x80',
                'connection_id': b'\x11' * 16,
            },
        )
        raw = proto.data

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.length, 2)
        self.assertEqual(parsed.info.msg_type, HandshakeType.SERVER_HELLO)
        self.assertFalse(parsed.info.body.session_id_hit)
        self.assertEqual(parsed.info.body.certificate_type, 1)
        self.assertEqual(parsed.info.body.certificate, b'\xee' * 10)
        self.assertEqual(parsed.info.body.cipher_specs, b'\x01\x00\x80')
        self.assertEqual(parsed.info.body.connection_id, b'\x11' * 16)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_server_hello_three_byte_header_session_id_hit_round_trips(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        # A SESSION-ID-HIT SERVER-HELLO carries no certificate or cipher specs.
        proto = SSLv2(
            msg_type=HandshakeType.SERVER_HELLO,
            two_byte_header=False,
            is_escape=True,
            padding=7,
            body={
                'session_id_hit': True,
                'certificate_type': 0,
                'certificate': b'',
                'cipher_specs': b'',
                'connection_id': b'\x22' * 32,
            },
        )
        raw = proto.data

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.length, 3)
        self.assertTrue(parsed.info.is_escape)
        self.assertEqual(parsed.info.padding, 7)
        self.assertTrue(parsed.info.body.session_id_hit)
        self.assertEqual(parsed.info.body.certificate, b'')
        self.assertEqual(parsed.info.body.cipher_specs, b'')
        self.assertEqual(parsed.info.body.connection_id, b'\x22' * 32)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_server_hello_session_id_hit_preserves_non_boolean_octet(self) -> None:
        """``SESSION-ID-HIT`` is any *non-zero* octet per the draft (§5.6.1),
        not specifically ``0x01``, so the exact octet survives a round trip
        rather than being normalised to a :obj:`bool`."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2(
            msg_type=HandshakeType.SERVER_HELLO,
            two_byte_header=True,
            body={
                'session_id_hit': 0xFF,
                'certificate_type': 0,
                'certificate': b'',
                'cipher_specs': b'',
                'connection_id': b'\x33' * 16,
            },
        )
        raw = proto.data

        parsed = SSLv2(raw, len(raw))
        # Truthy, as the draft's "any non-zero value" says -- but the point
        # of this test is the *exact* octet, not just its truthiness.
        self.assertTrue(parsed.info.body.session_id_hit)
        self.assertEqual(parsed.info.body.session_id_hit, 0xFF)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_unimplemented_message_type_keeps_raw_body(self) -> None:
        """A message type this package does not decode the body of -- here
        ``CLIENT-FINISHED`` -- is kept as raw octets rather than dropped."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body=b'\x01\x02\x03\x04')
        raw = proto.data

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.info.msg_type, HandshakeType.CLIENT_FINISHED)
        self.assertEqual(parsed.info.body, b'\x01\x02\x03\x04')
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_from_data_keeps_both_records_when_chained(self) -> None:
        """A second record chained onto the first survives a ``from_data``
        round trip: ``_make_data`` passes ``payload`` through to ``make``."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        first = SSLv2(msg_type=HandshakeType.CLIENT_HELLO, two_byte_header=True, body={
            'cipher_specs': b'\x01\x00\x80', 'session_id': b'', 'challenge': b'\xcc' * 16,
        })
        second = SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, two_byte_header=True,
                      body=b'\x01\x02\x03\x04')
        combined = bytes(first) + bytes(second)

        parsed = SSLv2(combined, len(combined))
        self.assertEqual(bytes(parsed.payload), bytes(second))
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), combined)

    def test_from_data_raises_no_unknown_field_warning(self) -> None:
        """``from_data`` emits no :exc:`UnknownFieldWarning`: ``_make_data``
        drops derived fields such as ``header_len`` and ``record_length``."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.warnings import UnknownFieldWarning

        proto = SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body=b'\x01\x02\x03\x04')
        raw = proto.data
        parsed = SSLv2(raw, len(raw))

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            SSLv2.from_data(parsed.info)
        self.assertEqual([w for w in caught if issubclass(w.category, UnknownFieldWarning)], [])

    def test_maximum_length_record_parses_and_one_past_it_is_refused(self) -> None:
        """Each header form carries exactly its maximum ``RECORD-LENGTH``
        (``0x7FFF`` and ``0x3FFF``), checked against literal header octets;
        one octet more is refused rather than wrapped into the flag bits."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        finished = int(HandshakeType.CLIENT_FINISHED)
        cases = (
            # (two_byte_header, is_escape, maximum, header octets)
            (True, False, 0x7FFF, b'\xff\xff'),
            (False, False, 0x3FFF, b'\x3f\xff\x00'),
            (False, True, 0x3FFF, b'\x7f\xff\x00'),
        )
        for two_byte_header, is_escape, maximum, header in cases:
            with self.subTest(two_byte_header=two_byte_header, is_escape=is_escape):
                body = bytes(range(256)) * (maximum // 256) + b'\x5a' * (maximum % 256 - 1)
                raw = header + bytes([finished]) + body
                self.assertEqual(len(raw), len(header) + maximum)

                parsed = SSLv2(raw, len(raw))
                self.assertEqual(parsed.length, len(header))
                self.assertEqual(parsed.info.two_byte_header, two_byte_header)
                self.assertEqual(parsed.info.is_escape, is_escape)
                self.assertEqual(parsed.info.record_length, maximum)
                self.assertEqual(parsed.info.body, body)
                self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

                form = '2-octet' if two_byte_header else '3-octet'
                refused = rf'SSLv2: record \({maximum + 1} octet\(s\)\) too long for the {form}'
                with self.assertRaisesRegex(ProtocolError, refused):
                    SSLv2(msg_type=finished, two_byte_header=two_byte_header,
                          is_escape=is_escape, body=body + b'\x00')

    def test_zero_record_length_is_refused_rather_than_corrupting_the_next_record(self) -> None:
        """A conformant ``RECORD-LENGTH`` is always >= 1 (it counts
        ``MSG-TYPE`` itself). A malformed capture declaring ``0`` is refused
        rather than reading ``MSG-TYPE`` and the body from the next record."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        second_record = bytes(SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, two_byte_header=True,
                                   body=b'\xaa\xbb'))
        # 2-octet header, high bit set, RECORD-LENGTH = 0.
        malformed = bytes([0x80, 0x00]) + second_record

        with self.assertRaisesRegex(ProtocolError, r'SSLv2: record length \(0\) is too short'):
            SSLv2(malformed, len(malformed))

    def test_zero_record_length_schema_leaves_the_next_record_as_payload(self) -> None:
        """The schema alone, without ``read()``'s check, sizes the body of a
        ``RECORD-LENGTH = 0`` record to nothing rather than the rest of the buffer."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.schema.application.sslv2 import SSLv2 as Schema_SSLv2

        second_record = bytes(SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, two_byte_header=True,
                                   body=b'\xaa\xbb'))
        for header in (b'\x80\x00', b'\x00\x00\x00'):
            with self.subTest(header=header):
                malformed = header + bytes([HandshakeType.CLIENT_FINISHED]) + second_record
                schema = Schema_SSLv2.unpack(malformed)
                self.assertEqual(schema.body.data, b'')
                self.assertEqual(schema.payload, second_record)

    def test_make_rejects_out_of_range_padding(self) -> None:
        """``padding`` is written as a single octet for the 3-octet header
        form, so an out-of-range value is refused rather than wrapped mod 256;
        a ``bool``, which would pack as ``0x00``/``0x01``, and a non-``int``,
        which would reach a bare ``TypeError``, are refused too (#2614)."""
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        for padding in (256, 300, -1, True, False, '1', 1.0, None):
            with self.subTest(padding=padding):
                with self.assertRaises(ProtocolError) as ctx:
                    SSLv2(msg_type=1, two_byte_header=False, padding=padding, body=b'')
                self.assertEqual(str(ctx.exception), f'SSLv2: invalid padding: {padding!r}')
        self.assertEqual(SSLv2(msg_type=1, two_byte_header=False, padding=255, body=b'').data[2],
                         255)

    def test_ids_are_stable(self) -> None:
        from pcapkit.protocols.application.sslv2 import SSLv2

        self.assertEqual(SSLv2.id(), ('SSLv2',))

    def test_name_property(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        # ``CLIENT-FINISHED`` so the (deliberately empty) raw body does not
        # short-read against ``ClientHello``'s fixed fields.
        proto = SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body=b'')
        self.assertEqual(proto.name, 'Secure Sockets Layer version 2')
        self.assertEqual(proto.alias, 'SSLv2')

    def test_omitted_body_defaults_to_empty_client_hello(self) -> None:
        """``body=None`` (the default) builds the same empty ``CLIENT-HELLO``
        body as ``body={}`` would, rather than raising."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        proto = SSLv2()
        self.assertEqual(proto.info.msg_type, HandshakeType.CLIENT_HELLO)
        self.assertEqual(proto.info.body.cipher_specs, b'')
        self.assertEqual(proto.info.body.session_id, b'')

    def test_make_accepts_a_data_model_body(self) -> None:
        """A :class:`~pcapkit.protocols.data.application.sslv2.ClientHello`/
        :class:`~pcapkit.protocols.data.application.sslv2.ServerHello` data
        model -- e.g. a round trip through :meth:`~pcapkit.protocols.protocol.Protocol.from_data`
        -- rebuilds the same body a dict would."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        first = SSLv2(msg_type=HandshakeType.CLIENT_HELLO, body={
            'cipher_specs': b'\x01\x00\x80', 'session_id': b'', 'challenge': b'\xcc' * 16,
        })
        second = SSLv2(msg_type=HandshakeType.CLIENT_HELLO, body=first.info.body)
        self.assertEqual(second.data, first.data)

        hello = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body={
            'certificate': b'\xdd' * 4, 'cipher_specs': b'\x01\x00\x80', 'connection_id': b'\x33' * 16,
        })
        rebuilt = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body=hello.info.body)
        self.assertEqual(rebuilt.data, hello.data)

    def test_make_accepts_a_prebuilt_schema_body(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.schema.application.sslv2 import ClientHello as Schema_ClientHello

        schema = Schema_ClientHello(
            client_version=2, cipher_specs_length=0, session_id_length=0, challenge_length=16,
            cipher_specs=b'', session_id=b'', challenge=b'\xee' * 16,
        )
        proto = SSLv2(msg_type=HandshakeType.CLIENT_HELLO, body=schema)
        parsed = SSLv2(proto.data, len(proto.data))
        self.assertEqual(parsed.info.body.challenge, b'\xee' * 16)

    def test_dict_body_refused_for_an_unparsed_message_type(self) -> None:
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'SSLv2: a .* body must be given as bytes'):
            SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body={'foo': b'bar'})

    def test_invalid_body_type_is_refused(self) -> None:
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'SSLv2: invalid body: '):
            SSLv2(msg_type=1, body=12345)

    def test_make_rejects_out_of_range_session_id_hit(self) -> None:
        """``SESSION-ID-HIT`` is a single octet, so ``256``, ``300`` and ``-1``
        are refused rather than wrapped mod 256; ``0`` and ``255`` build."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        for bad in (256, 300, -1):
            with self.assertRaisesRegex(ProtocolError, rf'^SSLv2: invalid session_id_hit: {bad}$'):
                SSLv2(msg_type=HandshakeType.SERVER_HELLO, body={
                    'session_id_hit': bad, 'certificate_type': 0, 'certificate': b'',
                    'cipher_specs': b'', 'connection_id': b'\x00' * 16,
                })

        for good in (0, 255):
            proto = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body={
                'session_id_hit': good, 'certificate_type': 0, 'certificate': b'',
                'cipher_specs': b'', 'connection_id': b'\x00' * 16,
            })
            raw = proto.data
            parsed = SSLv2(raw, len(raw))
            self.assertEqual(parsed.info.body.session_id_hit, good)

    def test_make_rejects_mismatched_data_model_body_msg_type(self) -> None:
        """A :class:`~pcapkit.protocols.data.application.sslv2.ClientHello`/
        :class:`~pcapkit.protocols.data.application.sslv2.ServerHello` data
        model handed to ``make()`` is refused unless ``msg_type`` matches it,
        since a mismatched record would re-parse as another type's fields."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        hello = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body={
            'certificate': b'\xdd' * 4, 'cipher_specs': b'\x01\x00\x80', 'connection_id': b'\x33' * 16,
        })
        server_hello_body = hello.info.body

        with self.assertRaisesRegex(ProtocolError, r'ServerHello body must be given with msg_type=SERVER_HELLO'):
            SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body=server_hello_body)

        with self.assertRaisesRegex(ProtocolError, r'ServerHello body must be given with msg_type=SERVER_HELLO'):
            SSLv2(msg_type=HandshakeType.CLIENT_HELLO, body=server_hello_body)

        client_hello = SSLv2(msg_type=HandshakeType.CLIENT_HELLO, body={
            'cipher_specs': b'\x01\x00\x80', 'session_id': b'', 'challenge': b'\xcc' * 16,
        })
        client_hello_body = client_hello.info.body

        with self.assertRaisesRegex(ProtocolError, r'ClientHello body must be given with msg_type=CLIENT_HELLO'):
            SSLv2(msg_type=HandshakeType.SERVER_HELLO, body=client_hello_body)

    def test_server_hello_hand_built_wire_bytes_parses(self) -> None:
        """A hand-written ``SERVER-HELLO``, not derived from ``make()``, parsed
        as a known answer: a round trip alone cannot catch a bug shared by
        ``make()`` and ``read()``."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        # 2-octet header, RECORD-LENGTH=34: MSG-SERVER-HELLO(4),
        # SESSION-ID-HIT=0, CERTIFICATE-TYPE=1, SERVER-VERSION=0x0002,
        # CERTIFICATE-LENGTH=4, CIPHER-SPECS-LENGTH=3, CONNECTION-ID-LENGTH=16,
        # CERTIFICATE=\xaa*4, CIPHER-SPECS=\x01\x00\x80, CONNECTION-ID=\xbb*16.
        raw = bytes.fromhex(
            '80220400010002000400030010aaaaaaaa010080'
            'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
        )

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.length, 2)
        self.assertEqual(parsed.info.record_length, 34)
        self.assertEqual(parsed.info.msg_type, HandshakeType.SERVER_HELLO)
        self.assertFalse(parsed.info.body.session_id_hit)
        self.assertEqual(parsed.info.body.certificate_type, 1)
        self.assertEqual(parsed.info.body.certificate, b'\xaa' * 4)
        self.assertEqual(parsed.info.body.cipher_specs, b'\x01\x00\x80')
        self.assertEqual(parsed.info.body.connection_id, b'\xbb' * 16)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_server_hello_with_long_certificate_hand_built_wire_bytes_parses(self) -> None:
        """A hand-written ``SERVER-HELLO`` carrying a 256-octet certificate,
        so ``RECORD-LENGTH`` (286, ``0x011E``) needs the header's high length
        bits, parsed as a known answer in both header forms."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.const.sslv2.version import Version
        from pcapkit.protocols.application.sslv2 import SSLv2

        certificate = bytes(range(256))
        # MSG-SERVER-HELLO(4), SESSION-ID-HIT=0, CERTIFICATE-TYPE=1,
        # SERVER-VERSION=0x0002, CERTIFICATE-LENGTH=256,
        # CIPHER-SPECS-LENGTH=3, CONNECTION-ID-LENGTH=16, then the three fields.
        record = (bytes.fromhex('04' '00' '01' '0002' '0100' '0003' '0010')
                  + certificate + bytes.fromhex('010080') + b'\xcc' * 16)
        self.assertEqual(len(record), 0x011E)
        cases = (
            # (header octets, header_len, two_byte_header, is_escape, padding)
            (b'\x81\x1e', 2, True, False, 0),
            (b'\x41\x1e\x07', 3, False, True, 7),
        )
        for header, header_len, two_byte_header, is_escape, padding in cases:
            with self.subTest(two_byte_header=two_byte_header):
                raw = header + record
                parsed = SSLv2(raw, len(raw))
                self.assertEqual(parsed.length, header_len)
                self.assertEqual(parsed.info.two_byte_header, two_byte_header)
                self.assertEqual(parsed.info.is_escape, is_escape)
                self.assertEqual(parsed.info.padding, padding)
                self.assertEqual(parsed.info.record_length, 0x011E)
                self.assertEqual(parsed.info.msg_type, HandshakeType.SERVER_HELLO)
                self.assertEqual(parsed.info.body.session_id_hit, 0)
                self.assertEqual(parsed.info.body.certificate_type, 1)
                self.assertEqual(parsed.info.body.server_version, Version.SSLv2)
                self.assertEqual(parsed.info.body.certificate, certificate)
                self.assertEqual(parsed.info.body.cipher_specs, b'\x01\x00\x80')
                self.assertEqual(parsed.info.body.connection_id, b'\xcc' * 16)
                self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_minimal_client_hello_hand_built_wire_bytes_parses(self) -> None:
        """A ``CLIENT-HELLO`` body of exactly its 8-octet fixed sub-header,
        every length zero, still decodes as a ``CLIENT-HELLO``."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.const.sslv2.version import Version
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.data.application.sslv2 import ClientHello

        # 2-octet header, RECORD-LENGTH=9: MSG-CLIENT-HELLO(1),
        # CLIENT-VERSION=0x0002, then three zero lengths.
        raw = bytes.fromhex('8009' '01' '0002' '0000' '0000' '0000')

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.info.record_length, 9)
        self.assertEqual(parsed.info.msg_type, HandshakeType.CLIENT_HELLO)
        self.assertIsInstance(parsed.info.body, ClientHello)
        self.assertEqual(parsed.info.body.client_version, Version.SSLv2)
        self.assertEqual(parsed.info.body.cipher_specs, b'')
        self.assertEqual(parsed.info.body.session_id, b'')
        self.assertEqual(parsed.info.body.challenge, b'')
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_ciphertext_tagged_hello_falls_back_to_raw_body(self) -> None:
        """A ``SERVER-HELLO``-tagged record whose own declared sub-field
        lengths do not add up to its ``RECORD-LENGTH`` -- simulating
        ciphertext under a hello tag -- falls back to
        :class:`~pcapkit.protocols.schema.application.sslv2.UnknownHandshakeBody`,
        keeping the raw body whole."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        # 2-octet header, RECORD-LENGTH=21: MSG-SERVER-HELLO(4), followed by
        # 20 octets of "ciphertext" whose first ten -- read as SESSION-ID-HIT,
        # CERTIFICATE-TYPE, SERVER-VERSION, CERTIFICATE-LENGTH,
        # CIPHER-SPECS-LENGTH, CONNECTION-ID-LENGTH -- declare lengths far
        # larger than the 10 octets actually remaining.
        garbage_body = bytes(range(20))
        raw = bytes.fromhex('801504') + garbage_body

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.info.record_length, 21)
        self.assertEqual(parsed.info.msg_type, HandshakeType.SERVER_HELLO)
        self.assertEqual(parsed.info.body, garbage_body)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

        # The gate also holds when the parsed schema is rebuilt from its
        # dict form, which still carries the forward-matched ``probe``.
        from pcapkit.protocols.schema.application.sslv2 import SSLv2 as Schema_SSLv2
        self.assertEqual(bytes(Schema_SSLv2.from_dict(parsed.__header__.to_dict())), raw)

    def test_hello_tagged_body_shorter_than_its_fixed_sub_header_falls_back(self) -> None:
        """A hello-tagged body too short to hold even the hello's own
        fixed-width sub-header (8 octets for ``CLIENT-HELLO``, 10 for
        ``SERVER-HELLO``) cannot be a hello at all, so it is kept raw."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        cases = (
            (HandshakeType.CLIENT_HELLO, 3), (HandshakeType.CLIENT_HELLO, 7),
            (HandshakeType.SERVER_HELLO, 3), (HandshakeType.SERVER_HELLO, 9),
        )
        for msg_type, size in cases:
            with self.subTest(msg_type=msg_type, size=size):
                short_body = bytes(range(1, size + 1))
                raw = bytes([0x80, 1 + len(short_body), msg_type]) + short_body
                parsed = SSLv2(raw, len(raw))
                self.assertEqual(parsed.info.msg_type, msg_type)
                self.assertEqual(parsed.info.body, short_body)
                self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_server_hello_with_trailing_octet_falls_back_to_raw_body(self) -> None:
        """A valid ``SERVER-HELLO`` body followed by one more octet inside the
        same record overruns its declared sub-field lengths, so it is kept raw."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        hello = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body={
            'certificate_type': 1, 'certificate': b'\xaa' * 4,
            'cipher_specs': b'\x01\x00\x80', 'connection_id': b'\xbb' * 16,
        })
        body = hello.data[3:] + b'\x00'
        raw = bytes([0x80, 1 + len(body), HandshakeType.SERVER_HELLO]) + body

        parsed = SSLv2(raw, len(raw))
        self.assertEqual(parsed.info.msg_type, HandshakeType.SERVER_HELLO)
        self.assertEqual(parsed.info.body, body)
        self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def _assert_made_schema_round_trips(self, proto: 'Any') -> None:
        """``Schema_SSLv2.from_dict(made.__header__.to_dict())`` packs back
        to the made record's exact octets, with no unknown-field warning."""
        from pcapkit.protocols.schema.application.sslv2 import SSLv2 as Schema_SSLv2
        from pcapkit.utilities.warnings import UnknownFieldWarning

        made = proto.__header__.to_dict()
        self.assertNotIn('probe', made)
        with warnings.catch_warnings():
            warnings.simplefilter('error', UnknownFieldWarning)
            rebuilt = Schema_SSLv2.from_dict(made)
        self.assertEqual(bytes(rebuilt), proto.data)

    def test_made_client_hello_schema_round_trips_through_from_dict(self) -> None:
        """A ``make()``-built schema has no forward-matched ``probe``, so
        :func:`~pcapkit.protocols.schema.application.sslv2.sslv2_body_selector`
        must not treat it as an implausibly short one and pick
        ``UnknownHandshakeBody``."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        self._assert_made_schema_round_trips(SSLv2())
        for two_byte_header in (True, False):
            with self.subTest(two_byte_header=two_byte_header):
                self._assert_made_schema_round_trips(SSLv2(
                    msg_type=HandshakeType.CLIENT_HELLO, two_byte_header=two_byte_header, body={
                        'cipher_specs': b'\x01\x00\x80', 'session_id': b'\x11' * 16,
                        'challenge': b'\xcc' * 16,
                    },
                ))

    def test_made_server_hello_schema_round_trips_through_from_dict(self) -> None:
        """``SERVER-HELLO`` counterpart of the ``CLIENT-HELLO`` case above."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        self._assert_made_schema_round_trips(SSLv2(msg_type=HandshakeType.SERVER_HELLO))
        for two_byte_header in (True, False):
            with self.subTest(two_byte_header=two_byte_header):
                self._assert_made_schema_round_trips(SSLv2(
                    msg_type=HandshakeType.SERVER_HELLO, two_byte_header=two_byte_header, body={
                        'session_id_hit': 1, 'certificate_type': 1, 'certificate': b'\xdd' * 4,
                        'cipher_specs': b'\x01\x00\x80', 'connection_id': b'\x33' * 16,
                    },
                ))

    def test_read_rejects_out_of_range_session_id_hit_on_a_prebuilt_schema(self) -> None:
        """A prebuilt :class:`~pcapkit.protocols.schema.application.sslv2.ServerHello`
        bypasses ``make()``'s own ``SESSION-ID-HIT`` range check; ``read()``'s
        guard is what refuses it, where it would otherwise pack as ``0x00``
        and silently turn a HIT into a MISS. The guard takes ``int()`` first,
        so a ``bool``, a documented spelling, passes it (#2614)."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.schema.application.sslv2 import ServerHello as Schema_ServerHello
        from pcapkit.utilities.exceptions import ProtocolError

        schema = Schema_ServerHello(
            session_id_hit=256, certificate_type=0, server_version=2, certificate_length=0,
            cipher_specs_length=0, connection_id_length=16, certificate=b'', cipher_specs=b'',
            connection_id=b'\x00' * 16,
        )
        with self.assertRaisesRegex(ProtocolError, r'^SSLv2: invalid session_id_hit: 256$'):
            SSLv2(msg_type=HandshakeType.SERVER_HELLO, body=schema)
        for hit in (False, True):
            with self.subTest(hit=hit):
                schema.session_id_hit = hit
                proto = SSLv2(msg_type=HandshakeType.SERVER_HELLO, body=schema)
                self.assertEqual(proto.data[3], int(hit))  # 2-octet header, MSG-TYPE, the hit

    def test_client_hello_length_mismatch_falls_back_to_raw_body(self) -> None:
        """A ``CLIENT-HELLO``-tagged body whose declared sub-field lengths
        overrun or underrun its ``RECORD-LENGTH`` is kept as raw octets."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        # CLIENT-VERSION=0x0002, then CIPHER-SPECS-LENGTH, SESSION-ID-LENGTH,
        # CHALLENGE-LENGTH; the 8-octet sub-header is followed by 19 octets.
        tail = b'\xcc' * 19
        cases = {
            'overrun': b'\x00\x02\x00\x03\x00\x00\x00\x11' + tail,   # 3 + 17 > 19
            'underrun': b'\x00\x02\x00\x03\x00\x00\x00\x0f' + tail,  # 3 + 15 < 19
        }
        for name, body in cases.items():
            with self.subTest(case=name):
                raw = bytes([0x80, 1 + len(body), HandshakeType.CLIENT_HELLO]) + body
                parsed = SSLv2(raw, len(raw))
                self.assertEqual(parsed.info.msg_type, HandshakeType.CLIENT_HELLO)
                self.assertEqual(parsed.info.body, body)
                self.assertEqual(bytes(SSLv2.from_data(parsed.info)), raw)

    def test_make_itself_rejects_out_of_range_session_id_hit(self) -> None:
        """``make()`` refuses an out-of-range ``SESSION-ID-HIT`` itself, called
        directly so ``read()``'s own check never runs."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SSLv2(msg_type=HandshakeType.CLIENT_FINISHED, body=b'')
        with self.assertRaisesRegex(ProtocolError, r'^SSLv2: invalid session_id_hit: 256$'):
            proto.make(msg_type=HandshakeType.SERVER_HELLO, body={'session_id_hit': 256})


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestSSLv2SegmentRecords(unittest.TestCase):
    """A whole record after the first in a TCP segment is a further SSLv2 layer (#2567)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_record_is_an_sslv2_layer(self) -> None:
        """Each record's header form and RECORD-LENGTH, per the draft's §4.1."""
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.misc.null import NoPayload

        for name, wire in SEGMENTS.items():
            with self.subTest(segment=name):
                records = _split_records(wire)
                parsed = SSLv2(wire, len(wire))
                layers, rest = _layers(parsed)
                self.assertEqual(str(parsed.protochain), ':'.join(['SSLv2'] * len(records)))
                self.assertIsInstance(rest, NoPayload)
                for layer, (header_len, record) in zip(layers, records):
                    self.assertEqual(layer.length, header_len)
                    self.assertEqual(layer.info.two_byte_header, header_len == 2)
                    self.assertEqual(layer.info.record_length, len(record) - header_len)
                    self.assertEqual(int(layer.info.msg_type), record[header_len])

    def test_records_match_the_draft(self) -> None:
        """Each record's own message type and body, decoded as a direct parse would."""
        from pcapkit.const.sslv2.handshake_type import HandshakeType
        from pcapkit.protocols.application.sslv2 import SSLv2

        wire = SEGMENTS['SERVER-HELLO + SERVER-VERIFY (3-octet header) + SERVER-FINISHED']
        layers, _ = _layers(SSLv2(wire, len(wire)))
        self.assertEqual([layer.info.msg_type for layer in layers],
                         [HandshakeType.SERVER_HELLO, HandshakeType.SERVER_VERIFY,
                          HandshakeType.SERVER_FINISHED])
        self.assertEqual(layers[0].info.body.connection_id, b'\xbb' * 16)
        self.assertEqual((layers[1].info.padding, layers[1].info.is_escape), (7, False))
        self.assertEqual([layer.info.body for layer in layers[1:]],
                         [bytes(range(16)), bytes(range(16, 32))])

        wire = SEGMENTS['CLIENT-HELLO + CLIENT-MASTER-KEY']
        layers, _ = _layers(SSLv2(wire, len(wire)))
        self.assertEqual(layers[0].info.body.cipher_specs, b'\x01\x00\x80')
        self.assertEqual(layers[1].info.msg_type, HandshakeType.CLIENT_MASTER_KEY)
        self.assertEqual(layers[1].info.body, CLIENT_MASTER_KEY[3:])

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        """Parsed directly and behind TLS's SSLv2 fallback on TCP 443."""
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.transport.tcp import TCP

        for name, wire in SEGMENTS.items():
            with self.subTest(segment=name):
                parsed = SSLv2(wire, len(wire))
                rebuilt = SSLv2.from_data(parsed.info)
                self.assertEqual(bytes(rebuilt).hex(), wire.hex())
                self.assertEqual(len(_layers(rebuilt)[0]), len(_split_records(wire)))

                segment = TCP_TO_443 + wire
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    tcp = TCP(segment, len(segment))
                    rebuilt_tcp = TCP.from_data(tcp.info)
                self.assertEqual(str(tcp.protochain), f'TCP:{parsed.protochain}')
                self.assertEqual(bytes(rebuilt_tcp).hex(), segment.hex())
                self.assertEqual(str(rebuilt_tcp.protochain), str(tcp.protochain))

    def test_make_then_parse_is_byte_exact(self) -> None:
        """Each record made from its parsed fields, carrying the next as ``payload``."""
        from pcapkit.protocols.application.sslv2 import SSLv2

        for name, wire in SEGMENTS.items():
            with self.subTest(segment=name):
                parsed = SSLv2(wire, len(wire))
                layers, _ = _layers(parsed)
                maker = object.__new__(SSLv2)
                schema = b''  # type: Any
                for layer in reversed(layers):
                    info = layer.info
                    schema = maker.make(msg_type=info.msg_type, two_byte_header=info.two_byte_header,
                                        is_escape=info.is_escape, padding=info.padding,
                                        body=info.body, payload=schema)
                made = bytes(schema)
                self.assertEqual(made.hex(), wire.hex())
                self.assertEqual(str(SSLv2(made, len(made)).protochain), str(parsed.protochain))

    def test_a_record_that_fails_to_decode_is_raw_with_the_rest(self) -> None:
        """A RECORD-LENGTH of 0 ends the chain as ``Raw`` carrying ``read()``'s error."""
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.misc.raw import Raw

        for name, segment, chain in (
                ('second record', CLIENT_HELLO + ZERO_LENGTH + CLIENT_MASTER_KEY, 'SSLv2:Raw'),
                ('third record', CLIENT_HELLO + CLIENT_MASTER_KEY + ZERO_LENGTH + CLIENT_MASTER_KEY,
                 'SSLv2:SSLv2:Raw')):
            with self.subTest(record=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    parsed = SSLv2(segment, len(segment))
                    rebuilt = bytes(SSLv2.from_data(parsed.info))
                _, rest = _layers(parsed)
                self.assertEqual(str(parsed.protochain), chain)
                self.assertIs(type(rest), Raw)
                self.assertEqual(rest.info.error,
                                 'SSLv2: record length (0) is too short to include a MSG-TYPE octet')
                self.assertEqual(bytes(rest), ZERO_LENGTH + CLIENT_MASTER_KEY)
                self.assertEqual(caught, [])
                self.assertEqual(rebuilt, segment)

    def test_octets_opening_no_record_stay_raw_without_an_error(self) -> None:
        from pcapkit.protocols.application.sslv2 import SSLv2
        from pcapkit.protocols.misc.raw import Raw

        for name, tail in (('a 2-octet header cut short', b'\x80'),
                           ('a 3-octet header cut short', b'\x00\x05'),
                           ('a record the segment ends inside', CLIENT_MASTER_KEY[:-1])):
            with self.subTest(tail=name):
                wire = CLIENT_HELLO + CLIENT_MASTER_KEY + tail
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    parsed = SSLv2(wire, len(wire))
                _, rest = _layers(parsed)
                self.assertEqual(str(parsed.protochain), 'SSLv2:SSLv2:Raw')
                self.assertIs(type(rest), Raw)
                self.assertIsNone(rest.info.error)
                self.assertEqual(bytes(rest), tail)
                self.assertEqual(caught, [])
                self.assertEqual(bytes(SSLv2.from_data(parsed.info)), wire)

    def test_a_parse_stopping_at_sslv2_keeps_the_rest_raw(self) -> None:
        from pcapkit.protocols.application.sslv2 import SSLv2

        wire = SEGMENTS['CLIENT-HELLO + CLIENT-MASTER-KEY']
        self.assertEqual(str(SSLv2(wire, len(wire)).protochain), 'SSLv2:SSLv2')
        for stop in ({'protocol': 'SSLv2'}, {'protocol': 'SSL'}, {'layer': 'Application'}):
            with self.subTest(stop=stop):
                parsed = SSLv2(wire, len(wire), **stop)
                self.assertEqual(str(parsed.protochain), 'SSLv2:Raw')
                self.assertEqual(bytes(parsed.payload), CLIENT_MASTER_KEY)

    def test_a_tcp_443_parse_stopping_at_sslv2_keeps_the_rest_raw(self) -> None:
        """Behind TLS's SSLv2 fallback too, whether TLS or the SSLv2 trial matches the stop."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        wire = SEGMENTS['CLIENT-HELLO + CLIENT-MASTER-KEY']
        self.assertEqual(str(_behind_tcp_443(wire)[0].protochain), 'TCP:SSLv2:SSLv2')
        for stop in ({'layer': 'Application'}, {'protocol': 'SSLv2'}, {'protocol': 'TLS'}, {'protocol': 'SSL'}):
            with self.subTest(stop=stop):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    tcp, rest = _behind_tcp_443(wire, **stop)
                    rebuilt = bytes(TCP.from_data(tcp.info))
                self.assertEqual(str(tcp.protochain), 'TCP:SSLv2:Raw')
                self.assertIs(type(rest), Raw)
                self.assertIsNone(rest.info.error)
                self.assertEqual(bytes(rest), CLIENT_MASTER_KEY)
                self.assertEqual(caught, [])
                self.assertEqual(rebuilt, TCP_TO_443 + wire)

    def test_a_tcp_443_record_that_fails_to_decode_is_raw_with_the_rest(self) -> None:
        """Behind TLS's SSLv2 fallback, as in a direct parse."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        for name, wire, chain in (
                ('second record', CLIENT_HELLO + ZERO_LENGTH + CLIENT_MASTER_KEY, 'TCP:SSLv2:Raw'),
                ('third record', CLIENT_HELLO + CLIENT_MASTER_KEY + ZERO_LENGTH + CLIENT_MASTER_KEY,
                 'TCP:SSLv2:SSLv2:Raw')):
            with self.subTest(record=name):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    tcp, rest = _behind_tcp_443(wire)
                    rebuilt = bytes(TCP.from_data(tcp.info))
                self.assertEqual(str(tcp.protochain), chain)
                self.assertIs(type(rest), Raw)
                self.assertEqual(rest.info.error,
                                 'SSLv2: record length (0) is too short to include a MSG-TYPE octet')
                self.assertEqual(bytes(rest), ZERO_LENGTH + CLIENT_MASTER_KEY)
                self.assertEqual(caught, [])
                self.assertEqual(rebuilt, TCP_TO_443 + wire)

    def test_a_tcp_443_record_cut_short_stays_raw_without_an_error(self) -> None:
        """Behind TLS's SSLv2 fallback, as in a direct parse."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.tcp import TCP

        for name, tail in (('a 2-octet header cut short', b'\x80'),
                           ('a 3-octet header cut short', b'\x00\x05'),
                           ('a record the segment ends inside', CLIENT_MASTER_KEY[:-1])):
            with self.subTest(tail=name):
                wire = CLIENT_HELLO + CLIENT_MASTER_KEY + tail
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    tcp, rest = _behind_tcp_443(wire)
                    rebuilt = bytes(TCP.from_data(tcp.info))
                self.assertEqual(str(tcp.protochain), 'TCP:SSLv2:SSLv2:Raw')
                self.assertIs(type(rest), Raw)
                self.assertIsNone(rest.info.error)
                self.assertEqual(bytes(rest), tail)
                self.assertEqual(caught, [])
                self.assertEqual(rebuilt, TCP_TO_443 + wire)

    def test_a_tcp_443_parse_hands_the_caller_context_to_every_record(self) -> None:
        """Each record after the first behind TLS's SSLv2 fallback carries the caller's registry."""
        from pcapkit.corekit.context import ContextRegistry, ProtocolContext

        class SSLv2Context(ProtocolContext):
            @classmethod
            def protocol(cls) -> 'tuple[str, ...]':
                return ('SSLv2',)

        context = SSLv2Context()
        registry = ContextRegistry(context)
        for name, wire in SEGMENTS.items():
            with self.subTest(segment=name):
                tcp, _ = _behind_tcp_443(wire, __context__=registry)
                layers, _ = _layers(tcp.payload.payload)
                self.assertEqual(len(layers), len(_split_records(wire)) - 1)
                for layer in layers:
                    self.assertEqual(dict(layer.context), dict(registry))
                    self.assertIs(layer._get_context(SSLv2Context), context)  # pylint: disable=protected-access

    def test_frame_layer_limit_bounds_the_records(self) -> None:
        """Each record is a layer, so the limit stops the walk with one warning."""
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities import config
        from pcapkit.utilities.warnings import ProtocolWarning

        raw = TCP_TO_443 + CLIENT_HELLO + CLIENT_MASTER_KEY * (config.FRAME_LAYER_LIMIT + 6)
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            proto = TCP(raw, len(raw))
        self.assertEqual(str(proto.protochain),
                         ':'.join(['TCP'] + ['SSLv2'] * config.FRAME_LAYER_LIMIT + ['Raw']))
        self.assertEqual([item.category for item in caught], [ProtocolWarning])
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            self.assertEqual(bytes(TCP.from_data(proto.info)), raw)


if __name__ == '__main__':
    unittest.main()
