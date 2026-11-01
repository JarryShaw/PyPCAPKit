# -*- coding: utf-8 -*-
"""Unit tests for :mod:`pcapkit.protocols.application.ssl`,
:mod:`pcapkit.protocols.application.tls` and
:mod:`pcapkit.protocols.application.dtls`.

"""
from __future__ import annotations

import unittest
import warnings

from tests._support import reimport_once_per_class

#: A 20-octet TCP header, data offset 5, ACK set, from port 50000 to port 443,
#: i.e. the port :attr:`TCP.__proto__ <pcapkit.protocols.transport.tcp.TCP.__proto__>`
#: binds TLS at. Shaped exactly as
#: :mod:`tests.protocols.transport.test_tcp_http_dispatch_unit`'s port-80 header.
_TCP_TO_443 = bytes.fromhex('c35001bb00000001000000015010ffff00000000')


def _udp_to_5684(payload: bytes) -> bytes:
    """An 8-octet UDP header to port 5684 -- where DTLS is bound -- plus
    ``payload``. The checksum is left zero, which UDP permits over IPv4 and
    which nothing here is testing.

    """
    return ((50000).to_bytes(2, 'big') + (5684).to_bytes(2, 'big')
            + (8 + len(payload)).to_bytes(2, 'big') + b'\x00\x00' + payload)


class SSLFamilyUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_ssl_id_names_both_concrete_protocols(self) -> None:
        from pcapkit.protocols.application.ssl import SSL

        self.assertEqual(SSL.id(), ('TLS', 'DTLS'))

    def test_tls_properties_and_make_data(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import TLS as Data_TLS

        proto = object.__new__(TLS)
        self.assertEqual(proto.name, 'Transport Layer Security')
        self.assertEqual(proto.length, 5)
        self.assertEqual(proto.__length_hint__(), 5)

        data = Data_TLS(content_type=ContentType.application_data, version=0x0303,
                        length=5, content=b'hello')
        values = TLS._make_data(data)
        self.assertEqual(values['content_type'], ContentType.application_data)
        self.assertEqual(values['version'], 0x0303)
        self.assertEqual(values['content'], b'hello')
        self.assertIn('payload', values)

    def test_dtls_properties_and_make_data(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.dtls import DTLS as Data_DTLS

        proto = object.__new__(DTLS)
        self.assertEqual(proto.name, 'Datagram Transport Layer Security')
        self.assertEqual(proto.length, 13)
        self.assertEqual(proto.__length_hint__(), 13)

        data = Data_DTLS(content_type=ContentType.change_cipher_spec, version=0xFEFD,
                         epoch=1, sequence_number=42, length=1, content=b'\x01')
        values = DTLS._make_data(data)
        self.assertEqual(values['epoch'], 1)
        self.assertEqual(values['sequence_number'], 42)
        self.assertEqual(values['content_type'], ContentType.change_cipher_spec)

    def test_tcp_and_udp_dispatch_tables_name_tls_and_dtls(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        self.assertEqual(TCP.__proto__[443].klass.__name__, 'TLS')
        self.assertEqual(UDP.__proto__[5684].klass.__name__, 'DTLS')
        # 8443 stays unbound -- IANA names it ``pcsync-https``, not an HTTP
        # alternate or a TLS one.
        self.assertEqual(TCP.__proto__[8443].klass.__name__, 'Raw')

    def test_change_cipher_spec_wrong_length_keeps_its_octets(self) -> None:
        """A ``change_cipher_spec`` that is not exactly 1 octet is not a bug.

        A cleartext CCS is always 1 octet, but a CCS sent mid-renegotiation
        (after keys exist) is ciphertext under the same content type, and
        ciphertext is never exactly 1 octet, given MAC/tag overhead. As for
        content types 21 and 22, the fragment is kept opaque rather than
        raising, so the record (and its cleartext header) survives instead
        of degrading to :class:`Raw`.

        """
        from pcapkit.protocols.application.tls import TLS

        wire = b'\x14\x03\x03\x00\x02\x01\x01'
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.info.content, b'\x01\x01')
        self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)

    def test_dtls_truncated_fragment_header_raises(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        # A handshake header claiming a body, but too few octets follow for
        # even the 8-octet DTLS fragment header.
        fragment = b'\x01\x00\x00\x05\x00\x00'
        wire = (b'\x16\xfe\xfd\x00\x00\x00\x00\x00\x00\x00\x01'
               + len(fragment).to_bytes(2, 'big') + fragment)
        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))

    def test_malformed_extension_list_raises(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        version = b'\x03\x03'
        random = bytes(32)
        session_id = b'\x00'
        cipher_suites = b'\x00\x02\x13\x01'
        compression = b'\x01\x00'
        # Extensions length says 4 octets follow, but the extension header
        # alone claims a body longer than that.
        bad_extensions = b'\x00\x04' + b'\x00\x0d\x00\xff'
        body = version + random + session_id + cipher_suites + compression + bad_extensions
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))

    def test_client_hello_with_an_odd_cipher_suites_length_raises(self) -> None:
        """An odd ``cipher_suites`` length byte count has no RFC-compliant decoding.

        Without this check the trailing, incomplete pair decoded as one lone
        octet rather than failing, and rebuilding padded it back out to 2
        octets -- a round-trip that silently lost byte-exactness instead of
        refusing to parse.

        """
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        version = b'\x03\x03'
        random = bytes(32)
        session_id = b'\x00'
        # 3 octets of cipher suites -- not a multiple of 2.
        cipher_suites = b'\x00\x03\x13\x01\x00'
        compression = b'\x01\x00'
        body = version + random + session_id + cipher_suites + compression
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))

    def test_client_hello_with_excess_octets_raises(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        version = b'\x03\x03'
        random = bytes(32)
        body = version + random + b'\x00' + b'\x00\x02\x13\x01' + b'\x01\x00' + b'\x00\x00' + b'\xff'
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))

    def test_server_hello_with_excess_octets_raises(self) -> None:
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        version = b'\x03\x03'
        random = bytes(32)
        body = version + random + b'\x00' + b'\x13\x01' + b'\x00' + b'\x00\x00' + b'\xff'
        handshake = b'\x02' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))

    def test_make_accepts_an_already_encoded_handshake_message(self) -> None:
        """A list of handshake messages may mix decoded and raw entries."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        raw_message = b'\x0e\x00\x00\x00'  # server_hello_done, zero-length
        maker = object.__new__(TLS)
        schema = maker.make(content_type=ContentType.handshake, content=(raw_message,))
        self.assertEqual(bytes(schema)[5:], raw_message)

    def test_make_content_accepts_a_bytearray_for_an_unknown_content_type(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        maker = object.__new__(TLS)
        schema = maker.make(content_type=ContentType.heartbeat, content=bytearray(b'\x01\x02'))
        self.assertEqual(bytes(schema)[5:], b'\x01\x02')


class RecordValidationTests(unittest.TestCase):
    """Every branch of ``SSL._validate_tls_record``, and what dispatch does with it.

    The content-type check is an allowlist of the assigned 20-27, not a test
    of whether :class:`~pcapkit.const.tls.content_type.ContentType` *names*
    the value: 0 resolves to an ``Unassigned`` member via ``_missing_`` --
    the registry never assigns it, and :rfc:`9846#section-5.1` rejects a
    record carrying it outright -- so a name-based check would accept
    ``00 03 03 00 04 deadbeef`` on TCP:443 and decode its fragment.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_content_type_zero_is_rejected(self) -> None:
        """The exploit, verbatim, for both protocols."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        tls_wire = b'\x00\x03\x03\x00\x04\xde\xad\xbe\xef'
        with self.assertRaises(ProtocolError):
            TLS(tls_wire, len(tls_wire))

        dtls_wire = (b'\x00\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                     + (4).to_bytes(2, 'big') + b'\xde\xad\xbe\xef')
        with self.assertRaises(ProtocolError):
            DTLS(dtls_wire, len(dtls_wire))

    def test_content_types_outside_the_assigned_range_are_rejected(self) -> None:
        """One from each band IANA does not assign a content type in.

        19 is the top of the Unassigned 0-19 band, 28 the bottom of 28-31, 32
        and 63 the ends of the 32-63 band :rfc:`9147` reserves, and 64 and 255
        the ends of 64-255. 27, :rfc:`9853`'s
        ``return_routability_check``, is on the other side of the boundary and
        must *not* be rejected, so it is asserted here rather than left to the
        round-trip module, where a regression would read as an unrelated
        failure.

        """
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        for content_type in (19, 28, 32, 63, 64, 255):
            with self.subTest(content_type=content_type):
                wire = bytes([content_type]) + b'\x03\x03\x00\x04\xde\xad\xbe\xef'
                with self.assertRaises(ProtocolError):
                    TLS(wire, len(wire))

        wire = b'\x1b\x03\x03\x00\x04\xde\xad\xbe\xef'
        parsed = TLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.return_routability_check)
        self.assertEqual(parsed.info.content, b'\xde\xad\xbe\xef')

    def test_tls12_cid_is_excluded(self) -> None:
        """Content type 25 (RFC 9146 Connection ID) is assigned by IANA, but
        is deliberately left out of the wire allowlist.

        Its record format puts the connection ID *before* ``length``, at an
        offset only the out-of-band negotiated CID length can resolve --
        something this dissector's stateless, per-packet schema read has no
        way to track. Reading ``length`` at the fixed offset every other
        type uses instead fabricates a fragment from the CID's own tail, so
        25 is excluded here and degrades to Raw, same as an unassigned type,
        rather than being decoded wrong. Guards a coverage gap the full suite
        would otherwise pass with 25 silently dropped from the allowlist.

        """
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        wire = b'\x19\x03\x03\x00\x08' + b'\xde\xad\xbe\xef\xde\xad\xbe\xef'
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))

        raw = _TCP_TO_443 + wire
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = TCP(raw, len(raw))
        self.assertEqual(str(proto.protochain), 'TCP:Raw')

    def test_ack_content_type_is_accepted(self) -> None:
        """Content type 26 (``ack``) stays in the wire allowlist.

        Guards the other half of the coverage gap above: a regression that
        dropped 26 instead of (or alongside) 25 would otherwise pass the
        full suite undetected, since nothing else exercises it directly.

        """
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        wire = b'\x1a\x03\x03\x00\x04\xde\xad\xbe\xef'
        parsed = TLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.ack)
        self.assertEqual(parsed.info.content, b'\xde\xad\xbe\xef')

    def test_a_legacy_record_version_outside_the_protocol_range_is_rejected(self) -> None:
        """TLS records are ``0x03xx`` and DTLS records ``0xFExx``, never each
        other's. Each protocol is handed the other's version as well as a
        value neither uses, so neither half can pass by accepting everything.

        """
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        for version in (b'\x02\x03', b'\xfe\xfd'):
            with self.subTest(protocol='TLS', version=version.hex()):
                wire = b'\x17' + version + b'\x00\x05hello'
                with self.assertRaises(ProtocolError):
                    TLS(wire, len(wire))

        for version in (b'\x02\x03', b'\x03\x03'):
            with self.subTest(protocol='DTLS', version=version.hex()):
                wire = (b'\x17' + version + bytes(2) + (1).to_bytes(6, 'big')
                        + (5).to_bytes(2, 'big') + b'hello')
                with self.assertRaises(ProtocolError):
                    DTLS(wire, len(wire))

    def test_a_declared_length_past_the_end_of_the_buffer_is_rejected(self) -> None:
        """A record header is not made genuine by claiming more than arrived.

        ``FieldBase.unpack``'s truncated-capture tolerance zero-pads a short
        read out to the declared length, so without this check the five octets
        of ``hello`` would decode as a 65535-octet record whose remaining
        content was fabricated here rather than received.

        """
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        with warnings.catch_warnings():
            # The over-declared length makes the schema's own residual-length
            # arithmetic go negative, which it is entitled to warn about; the
            # refusal is what is under test.
            warnings.simplefilter('ignore')

            tls_wire = b'\x17\x03\x03\xff\xffhello'
            with self.assertRaises(ProtocolError):
                TLS(tls_wire, len(tls_wire))

            # One octet over, rather than wildly over: the check is ``>``, so
            # an off-by-one in it would survive the extreme case above.
            tls_wire = b'\x17\x03\x03\x00\x06hello'
            with self.assertRaises(ProtocolError):
                TLS(tls_wire, len(tls_wire))

            dtls_wire = (b'\x17\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                         + (0xFFFF).to_bytes(2, 'big') + b'hello')
            with self.assertRaises(ProtocolError):
                DTLS(dtls_wire, len(dtls_wire))

    def test_a_rejected_record_degrades_to_raw_rather_than_propagating(self) -> None:
        """What the refusals above are *for*, measured end to end.

        ``_validate_tls_record`` raises so that
        :func:`~pcapkit.corekit.decorators.beholder` replaces the layer with
        :class:`~pcapkit.protocols.misc.raw.Raw`; asserting the exception alone
        would not show that dispatch survives it. The good payload is asserted
        alongside, so the test cannot be satisfied by a binding that resolves
        to ``Raw`` unconditionally.

        """
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        tls_good = b'\x16\x03\x03\x00\x04\x0e\x00\x00\x00'
        tls_cases = (
            # The identified tier's own alias, not the dispatcher's generic
            # name -- same convention as ``HTTP``'s own dispatch (see
            # ``tests.protocols.transport.test_tcp_http_dispatch_unit``).
            ('a genuine record', tls_good, 'TCP:TLS 1.2'),
            ('content type 0', b'\x00\x03\x03\x00\x04\xde\xad\xbe\xef', 'TCP:Raw'),
            ('a DTLS legacy version', b'\x17\xfe\xfd\x00\x05hello', 'TCP:Raw'),
            ('a length past the buffer', b'\x17\x03\x03\xff\xffhello', 'TCP:Raw'),
        )
        for name, payload, expected in tls_cases:
            with self.subTest(transport='TCP:443', payload=name):
                raw = _TCP_TO_443 + payload
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    proto = TCP(raw, len(raw))
                self.assertEqual(str(proto.protochain), expected)

        dtls_header = b'\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
        dtls_cases = (
            ('a genuine record',
             b'\x16' + dtls_header + (12).to_bytes(2, 'big') + b'\x0e\x00\x00\x00' + bytes(8),
             'UDP:DTLS 1.2'),
            ('content type 0',
             b'\x00' + dtls_header + (4).to_bytes(2, 'big') + b'\xde\xad\xbe\xef',
             'UDP:Raw'),
        )
        for name, payload, expected in dtls_cases:
            with self.subTest(transport='UDP:5684', payload=name):
                raw = _udp_to_5684(payload)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    proto = UDP(raw, len(raw))
                self.assertEqual(str(proto.protochain), expected)


class EncryptedHandshakeRecordTests(unittest.TestCase):
    """A ``handshake`` record is not always a *cleartext* handshake.

    Once keys are derived, a ``Finished`` and every post-handshake message
    travel as ciphertext under content type 22 -- the same type the cleartext
    flights used, with nothing in the cleartext header to say which it is.
    Decoding the second kind as the first either fabricates messages from
    pseudorandom octets or, as it did here, raises and drops the whole record
    to :class:`~pcapkit.protocols.misc.raw.Raw`, discarding a record header
    that *was* in the clear.

    DTLS answers this exactly, from the epoch in its record header; TLS has no
    such field, so self-consistency stands in -- whether the 4-octet message
    headers tile the fragment exactly.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_encrypted_tls_handshake_record_keeps_its_octets(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        # 40 octets, the size of a TLS 1.2 encrypted ``Finished``. Its first
        # octet would read as a ``msg_type`` and the next three as a length,
        # neither of which tiles the fragment.
        ciphertext = (b'\x9f\x2b\x71\xc4' * 10)[:40]
        wire = b'\x16\x03\x03' + len(ciphertext).to_bytes(2, 'big') + ciphertext

        parsed = TLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.handshake)
        self.assertEqual(parsed.info.content, ciphertext)
        self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)

    def test_a_fragment_that_nearly_tiles_keeps_its_octets(self) -> None:
        """The two ways the walk can fail, which a single ciphertext sample
        would not separate: running out of room for the next header, and a
        declared length that overshoots the end.

        """
        from pcapkit.protocols.application.tls import TLS

        # Two octets left over after one whole message: too few for a header.
        short_tail = b'\x0e\x00\x00\x00' + b'\xab\xcd'
        # One message declaring one octet more than the fragment holds.
        overshoot = b'\x0e\x00\x00\x05' + b'\xab\xcd\xef\x01'

        for name, fragment in (('too short for a header', short_tail),
                               ('declared length overshoots', overshoot)):
            with self.subTest(fragment=name):
                wire = b'\x16\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment
                parsed = TLS(wire, len(wire))
                self.assertEqual(parsed.info.content, fragment)
                self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)

    def test_a_dtls_handshake_record_past_epoch_zero_keeps_its_octets(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS

        # 48 octets, the size of a DTLS encrypted ``Finished``.
        ciphertext = (b'\xa3\x5d\x12\xee' * 12)[:48]
        wire = (b'\x16\xfe\xfd' + (1).to_bytes(2, 'big') + (7).to_bytes(6, 'big')
                + len(ciphertext).to_bytes(2, 'big') + ciphertext)

        parsed = DTLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.handshake)
        self.assertEqual(parsed.info.epoch, 1)
        self.assertEqual(parsed.info.content, ciphertext)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_a_dtls_handshake_record_at_epoch_zero_still_decodes(self) -> None:
        """The complement, so the epoch test cannot pass by refusing everything.

        An epoch-0 record whose fragment is byte-for-byte what the epoch-1 case
        above keeps opaque would be ciphertext in reality, but epoch 0 is by
        definition the cleartext handshake, so the decision is the epoch's to
        make and this asserts it is actually consulted.

        """
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.dtls import DTLSHandshake

        fragment = b'\x0e\x00\x00\x00' + bytes(8)  # server_hello_done, unfragmented
        wire = (b'\x16\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                + len(fragment).to_bytes(2, 'big') + fragment)

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.info.epoch, 0)
        self.assertIsInstance(parsed.info.content[0], DTLSHandshake)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)


class EncryptedAlertRecordTests(unittest.TestCase):
    """The same bug class as ``EncryptedHandshakeRecordTests`` above, for
    content type 21 (``alert``).

    An encrypted alert is not an edge case: it is any TLS 1.2 alert sent
    after ``ChangeCipherSpec``, including the ``close_notify`` that ends
    nearly every TLS 1.2 connection. Before this fix, any alert fragment
    that was not exactly 2 octets raised and dropped the whole record --
    cleartext header included -- to :class:`~pcapkit.protocols.misc.raw.Raw`.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_an_encrypted_tls12_close_notify_keeps_its_octets(self) -> None:
        """A 26-octet AES-GCM-shaped ``close_notify``, the common case."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.tls import TLS

        ciphertext = (b'\xaa\xbb\xcc\xdd' * 7)[:26]
        wire = b'\x15\x03\x03' + len(ciphertext).to_bytes(2, 'big') + ciphertext

        parsed = TLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.alert)
        self.assertEqual(parsed.info.content, ciphertext)
        self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)

    def test_an_encrypted_cbc_alert_keeps_its_octets(self) -> None:
        """A 48-octet CBC-shaped alert -- a different cipher, same shape bug."""
        from pcapkit.protocols.application.tls import TLS

        ciphertext = (b'\x9a\x1b\x2c\x3d' * 12)[:48]
        wire = b'\x15\x03\x03' + len(ciphertext).to_bytes(2, 'big') + ciphertext

        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.info.content, ciphertext)
        self.assertEqual(bytes(TLS.from_data(parsed.info)), wire)

    def test_a_dtls_alert_past_epoch_zero_keeps_its_octets(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS

        ciphertext = (b'\x11\x22\x33\x44' * 2)[:7]
        wire = (b'\x15\xfe\xfd' + (1).to_bytes(2, 'big') + (9).to_bytes(6, 'big')
                + len(ciphertext).to_bytes(2, 'big') + ciphertext)

        parsed = DTLS(wire, len(wire))
        self.assertIs(parsed.info.content_type, ContentType.alert)
        self.assertEqual(parsed.info.epoch, 1)
        self.assertEqual(parsed.info.content, ciphertext)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_a_dtls_alert_at_epoch_zero_still_decodes(self) -> None:
        """The complement, so the epoch test cannot pass by refusing everything."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.tls import Alert

        fragment = b'\x01\x00'  # level=warning, description=close_notify
        wire = (b'\x15\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                + len(fragment).to_bytes(2, 'big') + fragment)

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.info.epoch, 0)
        self.assertIsInstance(parsed.info.content, Alert)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_a_dtls_alert_at_epoch_zero_with_the_wrong_length_raises(self) -> None:
        """Epoch 0 means cleartext, not "any length is fine".

        Unlike TLS -- where a non-2-octet fragment is read as ciphertext by
        construction -- DTLS already knows from the epoch that this fragment
        is supposed to be a genuine cleartext alert, so a wrong length here
        is a malformed record, not a disguised ciphertext one, and still
        has to raise.

        """
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        fragment = b'\x01\x00\xff'  # one octet too many for a cleartext alert
        wire = (b'\x15\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                + len(fragment).to_bytes(2, 'big') + fragment)
        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))

    def test_a_dtls_change_cipher_spec_at_epoch_zero_with_the_wrong_length_raises(self) -> None:
        """The same malformed-length case, for ``change_cipher_spec``."""
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        fragment = b'\x01\x02'  # a genuine cleartext CCS is exactly 1 octet
        wire = (b'\x14\xfe\xfd' + bytes(2) + (1).to_bytes(6, 'big')
                + len(fragment).to_bytes(2, 'big') + fragment)
        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))


def _tls_client_hello_wire(*, supported_versions: 'bytes | None' = None,
                           record_version: bytes = b'\x03\x03') -> bytes:
    """A minimal, well-formed TLS ``ClientHello`` record.

    Args:
        supported_versions: When given, the raw ``supported_versions``
            extension body (length-prefixed version list) to append as an
            extension; otherwise the message carries no extensions at all.
        record_version: The record header's legacy version octets.

    """
    version = b'\x03\x03'
    random = bytes(32)
    session_id = b'\x00'
    cipher_suites = b'\x00\x02\x13\x01'
    compression = b'\x01\x00'
    body = version + random + session_id + cipher_suites + compression
    if supported_versions is not None:
        extension = (43).to_bytes(2, 'big') + len(supported_versions).to_bytes(2, 'big') + supported_versions
        body += len(extension).to_bytes(2, 'big') + extension
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body  # msg_type=1, client_hello
    return b'\x16' + record_version + len(handshake).to_bytes(2, 'big') + handshake


def _dtls_client_hello_wire(*, supported_versions: 'bytes | None' = None,
                            record_version: bytes = b'\xfe\xfd') -> bytes:
    """A minimal, well-formed DTLS ``ClientHello`` record, unfragmented."""
    version = b'\xfe\xfd'
    random = bytes(32)
    session_id = b'\x00'
    cookie = b'\x00'
    cipher_suites = b'\x00\x02\x13\x01'
    compression = b'\x01\x00'
    body = version + random + session_id + cookie + cipher_suites + compression
    if supported_versions is not None:
        extension = (43).to_bytes(2, 'big') + len(supported_versions).to_bytes(2, 'big') + supported_versions
        body += len(extension).to_bytes(2, 'big') + extension
    frag_header = (0).to_bytes(2, 'big') + (0).to_bytes(3, 'big') + len(body).to_bytes(3, 'big')
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + frag_header + body
    record_header = b'\x16' + record_version + bytes(2) + (1).to_bytes(6, 'big')
    return record_header + len(handshake).to_bytes(2, 'big') + handshake


class VersionDispatchTests(unittest.TestCase):
    """:meth:`TLS.read`/:meth:`DTLS.read` (:issue:`2437`): identifying the
    concrete tier and setting
    :attr:`~pcapkit.protocols.application.tls.TLS.alias` dynamically,
    mirroring :class:`~pcapkit.protocols.link.arp.ARP`'s own dynamic dispatch
    over RARP/DRARP/InARP by operation code, rather than
    :class:`~pcapkit.protocols.application.http.HTTP`'s dispatch over
    distinct per-version classes: a record identified as, say, SSLv3 never
    becomes a different *class*, only a different :attr:`alias`, on the same
    :class:`~pcapkit.protocols.application.tls.TLS` instance throughout.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_tls_dispatches_sslv3_tlsv1_0_and_tlsv1_1_by_legacy_version(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        cases = (
            (0x0300, 'SSLv3'),
            (0x0301, 'TLS 1.0'),
            (0x0302, 'TLS 1.1'),
        )
        for legacy_version, alias in cases:
            with self.subTest(legacy_version=hex(legacy_version)):
                wire = bytes([0x17]) + legacy_version.to_bytes(2, 'big') + b'\x00\x05hello'
                parsed = TLS(wire, len(wire))
                self.assertEqual(parsed.alias, alias)
                self.assertEqual(parsed.info.content, b'hello')

    def test_tls_0303_without_1_3_negotiation_dispatches_tls_1_2(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        wire = _tls_client_hello_wire()
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS 1.2')

    def test_tls_0303_negotiating_1_3_dispatches_tls_1_3(self) -> None:
        from pcapkit.protocols.application.tls import TLS

        supported_versions = b'\x02' + (0x0304).to_bytes(2, 'big')
        wire = _tls_client_hello_wire(supported_versions=supported_versions)
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS 1.3')

    def test_tls_supported_versions_naming_only_1_2_stays_tls_1_2(self) -> None:
        """The negotiation really is consulted, not just "an extension exists"."""
        from pcapkit.protocols.application.tls import TLS

        supported_versions = b'\x02' + (0x0303).to_bytes(2, 'big')
        wire = _tls_client_hello_wire(supported_versions=supported_versions)
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS 1.2')

    def test_dtls_dispatches_dtlsv1_0_by_legacy_version(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = (b'\x17\xfe\xff' + bytes(2) + (1).to_bytes(6, 'big')
                + (5).to_bytes(2, 'big') + b'hello')
        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.0')

    def test_dtls_0xfefd_without_1_3_negotiation_dispatches_dtls_1_2(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = _dtls_client_hello_wire()
        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.2')

    def test_dtls_0xfefd_negotiating_1_3_dispatches_dtls_1_3(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        supported_versions = b'\x02' + (0xFEFC).to_bytes(2, 'big')
        wire = _dtls_client_hello_wire(supported_versions=supported_versions)
        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')

    def test_tls_unknown_record_version_keeps_the_generic_alias(self) -> None:
        """A ``0x03xx`` legacy version naming no known tier claims none.

        TLS 1.3 never puts ``0x0304`` on the record layer
        (:rfc:`9846#section-5.1`), and nothing assigns a later value, so
        neither may be branded TLS 1.2 -- or any other specific version.

        """
        from pcapkit.protocols.application.tls import TLS

        for legacy_version in (0x0304, 0x0305, 0x03FF):
            with self.subTest(legacy_version=hex(legacy_version)):
                wire = bytes([0x17]) + legacy_version.to_bytes(2, 'big') + b'\x00\x05hello'
                parsed = TLS(wire, len(wire))
                self.assertEqual(parsed.alias, 'TLS')
                self.assertEqual(parsed.name, 'Transport Layer Security')
                self.assertEqual(parsed.info.content, b'hello')

    def test_tls_unknown_record_version_stays_generic_even_offering_1_3(self) -> None:
        """The ``supported_versions`` peek only applies where TLS 1.3 may
        legitimately sit on the record layer, not to an unknown version."""
        from pcapkit.protocols.application.tls import TLS

        supported_versions = b'\x02' + (0x0304).to_bytes(2, 'big')
        wire = _tls_client_hello_wire(supported_versions=supported_versions,
                                      record_version=b'\x03\x04')
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS')

    def test_tls_0301_client_hello_negotiating_1_3_dispatches_tls_1_3(self) -> None:
        """An initial ``ClientHello`` may carry ``0x0301`` on the record layer
        "for compatibility purposes" (:rfc:`9846#section-5.1`)."""
        from pcapkit.protocols.application.tls import TLS

        supported_versions = b'\x02' + (0x0304).to_bytes(2, 'big')
        wire = _tls_client_hello_wire(supported_versions=supported_versions,
                                      record_version=b'\x03\x01')
        parsed = TLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'TLS 1.3')

        plain = _tls_client_hello_wire(record_version=b'\x03\x01')
        self.assertEqual(TLS(plain, len(plain)).alias, 'TLS 1.0')

    def test_dtls_unknown_record_version_keeps_the_generic_alias(self) -> None:
        """A ``0xFExx`` legacy version naming no known tier claims none --
        DTLS 1.3's own ``0xFEFC`` included, which :rfc:`9147#section-4`
        never puts on the record layer."""
        from pcapkit.protocols.application.dtls import DTLS

        for legacy_version in (0xFEFC, 0xFEFE, 0xFE00):
            with self.subTest(legacy_version=hex(legacy_version)):
                wire = (bytes([0x17]) + legacy_version.to_bytes(2, 'big') + bytes(2)
                        + (1).to_bytes(6, 'big') + (5).to_bytes(2, 'big') + b'hello')
                parsed = DTLS(wire, len(wire))
                self.assertEqual(parsed.alias, 'DTLS')
                self.assertEqual(parsed.info.content, b'hello')

    def test_dtls_0xfeff_client_hello_negotiating_1_3_dispatches_dtls_1_3(self) -> None:
        """An initial ``ClientHello`` may carry DTLS 1.0's ``{254, 255}``
        on the record layer (:rfc:`9147#section-4`)."""
        from pcapkit.protocols.application.dtls import DTLS

        supported_versions = b'\x02' + (0xFEFC).to_bytes(2, 'big')
        wire = _dtls_client_hello_wire(supported_versions=supported_versions,
                                       record_version=b'\xfe\xff')
        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')

        plain = _dtls_client_hello_wire(record_version=b'\xfe\xff')
        self.assertEqual(DTLS(plain, len(plain)).alias, 'DTLS 1.0')

    def test_sslv3_is_constructible_directly_and_narrows_id(self) -> None:
        """:class:`SSLv3` -- explicit/manual construction only, mirroring
        :class:`~pcapkit.protocols.link.arp.InARP`'s relationship to
        :class:`~pcapkit.protocols.link.arp.ARP`: it narrows :meth:`id` only
        and inherits :meth:`~pcapkit.protocols.application.tls.TLS.read`
        unchanged, so parsing SSLv3-shaped data through it sets
        :attr:`alias` to ``'SSLv3'`` exactly as parsing it through
        :class:`~pcapkit.protocols.application.tls.TLS` would.

        """
        from pcapkit.protocols.application.tls import SSLv3

        tls_wire = b'\x17\x03\x00\x00\x05hello'
        parsed = SSLv3(tls_wire, len(tls_wire))
        self.assertEqual(parsed.alias, 'SSLv3')
        self.assertEqual(parsed.info.content, b'hello')
        self.assertEqual(SSLv3.id(), ('SSLv3',))

    def test_sslv3_class_does_not_force_its_own_alias(self) -> None:
        """The same nuance :class:`~pcapkit.protocols.link.arp.InARP` has:
        constructing :class:`SSLv3` directly over data that is not actually
        SSLv3-shaped still reports the *real* tier, since :meth:`read` is
        inherited unmodified and dispatches off the wire, not off the class
        it happened to be instantiated as.

        """
        from pcapkit.protocols.application.tls import SSLv3

        tls_1_0_wire = b'\x17\x03\x01\x00\x05hello'
        parsed = SSLv3(tls_1_0_wire, len(tls_1_0_wire))
        self.assertEqual(parsed.alias, 'TLS 1.0')

    def test_tls_and_dtls_id_are_fixed_regardless_of_dispatched_tier(self) -> None:
        """:meth:`TLS.id`/:meth:`DTLS.id` do not vary with the identified
        tier: a genuine TLS 1.2 record must not stop matching a lookup keyed
        on ``('TLS',)`` just because *some* instance of the class happened to
        parse as SSLv3.

        """
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.application.tls import TLS

        self.assertEqual(TLS.id(), ('TLS',))
        self.assertEqual(DTLS.id(), ('DTLS',))

        sslv3_wire = b'\x17\x03\x00\x00\x05hello'
        parsed = TLS(sslv3_wire, len(sslv3_wire))
        self.assertEqual(parsed.alias, 'SSLv3')
        self.assertEqual(TLS.id(), ('TLS',))

        dtls_1_0_wire = (b'\x17\xfe\xff' + bytes(2) + (1).to_bytes(6, 'big')
                         + (5).to_bytes(2, 'big') + b'hello')
        parsed_dtls = DTLS(dtls_1_0_wire, len(dtls_1_0_wire))
        self.assertEqual(parsed_dtls.alias, 'DTLS 1.0')
        self.assertEqual(DTLS.id(), ('DTLS',))

    def test_sslv3_record_reports_its_own_name(self) -> None:
        """SSLv3 is the one tier in the family with a genuinely different
        full :attr:`name`, set dynamically the same way :attr:`alias` is --
        mirroring :attr:`ARP._name <pcapkit.protocols.link.arp.ARP._name>`
        tracking :attr:`ARP._acnm <pcapkit.protocols.link.arp.ARP._acnm>`.

        """
        from pcapkit.protocols.application.tls import TLS

        sslv3_wire = b'\x17\x03\x00\x00\x05hello'
        parsed = TLS(sslv3_wire, len(sslv3_wire))
        self.assertEqual(parsed.name, 'Secure Sockets Layer version 3')

        tls_1_2_wire = _tls_client_hello_wire()
        parsed_12 = TLS(tls_1_2_wire, len(tls_1_2_wire))
        self.assertEqual(parsed_12.name, 'Transport Layer Security')

    def test_malformed_client_hello_raises_through_dispatch_same_as_before(self) -> None:
        """Dispatch's own sniff must not swallow a genuine parse failure.

        The sniff that decides SSLv3+ vs. TLS 1.3 decodes the same
        ``ClientHello`` the real parse goes on to decode; this pins that a
        malformed one still raises from the dispatcher's :meth:`read`, not
        just from a concrete tier constructed directly (already covered by
        ``RecordValidationTests`` et al. above).

        """
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        version = b'\x03\x03'
        random = bytes(32)
        session_id = b'\x00'
        cipher_suites = b'\x00\x03\x13\x01\x00'  # odd length -- malformed
        compression = b'\x01\x00'
        body = version + random + session_id + cipher_suites + compression
        handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(handshake).to_bytes(2, 'big') + handshake
        with self.assertRaises(ProtocolError):
            TLS(wire, len(wire))


class NonRecordPayloadTests(unittest.TestCase):
    """A port-443 payload that is not a TLS record degrades to
    :class:`~pcapkit.protocols.misc.raw.Raw`."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_first_octet_parses_only_as_an_accepted_content_type(self) -> None:
        from pcapkit.protocols.application.ssl import _WIRE_CONTENT_TYPES
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.utilities.exceptions import ProtocolError

        for content_type in range(0x100):
            with self.subTest(content_type=content_type):
                wire = bytes([content_type]) + b'\x03\x03\x00\x04\xde\xad\xbe\xef'
                if content_type in _WIRE_CONTENT_TYPES:
                    self.assertEqual(int(TLS(wire, len(wire)).info.content_type), content_type)
                else:
                    with self.assertRaises(ProtocolError):
                        TLS(wire, len(wire))

    def test_an_sslv2_client_hello_is_raw(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        body = b'\x01\x00\x02\x00\x03\x00\x00\x00\x10' + b'\x01\x00\x80' + bytes(16)
        raw = _TCP_TO_443 + (0x8000 | len(body)).to_bytes(2, 'big') + body
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = TCP(raw, len(raw))
        self.assertEqual(str(proto.protochain), 'TCP:Raw')

    def test_random_segments_are_raw(self) -> None:
        import random

        from pcapkit.protocols.transport.tcp import TCP

        rng = random.Random(2441)
        for _ in range(200):
            raw = _TCP_TO_443 + rng.getrandbits(1460 * 8).to_bytes(1460, 'big')
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                proto = TCP(raw, len(raw))
            self.assertEqual(str(proto.protochain), 'TCP:Raw', raw[20:25].hex())


class ExportTests(unittest.TestCase):
    """The family is exported, and registered, the way every sibling
    application protocol is -- :class:`~pcapkit.protocols.application.ngap.NGAP`
    for one."""

    NAMES = ('SSL', 'SSLv3', 'TLS', 'DTLS')

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_exported_from_every_namespace(self) -> None:
        import pcapkit
        import pcapkit.all
        import pcapkit.protocols
        import pcapkit.protocols.application
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.protocols.application.tls import TLS, SSLv3

        classes = {'SSL': SSL, 'SSLv3': SSLv3, 'TLS': TLS, 'DTLS': DTLS}
        for module in (pcapkit, pcapkit.all, pcapkit.protocols, pcapkit.protocols.application):
            for name in self.NAMES:
                with self.subTest(module=module.__name__, name=name):
                    self.assertIn(name, module.__all__)
                    self.assertIs(getattr(module, name), classes[name])

    def test_registered_in_the_protocol_registry(self) -> None:
        import pcapkit.protocols

        for name in self.NAMES:
            with self.subTest(name=name):
                self.assertIs(pcapkit.protocols.__proto__[name.upper()],
                              getattr(pcapkit.protocols, name))

    def test_string_lookup_matches_a_parsed_record(self) -> None:
        """``'SSL' in pkt`` agrees with ``SSL in pkt``, the name being registered."""
        from pcapkit.protocols.application.ssl import SSL
        from pcapkit.protocols.transport.tcp import TCP

        raw = _TCP_TO_443 + b'\x17\x03\x03\x00\x05hello'
        proto = TCP(raw, len(raw))
        self.assertIn(SSL, proto)
        self.assertIn('SSL', proto)
        self.assertIn('TLS', proto)

    def test_const_package_star_imports_tls(self) -> None:
        import pcapkit.const
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.const.tls.handshake_type import HandshakeType

        self.assertIn('TLS_ContentType', pcapkit.const.__all__)
        self.assertIn('TLS_HandshakeType', pcapkit.const.__all__)
        self.assertIs(pcapkit.const.TLS_ContentType, ContentType)
        self.assertIs(pcapkit.const.TLS_HandshakeType, HandshakeType)


if __name__ == '__main__':
    unittest.main()
