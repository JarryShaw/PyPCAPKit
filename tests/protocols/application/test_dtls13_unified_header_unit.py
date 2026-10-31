# -*- coding: utf-8 -*-
"""Unit tests for DTLS 1.3's unified-header ciphertext records (:issue:`2467`).

RFC 9147 section 4.1 gives an encrypted record a unified header, first octet
``001CSLEE``: ``C`` names a connection ID, ``S`` an 8- or 16-bit sequence
number, ``L`` a length field, and ``EE`` the low two bits of the epoch.

"""
from __future__ import annotations

import unittest
import warnings

from tests._support import reimport_once_per_class

#: First octets for the four flag combinations the tests use, with ``C`` clear
#: unless named: ``001 0 S L EE``.
_L_SHORT_SEQ_EPOCH1 = 0x25  # S=0, L=1, EE=01
_L_LONG_SEQ_EPOCH2 = 0x2E   # S=1, L=1, EE=10
_NO_LENGTH_EPOCH3 = 0x23    # S=0, L=0, EE=11
_CID_PRESENT = 0x38         # C=1, S=0, L=1, EE=00

#: A 16-octet stand-in for an AEAD ciphertext, the shortest the record-number
#: sample allows (:rfc:`9147#section-4.2.3`).
_FRAGMENT = bytes(range(0xA0, 0xB0))


def _unified(first: int, sequence: bytes, length: 'bytes | None', fragment: bytes) -> bytes:
    """A unified-header record: the first octet, the sequence number, the
    length if one is carried, then the ciphertext."""
    return bytes([first]) + sequence + (length or b'') + fragment


def _udp_to_5684(payload: bytes) -> bytes:
    """An 8-octet UDP header to port 5684, where DTLS is bound, plus ``payload``."""
    return ((50000).to_bytes(2, 'big') + (5684).to_bytes(2, 'big')
            + (8 + len(payload)).to_bytes(2, 'big') + b'\x00\x00' + payload)


class UnifiedHeaderParseTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_length_present_with_an_8_bit_sequence_number(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = _unified(_L_SHORT_SEQ_EPOCH1, b'\x2a', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT)

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')
        self.assertEqual(parsed.length, 4)  # first octet, sequence number, length
        self.assertEqual(parsed.info.epoch, 1)
        self.assertEqual(parsed.info.sequence_number, 0x2A)
        self.assertFalse(parsed.info.sequence_long)
        self.assertEqual(parsed.info.length, len(_FRAGMENT))
        self.assertEqual(parsed.info.content, _FRAGMENT)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_length_present_with_a_16_bit_sequence_number(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = _unified(_L_LONG_SEQ_EPOCH2, b'\x12\x34', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT)

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')
        self.assertEqual(parsed.length, 5)
        self.assertEqual(parsed.info.epoch, 2)
        self.assertEqual(parsed.info.sequence_number, 0x1234)
        self.assertTrue(parsed.info.sequence_long)
        self.assertEqual(parsed.info.content, _FRAGMENT)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_without_a_length_the_record_runs_to_the_end_of_the_datagram(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = _unified(_NO_LENGTH_EPOCH3, b'\x07', None, _FRAGMENT)

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.alias, 'DTLS 1.3')
        self.assertEqual(parsed.length, 2)  # first octet and sequence number only
        self.assertEqual(parsed.info.epoch, 3)
        self.assertIsNone(parsed.info.length)
        self.assertEqual(parsed.info.content, _FRAGMENT)
        self.assertEqual(bytes(DTLS.from_data(parsed.info)), wire)

    def test_a_coalesced_record_after_the_length_is_not_swallowed(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        trailing = b'\xde\xad'
        wire = _unified(_L_SHORT_SEQ_EPOCH1, b'\x07', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT) + trailing

        parsed = DTLS(wire, len(wire))
        self.assertEqual(parsed.info.content, _FRAGMENT)
        self.assertEqual(bytes(parsed.payload), trailing)

    def test_a_connection_id_is_refused_rather_than_misread(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        # The connection ID's length is negotiated, not carried, so the
        # record cannot be cut at the right place.
        wire = _unified(_CID_PRESENT, b'\x07', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT)

        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))

    def test_a_length_past_the_end_of_the_datagram_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        wire = _unified(_L_SHORT_SEQ_EPOCH1, b'\x07', (0x20).to_bytes(2, 'big'), _FRAGMENT)

        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))

    def test_a_header_with_no_ciphertext_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        wire = _unified(_NO_LENGTH_EPOCH3, b'\x07', None, b'')

        with self.assertRaises(ProtocolError):
            DTLS(wire, len(wire))

    def test_a_ciphertext_shorter_than_the_sample_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        # RFC 9147 section 4.2.3: a record under 16 octets of ciphertext MUST
        # be rejected as if it had failed deprotection.
        short = _FRAGMENT[:15]
        for name, length in (('length present', len(short).to_bytes(2, 'big')), ('length absent', None)):
            with self.subTest(case=name):
                wire = _unified(_L_SHORT_SEQ_EPOCH1 if length else _NO_LENGTH_EPOCH3, b'\x07', length, short)
                with self.assertRaises(ProtocolError):
                    DTLS(wire, len(wire))

    def test_a_ciphertext_of_the_minimum_length_is_accepted(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for name, first, length in (('length present', _L_SHORT_SEQ_EPOCH1, len(_FRAGMENT).to_bytes(2, 'big')),
                                    ('length absent', _NO_LENGTH_EPOCH3, None)):
            with self.subTest(case=name):
                wire = _unified(first, b'\x07', length, _FRAGMENT)
                parsed = DTLS(wire, len(wire))
                self.assertEqual(parsed.alias, 'DTLS 1.3')
                self.assertEqual(parsed.info.content, _FRAGMENT)

    def test_udp_port_5684_dispatches_the_unified_record(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        wire = _udp_to_5684(_unified(_L_SHORT_SEQ_EPOCH1, b'\x2a',
                                     len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT))

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = UDP(wire, len(wire))
        self.assertEqual(str(proto.protochain), 'UDP:DTLS 1.3')

    def test_a_refused_connection_id_record_degrades_to_raw_on_dispatch(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        # The genuine record is asserted alongside, so the refusal cannot be
        # satisfied by a binding that resolves to ``Raw`` unconditionally.
        good = _unified(_L_SHORT_SEQ_EPOCH1, b'\x2a', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT)
        refused = _unified(_CID_PRESENT, b'\x2a', len(_FRAGMENT).to_bytes(2, 'big'), _FRAGMENT)
        for name, payload, expected in (('a genuine record', good, 'UDP:DTLS 1.3'),
                                        ('a connection ID', refused, 'UDP:Raw')):
            with self.subTest(payload=name):
                wire = _udp_to_5684(payload)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    proto = UDP(wire, len(wire))
                self.assertEqual(str(proto.protochain), expected)


    def test_a_datagram_the_record_format_forbids_degrades_to_raw_on_dispatch(self) -> None:
        from pcapkit.protocols.transport.udp import UDP

        # First octet in the 001 range and the header fits, but the ciphertext
        # is under the sample length, so it is not a DTLS 1.3 record.
        wire = _udp_to_5684(_unified(_L_SHORT_SEQ_EPOCH1, b'\x2a',
                                     len(_FRAGMENT[:15]).to_bytes(2, 'big'), _FRAGMENT[:15]))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto = UDP(wire, len(wire))
        self.assertEqual(str(proto.protochain), 'UDP:Raw')


class UnifiedHeaderMakeTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_writes_each_flag_combination(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        cases = (
            ('length, 8-bit sequence', dict(epoch=1, sequence_number=0x2A, sequence_long=False,
                                            length_present=True), _L_SHORT_SEQ_EPOCH1),
            ('length, 16-bit sequence', dict(epoch=2, sequence_number=0x1234, sequence_long=True,
                                             length_present=True), _L_LONG_SEQ_EPOCH2),
            ('no length', dict(epoch=3, sequence_number=0x07, sequence_long=False,
                               length_present=False), _NO_LENGTH_EPOCH3),
        )
        for name, options, first in cases:
            with self.subTest(case=name):
                sequence_len = 2 if options['sequence_long'] else 1
                expected = bytes([first]) + options['sequence_number'].to_bytes(sequence_len, 'big')
                if options['length_present']:
                    expected += len(_FRAGMENT).to_bytes(2, 'big')
                expected += _FRAGMENT

                made = bytes(DTLS(ciphertext=True, content=_FRAGMENT, **options))
                self.assertEqual(made, expected)

    def test_make_then_parse_round_trips(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        for sequence_long in (False, True):
            for length_present in (False, True):
                with self.subTest(sequence_long=sequence_long, length_present=length_present):
                    made = DTLS(ciphertext=True, epoch=2, sequence_number=0x5A,
                                sequence_long=sequence_long, length_present=length_present,
                                content=_FRAGMENT)
                    parsed = DTLS(bytes(made), len(bytes(made)))
                    self.assertEqual(parsed.alias, 'DTLS 1.3')
                    self.assertEqual(parsed.info.epoch, 2)
                    self.assertEqual(parsed.info.sequence_number, 0x5A)
                    self.assertEqual(parsed.info.sequence_long, sequence_long)
                    self.assertEqual(parsed.info.content, _FRAGMENT)
                    self.assertEqual(parsed.info.length, len(_FRAGMENT) if length_present else None)

    def test_an_epoch_wider_than_two_bits_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            DTLS(ciphertext=True, epoch=4, content=_FRAGMENT)


if __name__ == '__main__':
    unittest.main()
