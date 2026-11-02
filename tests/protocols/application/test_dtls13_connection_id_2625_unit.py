# -*- coding: utf-8 -*-
"""DTLS 1.3 unified-header records with a connection ID (RFC 9147 section 4, #2625).

A unified header with its ``C`` bit set carries a connection ID between its
first octet and its sequence number (RFC 9147 section 4, Figure 3). The ID's
length is negotiated in the ``connection_id`` extension (RFC 9146 section 3),
not carried, so ``DTLSContext`` resolves it as it does for a ``tls12_cid``
record (#2515): from the IDs the capture's hellos negotiate, then from a
caller-supplied ``cid_length``.

:data:`WOLFSSL` is a real exchange between wolfSSL 5.9.4's example client and
server (``-u -v 4 -s``, built with ``--enable-dtls13 --enable-dtlscid``),
recorded through a loopback UDP relay: the client asks for ``cli4`` and the
server for ``SRV-CID8``. It has the shape of RFC 9147 section 9.1's Figure 15.
tshark 4.6.9 (``-d udp.port==5684,dtls``) reads every record as :data:`TSHARK`
lists it. The other vectors follow Figure 3.

"""
from __future__ import annotations

import sys
import threading
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class
from tests.protocols.application.test_dtls_connection_id_2515_unit import CCS, _dtls_layers, _ethernet_pcap, _udp
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks that the exception hooks are left alone.
__tier__ = 'ALL'

#: Connection IDs the wolfSSL client and server ask to receive.
CLIENT_CID = b'cli4'
SERVER_CID = b'SRV-CID8'

#: The exchange, one ``(from_client, payload)`` per UDP datagram, in order:
#: ClientHello, HelloRetryRequest, ClientHello with the cookie, ServerHello,
#: then the encrypted records.
WOLFSSL = tuple((direction == 'C', bytes.fromhex(payload)) for direction, payload in (
    ('C', '16fefd0000000000000000011d010001110000000000000111fefd6a51df028ea6014c22cc84ed52a3339c8169dc1813'
          'c0c5c06300aa31e5944a7e00000004130100aa010000e3002d0003020001002b000302fefc000d001c001a0603050304'
          '030806080b0805080a080408090601050104010301000a0010000e11ed11eb0019001800170015010000160000003600'
          '0504636c6934003300470045001700410459c382ae9a025039a4cf18e456797d1d40e8a139fad8b8599439822a4db40a'
          '3ac424b5e62ff460976dd294f29cd293758ec4646c51feec0060cd67adcdc72ae9ff0100010000290040001b0015436c'
          '69656e745f6964656e746974795348413235360000000000212011bb15a7723c35c0b15fadd5312bebdb97b5fe8c1673'
          '48c7aeba64a2169572c2'),
    ('S', '16fefd00000000000000000083020000770000000000000077fefdcf21ad74e59a6111be1d8c021e65b891c2a211167a'
          'bb8c5e079e09e2c8a8339c00130100004f002b0002fefc002c0045004320232eac3859d7c823503c79ebce1964a45481'
          '2e11685b840a928470e6dc8d8cd513016d064fb17b5dd932eec197ecad805d9c81f436d2bc32e6d07799381026dc1759'),
    ('C', '16fefd000000000000000101660100015a000100000000015afefd6a51df028ea6014c22cc84ed52a3339c8169dc1813'
          'c0c5c06300aa31e5944a7e00000004130100aa0100012c002b000302fefc002c0045004320232eac3859d7c823503c79'
          'ebce1964a454812e11685b840a928470e6dc8d8cd513016d064fb17b5dd932eec197ecad805d9c81f436d2bc32e6d077'
          '99381026dc1759002d0003020001000d001c001a0603050304030806080b0805080a080408090601050104010301000a'
          '0010000e11ed11eb00190018001700150100001600000036000504636c6934003300470045001700410459c382ae9a02'
          '5039a4cf18e456797d1d40e8a139fad8b8599439822a4db40a3ac424b5e62ff460976dd294f29cd293758ec4646c51fe'
          'ec0060cd67adcdc72ae9ff0100010000290040001b0015436c69656e745f6964656e7469747953484132353600000000'
          '002120ceeaf8ed350862aeb11af78a69ff83ea5091b1524e276d04406740388dc6b4d6'),
    ('S', '16fefd000000000000000100960200008a000100000000008afefd898d015731b30a6e72204d04801134454e3adce2d3'
          '6324877f41b1dbaa9bb790001301000062002900020000003300450017004104d5fa378935339c7196321c142be55caa'
          '4f808dd09c31b09b4a928756dd435b0fd4ce403f074fe4b6f2873b07362dd20b0ebf878aff0316d939a01c3ba6a12cbe'
          '002b0002fefc00360009085352562d43494438'),
    ('S', '3e636c69347f14001fd76e1e029b930d1e87922af501b31010d0874c8fb7e777432de932d82c2025'),
    ('S', '3e636c6934d8d5003dcb238bc73e714f266090997560c60b954f5f42c4506f39ce6b242cb72847952538a5336fcded73'
          '75abf27a7880b65f4e64dee27f36e390b52d8e1dd8a7'),
    ('C', '3e5352562d434944380f80003da4173a4beefc8f85af6d655126b0acdcca02bb9c17776eb8dbd2fded2aeb1430857bf0'
          'cc219b1a3ad804d90437ba5a768346c2d6d8a3f020ce0df15926'),
    ('S', '3f636c6934bd470023375a37380f3573e4a7ff2565eab3f49d5e687406d6559c48238a22afb7fb8959eb2445'),
    ('C', '3f5352562d4349443893ed001fa4c15c16ababd1a42babb2830e263463392dbea296593f9fff16c087a70997'),
    ('S', '3f636c6934046a002732fa988e0dfa32e8e8cc38edb60b11b4cf80223d245742017c7d7606b19b3e19bd25874f3b8bcb'),
    ('S', '3f636c6934a1e700136f937d6540c19eb544fe26758492bb3da27238'),
    ('C', '3f5352562d43494438ffe60013317a8d1aa3deec6712ba5f8542f142362afbf6'),
))

#: Index of the first record with a connection ID in :data:`WOLFSSL`.
FIRST_CID_RECORD = 4

#: Per datagram: its protochain, and ``(cid, epoch, sequence number, length)``
#: of each unified-header record with a connection ID in it, as tshark reports
#: them: ``dtls.record.connection_id``, ``dtls.unified_header.epoch_bits``,
#: ``dtls.record.sequence_suffix`` and ``dtls.record.length``.
TSHARK = (
    ('UDP:DTLS 1.3', ()),
    ('UDP:DTLS 1.3', ()),
    ('UDP:DTLS 1.3', ()),
    ('UDP:DTLS 1.3', ()),
    ('UDP:DTLS 1.3', ((CLIENT_CID, 2, 32532, 31),)),
    ('UDP:DTLS 1.3', ((CLIENT_CID, 2, 55509, 61),)),
    ('UDP:DTLS 1.3', ((SERVER_CID, 2, 3968, 61),)),
    ('UDP:DTLS 1.3', ((CLIENT_CID, 3, 48455, 35),)),
    ('UDP:DTLS 1.3', ((SERVER_CID, 3, 37869, 31),)),
    ('UDP:DTLS 1.3', ((CLIENT_CID, 3, 1130, 39),)),
    ('UDP:DTLS 1.3', ((CLIENT_CID, 3, 41447, 19),)),
    ('UDP:DTLS 1.3', ((SERVER_CID, 3, 65510, 19),)),
)

#: A 16-octet stand-in for an AEAD ciphertext, the shortest the record-number
#: sample allows (RFC 9147 section 4.2.3).
FRAGMENT = bytes(range(0xA0, 0xB0))


def _unified(cid: bytes, fragment: bytes = FRAGMENT, *, sequence: bytes = b'\x07',
             length_present: bool = True, epoch: int = 1) -> bytes:
    """A unified-header record with a connection ID, as RFC 9147 section 4's Figure 3 lays it out."""
    first = 0b00110000 | (len(sequence) == 2) << 3 | length_present << 2 | epoch
    length = len(fragment).to_bytes(2, 'big') if length_present else b''
    return bytes([first]) + cid + sequence + length + fragment


def _cid_layers(proto: 'Any') -> 'tuple':
    """``(cid, epoch, sequence number, length)`` of each unified-header layer with a connection ID under ``proto``."""
    from pcapkit.protocols.data.application.dtls import DTLSCiphertext

    return tuple((layer.info.cid, layer.info.epoch, layer.info.sequence_number, layer.info.length)
                 for layer in _dtls_layers(proto)[0]
                 if isinstance(layer.info, DTLSCiphertext) and layer.info.cid is not None)


class CaptureTests(unittest.TestCase):
    """The wolfSSL exchange reads as tshark reads it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_handshake_teaches_each_direction_its_id(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.application.dtls import DTLSContext
        from pcapkit.protocols.transport.udp import UDP

        registry = ContextRegistry()
        for index, ((from_client, payload), (chain, records)) in enumerate(zip(WOLFSSL, TSHARK), 1):
            with self.subTest(datagram=index):
                datagram = _udp(payload, from_client)
                proto = UDP(datagram, len(datagram), __context__=registry)
                self.assertEqual(str(proto.protochain), chain)
                self.assertEqual(_cid_layers(proto.payload), records)
        context = registry.match(['DTLS'], DTLSContext)
        self.assertEqual(context.connection_ids, (CLIENT_CID, SERVER_CID))  # type: ignore[union-attr]

    def test_each_record_reports_its_header(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        wire = WOLFSSL[6][1]  # first octet 0x3e: C, S and L set, epoch bits 2
        parsed = DTLS(wire, len(wire), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
        self.assertEqual(parsed.alias, 'DTLS 1.3')
        self.assertEqual(parsed.length, 1 + len(SERVER_CID) + 2 + 2)
        self.assertEqual((parsed.info.cid, parsed.info.epoch, parsed.info.sequence_number,
                          parsed.info.sequence_long, parsed.info.length),
                         (SERVER_CID, 2, 3968, True, 61))
        self.assertEqual(parsed.info.content, wire[-61:])

    def test_an_extraction_carries_the_ids_across_its_frames(self) -> None:
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extraction = pcapkit.extract(fin=_ethernet_pcap(self, WOLFSSL), nofile=True)
        try:
            self.assertEqual([str(frame.protochain) for frame in extraction.frame],
                             [f'Ethernet:IPv4:{chain}' for chain, _ in TSHARK])
            self.assertEqual([_cid_layers(frame['UDP'].payload) for frame in extraction.frame],
                             [records for _, records in TSHARK])
        finally:
            close_extractor(extraction)

    def test_a_caller_supplied_length_reads_records_without_the_handshake(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext
        from pcapkit.protocols.transport.udp import UDP

        for index in range(FIRST_CID_RECORD, len(WOLFSSL)):
            (from_client, payload), (chain, records) = WOLFSSL[index], TSHARK[index]
            with self.subTest(datagram=index + 1):
                context = DTLSContext(cid_length=len(records[0][0]))
                datagram = _udp(payload, from_client)
                proto = UDP(datagram, len(datagram), __context__=context)
                self.assertEqual(str(proto.protochain), chain)
                self.assertEqual(_cid_layers(proto.payload), records)

    def test_one_cid_length_does_not_read_both_directions_when_their_lengths_differ(self) -> None:
        """``cid_length`` is a single value (#2515), so the caller passes the IDs instead."""
        from pcapkit.protocols.application.dtls import DTLSContext
        from pcapkit.protocols.transport.udp import UDP

        for index in range(FIRST_CID_RECORD, len(WOLFSSL)):
            (from_client, payload), (_, records) = WOLFSSL[index], TSHARK[index]
            with self.subTest(datagram=index + 1):
                datagram = _udp(payload, from_client)
                by_length = UDP(datagram, len(datagram), __context__=DTLSContext(cid_length=len(CLIENT_CID)))
                by_ids = UDP(datagram, len(datagram), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
                self.assertEqual(str(by_length.protochain), 'UDP:Raw' if from_client else 'UDP:DTLS 1.3')
                self.assertEqual(str(by_ids.protochain), 'UDP:DTLS 1.3')
                self.assertEqual(_cid_layers(by_ids.payload), records)

    def test_an_id_the_capture_cannot_teach_comes_from_the_caller(self) -> None:
        """A ``NewConnectionId`` is encrypted (RFC 9147 section 9), so the ID it issues is the caller's to give."""
        import pcapkit
        from pcapkit.protocols.application.dtls import DTLSContext

        issued = b'issued-by-new-cid'
        from_client, payload = WOLFSSL[-2]
        moved = payload.replace(CLIENT_CID, issued, 1)
        datagrams = WOLFSSL[:-2] + ((from_client, moved),)
        for name, kwargs, chain in (('the handshake alone', {}, 'Ethernet:IPv4:UDP:Raw'),
                                    ('the caller', {'context': DTLSContext(issued)}, 'Ethernet:IPv4:UDP:DTLS 1.3')):
            with self.subTest(ids=name):
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    extraction = pcapkit.extract(fin=_ethernet_pcap(self, datagrams), nofile=True, **kwargs)
                try:
                    self.assertEqual(str(extraction.frame[-1].protochain), chain)
                    if kwargs:
                        self.assertEqual(_cid_layers(extraction.frame[-1]['UDP'].payload),
                                         ((issued, 3, 41447, 19),))
                        self.assertEqual(kwargs['context'].connection_ids, (issued, CLIENT_CID, SERVER_CID))
                finally:
                    close_extractor(extraction)


class InstanceMemoryTests(unittest.TestCase):
    """Learned connection IDs belong to one ``DTLSContext`` instance, as #2515 ruled."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, datagrams: 'tuple', **kwargs: 'Any') -> 'Any':
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extraction = pcapkit.extract(fin=_ethernet_pcap(self, datagrams), nofile=True, **kwargs)
        self.addCleanup(close_extractor, extraction)
        return extraction

    def test_a_new_instance_carries_no_history(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext

        first = self._extract(WOLFSSL)
        self.assertEqual(str(first.frame[-1].protochain), 'Ethernet:IPv4:UDP:DTLS 1.3')
        for name, kwargs in (('no context', {}), ('a fresh instance', {'context': DTLSContext()})):
            with self.subTest(second=name):
                second = self._extract(WOLFSSL[FIRST_CID_RECORD:], **kwargs)
                self.assertEqual({str(frame.protochain) for frame in second.frame}, {'Ethernet:IPv4:UDP:Raw'})

    def test_a_reused_caller_instance_keeps_its_ids(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext

        context = DTLSContext()
        self._extract(WOLFSSL, context=context)
        self.assertEqual(context.connection_ids, (CLIENT_CID, SERVER_CID))

        again = self._extract(WOLFSSL[FIRST_CID_RECORD:], context=context)
        self.assertEqual([_cid_layers(frame['UDP'].payload) for frame in again.frame],
                         [records for _, records in TSHARK[FIRST_CID_RECORD:]])


class QuietRefusalTests(unittest.TestCase):
    """A record whose connection ID is unknown is ``Raw``, quietly, on dispatch (#2588)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # NOTE: Imported before the sentinels go in, since importing pcapkit
        # outside development mode installs tbtrim's hook itself.
        import pcapkit  # pylint: disable=import-outside-toplevel,unused-import
        saved_sys, saved_threading = sys.excepthook, threading.excepthook

        def _restore() -> None:
            sys.excepthook = saved_sys
            threading.excepthook = saved_threading

        self.addCleanup(_restore)

        def _sys_sentinel(*args: 'Any') -> None:
            saved_sys(*args)

        def _threading_sentinel(args: 'Any') -> None:
            saved_threading(args)

        self.sys_sentinel, self.threading_sentinel = _sys_sentinel, _threading_sentinel
        sys.excepthook, threading.excepthook = _sys_sentinel, _threading_sentinel

    def test_dispatch_keeps_the_record_raw_and_logs_nothing(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.udp import UDP
        from pcapkit.utilities import exceptions
        from pcapkit.utilities.logging import logger

        for index in range(FIRST_CID_RECORD, len(WOLFSSL)):
            from_client, payload = WOLFSSL[index]
            with self.subTest(datagram=index + 1):
                datagram = _udp(payload, from_client)
                with capture(logger) as package, capture(exceptions.logger) as module:
                    proto = UDP(datagram, len(datagram))
                self.assertEqual(str(proto.protochain), 'UDP:Raw')
                self.assertIs(type(proto.payload), Raw)
                self.assertRegex(str(proto.payload.info.error),
                                 r'^DTLS 1\.3: invalid format: no connection ID length is known '
                                 r'for a unified-header record')
                self.assertEqual(package.messages + module.messages, [])
                self.assertIs(sys.excepthook, self.sys_sentinel)
                self.assertIs(threading.excepthook, self.threading_sentinel)
                self.assertEqual(bytes(UDP.from_data(proto.info)).hex(), datagram.hex())

    def test_a_direct_parse_raises(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        wire = WOLFSSL[FIRST_CID_RECORD][1]
        with self.assertRaisesRegex(ProtocolError, 'no connection ID length is known for a unified-header record'):
            DTLS(wire, len(wire))


class LayoutTests(unittest.TestCase):
    """Each flag combination with ``C`` set, built as Figure 3 lays it out."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_flag_combination_parses(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        cid = b'\xc1\xc2\xc3'
        for sequence in (b'\x07', b'\x12\x34'):
            for length_present in (True, False):
                with self.subTest(sequence_long=len(sequence) == 2, length_present=length_present):
                    wire = _unified(cid, sequence=sequence, length_present=length_present, epoch=3)
                    parsed = DTLS(wire, len(wire), __context__=DTLSContext(cid))
                    self.assertEqual(parsed.alias, 'DTLS 1.3')
                    self.assertEqual(parsed.length, 1 + len(cid) + len(sequence) + 2 * length_present)
                    self.assertEqual((parsed.info.cid, parsed.info.epoch, parsed.info.sequence_number,
                                      parsed.info.sequence_long, parsed.info.length, parsed.info.content),
                                     (cid, 3, int.from_bytes(sequence, 'big'), len(sequence) == 2,
                                      len(FRAGMENT) if length_present else None, FRAGMENT))
                    self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_record_without_a_cid_reports_none(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS

        wire = b'\x25\x07' + len(FRAGMENT).to_bytes(2, 'big') + FRAGMENT
        parsed = DTLS(wire, len(wire))
        self.assertIsNone(parsed.info.cid)
        self.assertEqual(parsed.length, 4)

    def test_a_header_cut_short_is_refused(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        for name, wire in (('no connection ID octets', b'\x3c'),
                           ('half a connection ID', b'\x3c\xc1\xc2'),
                           ('no sequence number', b'\x3c\xc1\xc2\xc3\xc4')):
            with self.subTest(case=name), warnings.catch_warnings(), self.assertRaises(ProtocolError):
                warnings.simplefilter('ignore')  # the schema's short read
                DTLS(wire, len(wire), __context__=DTLSContext(cid_length=4))


class ResolutionTests(unittest.TestCase):
    """``DTLSContext.match`` finds a unified header's ID by the same rules as a ``tls12_cid`` one's."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_learned_id_comes_before_cid_length(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        for name, wire, context, header in (
                ('the capture', WOLFSSL[6][1], DTLSContext(SERVER_CID, cid_length=len(CLIENT_CID)),
                 (SERVER_CID, 3968, 61)),
                # Either length leaves a record that fits, so only the order decides.
                ('either fits', _unified(b'\xab\xcd', bytes(32), length_present=False),
                 DTLSContext(b'\xab\xcd', cid_length=1), (b'\xab\xcd', 7, None)),
        ):
            with self.subTest(case=name):
                parsed = DTLS(wire, len(wire), __context__=context)
                self.assertEqual((parsed.info.cid, parsed.info.sequence_number, parsed.info.length), header)

    def test_a_shorter_id_is_not_read_as_a_longer_one(self) -> None:
        """``ab``'s sequence number opens with ``cd``, so ``abcd`` fits too unless the sample must."""
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        for name, fragment, length_present in (
                ('without a length', FRAGMENT, False),
                # Past ``abcd`` the length reads 5: the record fits, with no room for the sample.
                ('with a length', b'\x05' + bytes(255), True),
        ):
            with self.subTest(case=name):
                wire = _unified(b'\xab', fragment, sequence=b'\xcd\x00', length_present=length_present)
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(b'\xab', b'\xab\xcd'))
                self.assertEqual((parsed.info.cid, parsed.info.sequence_number, parsed.info.content),
                                 (b'\xab', 0xCD00, fragment))

    def test_without_a_length_the_sample_bounds_the_fit(self) -> None:
        """The sample's octets after ``abcd``'s header fit; with one fewer, only ``ab``'s shorter header leaves room."""
        from pcapkit.protocols.application.dtls import DTLSContext

        context = DTLSContext(b'\xab', b'\xab\xcd')
        for rest, expected in ((16, 2), (15, 1), (14, 2)):  # neither fits at 14: the first candidate
            with self.subTest(octets_after_the_sequence_number=rest):
                octets = b'\xab\xcd\x07' + bytes(rest)
                self.assertEqual(context.match(octets, sequence_length=1, length_present=False,
                                               min_content_length=16), expected)
        for size, expected in ((3, 2), (2, 1)):  # no minimum, as for tls12_cid: the header alone fits
            with self.subTest(octets=size):
                self.assertEqual(context.match(b'\xab\xcd\x07'[:size], sequence_length=1, length_present=False),
                                 expected)

    def test_the_longest_id_whose_record_fits(self) -> None:
        """The fit is read past the sequence number, which a ``tls12_cid`` record does not have."""
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        fragment = b'\xff' + bytes(15)
        for name, cid, ids in (
                ('both ids open it, the longer fits', b'\xab\xcd', (b'\xab', b'\xab\xcd')),
                # Past ``abcd`` and a sequence octet the length reads 0x10ff, which does not fit;
                # with no sequence octet, as in a tls12_cid record, it would read 0x0010 and fit.
                ('the longer opens it but does not fit', b'\xab', (b'\xab', b'\xab\xcd')),
        ):
            with self.subTest(case=name):
                wire = _unified(cid, fragment, sequence=b'\xcd')
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(*ids))
                self.assertEqual((parsed.info.cid, parsed.info.content), (cid, fragment))
                self.assertEqual(parsed.length, 1 + len(cid) + 1 + 2)

    def test_without_a_length_the_longest_id_whose_header_fits(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        wire = _unified(b'\xab\xcd', length_present=False)
        parsed = DTLS(wire, len(wire), __context__=DTLSContext(b'\xab', b'\xab\xcd'))
        self.assertEqual((parsed.info.cid, parsed.info.length, parsed.info.content), (b'\xab\xcd', None, FRAGMENT))

    def test_match_takes_the_unified_layout(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext

        context = DTLSContext(b'\xab', b'\xab\xcd')
        octets = _unified(b'\xab', b'\xff' + bytes(15), sequence=b'\xcd')[1:]
        self.assertEqual(context.match(octets, sequence_length=1), 1)
        self.assertEqual(context.match(octets), 2)  # read as a tls12_cid record's ID, length 0x0010
        self.assertEqual(context.match(octets, sequence_length=1, length_present=False), 2)
        self.assertIsNone(DTLSContext().match(octets, sequence_length=1))


class ChainTests(unittest.TestCase):
    """A unified-header record with a connection ID chains with the records sharing its datagram (#2535)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_records_either_side_of_one_are_further_layers(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        record = _unified(CLIENT_CID)
        last = _unified(CLIENT_CID, FRAGMENT + CCS, length_present=False)
        for name, wire, chain in (('after a legacy record', CCS + record, 'DTLS 1.2:DTLS 1.3'),
                                  ('before a legacy record', record + CCS, 'DTLS 1.3:DTLS 1.2'),
                                  ('two of them', record + record, 'DTLS 1.3:DTLS 1.3'),
                                  ('one without a length, last', CCS + record + last, 'DTLS 1.2:DTLS 1.3:DTLS 1.3')):
            with self.subTest(case=name):
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(CLIENT_CID))
                self.assertEqual(str(parsed.protochain), chain)
                self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())
        parsed = DTLS(CCS + last, len(CCS + last), __context__=DTLSContext(CLIENT_CID))
        self.assertEqual(_cid_layers(parsed), ((CLIENT_CID, 1, 7, None),))
        self.assertEqual(parsed.payload.info.content, FRAGMENT + CCS)

    def test_an_unknown_id_after_a_record_stays_raw_without_an_error(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.protocols.misc.raw import Raw

        record = _unified(CLIENT_CID)
        for name, tail, kwargs in (('no context', record, {}),
                                   ('another id', record, {'__context__': DTLSContext(SERVER_CID)}),
                                   ('a header cut short', record[:5], {'__context__': DTLSContext(CLIENT_CID)})):
            with self.subTest(case=name):
                parsed = DTLS(CCS + tail, len(CCS + tail), **kwargs)
                self.assertEqual(str(parsed.protochain), 'DTLS 1.2:Raw')
                self.assertIs(type(parsed.payload), Raw)
                self.assertEqual(bytes(parsed.payload), tail)
                self.assertIsNone(parsed.payload.info.error)


class RoundTripTests(unittest.TestCase):
    """Byte-exact both ways: parse then rebuild, and make then parse."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parse_then_rebuild_is_byte_exact(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.transport.udp import UDP

        registry = ContextRegistry()
        for index, (from_client, payload) in enumerate(WOLFSSL, 1):
            with self.subTest(datagram=index):
                datagram = _udp(payload, from_client)
                udp = UDP(datagram, len(datagram), __context__=registry)
                rebuilt = DTLS.from_data(udp.payload.info)
                self.assertEqual(bytes(rebuilt).hex(), payload.hex())
                self.assertEqual(str(rebuilt.protochain), str(udp.payload.protochain))

                again = UDP.from_data(udp.info, __context__=registry)
                self.assertEqual(bytes(again).hex(), datagram.hex())
                self.assertEqual(str(again.protochain), str(udp.protochain))
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(bytes(UDP.from_data(udp.info)).hex(), datagram.hex())

    def test_make_then_parse_is_byte_exact(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        maker = object.__new__(DTLS)
        for index in range(FIRST_CID_RECORD, len(WOLFSSL)):
            wire = WOLFSSL[index][1]
            with self.subTest(datagram=index + 1):
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
                info = parsed.info
                made = bytes(maker.make(ciphertext=True, epoch=info.epoch, cid=info.cid,
                                        sequence_number=info.sequence_number, sequence_long=info.sequence_long,
                                        length_present=info.length is not None, content=info.content))
                self.assertEqual(made.hex(), wire.hex())

                again = DTLS(made, len(made), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
                self.assertEqual(_cid_layers(again), _cid_layers(parsed))

        made = DTLS(ciphertext=True, epoch=2, sequence_number=0x1234, sequence_long=True, cid=b'\x0a\x0b',
                    content=FRAGMENT)
        self.assertEqual(bytes(made).hex(), _unified(b'\x0a\x0b', sequence=b'\x12\x34', epoch=2).hex())
        self.assertEqual((made.alias, made.length, made.info.cid, made.info.length), ('DTLS 1.3', 7, b'\x0a\x0b', 16))

    def test_a_record_made_with_a_payload_parses_it_again(self) -> None:
        """The constructed payload's connection IDs are registered for its parse, on the instance in use."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        def build(**kwargs: 'Any') -> 'Any':
            inner = DTLS(ciphertext=True, epoch=3, sequence_number=9, cid=SERVER_CID, content=FRAGMENT)
            return DTLS(content_type=ContentType.change_cipher_spec, epoch=0, sequence_number=3,
                        content=b'\x01', payload=inner, **kwargs)

        context = DTLSContext()
        outer = build(__context__=context)
        self.assertEqual(str(outer.protochain), 'DTLS 1.2:DTLS 1.3')
        self.assertEqual(_cid_layers(outer), ((SERVER_CID, 3, 9, 16),))
        self.assertEqual(context.connection_ids, (SERVER_CID,))
        self.assertEqual(build().context.match(['DTLS'], DTLSContext).connection_ids, (SERVER_CID,))
        self.assertEqual(DTLSContext().connection_ids, ())

    def test_make_refuses_an_invalid_id(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        maker = object.__new__(DTLS)
        for name, cid in (('an empty one', b''), ('a 256-octet one', bytes(256)), ('a str', 'ab')):
            with self.subTest(case=name), self.assertRaisesRegex(ProtocolError, 'invalid connection ID'):
                maker.make(ciphertext=True, content=FRAGMENT, cid=cid)


if __name__ == '__main__':
    unittest.main()
