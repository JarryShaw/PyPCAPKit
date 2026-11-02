# -*- coding: utf-8 -*-
"""DTLS 1.2 records with a connection ID (RFC 9146, #2515).

A ``tls12_cid`` record carries its connection ID between the sequence number
and the length (RFC 9146 section 4, Figure 3). The ID's length is negotiated in
the ``connection_id`` extension (section 3), not carried, so ``DTLSContext``
resolves it: from the IDs the capture's hellos negotiate, then from a
caller-supplied ``cid_length``.

:data:`MBEDTLS` is a real exchange between Mbed TLS 4.2.0's ``ssl_client2`` and
``ssl_server2`` (``dtls=1 cid=1``, PSK, ``TLS-PSK-WITH-AES-128-CCM-8``), recorded
through a loopback UDP relay: the client asks for ``c1c2c3c4`` and the server
for ``a1a2a3a4a5a6a7a8``. tshark 4.6.9 (``-d udp.port==5684,dtls``) reads every
record as :data:`TSHARK` lists it. The other vectors follow Figure 3.

"""
from __future__ import annotations

import os
import struct
import sys
import tempfile
import threading
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): checks that the exception hooks are left alone.
__tier__ = 'ALL'

#: Connection IDs the Mbed TLS client and server ask to receive.
CLIENT_CID = bytes.fromhex('c1c2c3c4')
SERVER_CID = bytes.fromhex('a1a2a3a4a5a6a7a8')

#: The exchange, one ``(from_client, payload)`` per UDP datagram, in order.
MBEDTLS = tuple((direction == 'C', bytes.fromhex(payload)) for direction, payload in (
    ('C', '16fefd00000000000000000073010000670000000000000067fefd6ae803a4e31740e255176c17d4d7c19d92b9baf6c6'
          '94d969206ae50ed241a71b00000004c0a800ff010000390000000e000c0000096c6f63616c686f7374000d000e000c06'
          '03060105030501040304010036000504c1c2c3c4001600000017000000230000'),
    ('S', '16fefd0000000000000000002f030000230000000000000023fefd206ae803a41747fbaa56813d1553efde9296659fc8'
          'a203e9cf16838e743a00bd79'),
    ('C', '16fefd00000000000000010093010000870001000000000087fefd6ae803a4e31740e255176c17d4d7c19d92b9baf6c6'
          '94d969206ae50ed241a71b00206ae803a41747fbaa56813d1553efde9296659fc8a203e9cf16838e743a00bd790004c0'
          'a800ff010000390000000e000c0000096c6f63616c686f7374000d000e000c06030601050305010403040100360005'
          '04c1c2c3c4001600000017000000230000'),
    ('S', '16fefd0000000000000001004e020000420001000000000042fefd6ae803a4066dfc8934f6d38d96f4ce92497b503f64'
          'e42e463c1b9bcc92c4d82200c0a800001aff010001000036000908a1a2a3a4a5a6a7a8001700000023000016fefd0000'
          '000000000002000c0e0000000002000000000000'),
    ('C', '16fefd0000000000000002001d100000110002000000000011000f436c69656e745f6964656e7469747914fefd000000'
          '000000000300010119fefd0001000000000000a1a2a3a4a5a6a7a8003000010000000000001b8aee327bde4168cb0404'
          '9d9cddb4af84dcaf56dd038079d4bffb32112f3cddfa545d09ce119162'),
    ('S', '16fefd000000000000000300a70400009b000300000000009b000151800095262e883ce0e2ad87ccfb4e54c5026e7500'
          '73dddb0c04a230c4e072ac2de31f060db34df670e2b3b8f36b3ea79f9630b202b84a5a916bd373d47332a76d67800833'
          '226c1ce974d46458c998c697b851698196ff635d111abd3dd0e71e90c210262d36a45e3d3420942d37713ab31b5ad339'
          'd77a74ae2e1b03c860937fdca5185a0146287ca3b647c39cd267f72b871bdb05ab26948b14fefd00000000000000040001'
          '0119fefd0001000000000000c1c2c3c400300001000000000000cabe27c79b3a78d4bdbd0624dc9d12f28e73530701fc'
          'f6b4e854c070744bc84d7e42334c0285b52b'),
    ('C', '19fefd0001000000000001a1a2a3a4a5a6a7a8005000010000000000015c14c021e3f2c5f71518f19696e72672aaea43'
          '729c1919edb9fd31adade0639b1b45b8ff56ab931d218e191e2e62c51ceca82492002c8b6aa535c7f352b671ceca4ae3'
          'b824f355bc'),
    ('S', '19fefd0001000000000001c1c2c3c400a00001000000000001997b0b4964e8217400cd02db2f5d3cbc8d6836729fe801'
          '221c047fdb3e81d44c00e116cfa4b9cc242d822a3a85a4379f8ddf6111126b2a1fc22925196eeee7d0f31e3d8bbb6de5'
          'bd99d05098e2f12d70b7b60e3426c6a9b87d8bd384e7180981b3e4616c5e74a08add944e3b9f4b3a4cc235338e5048d5'
          '37f9561a282f2abdcd7d33301d82f86e4b47672338f66c5ff4e90c12c9119085a1'),
    ('S', '19fefd0001000000000002c1c2c3c4002000010000000000021869d0aea6345fc7eb664b55505f8c5485d78f2af0b08d66'),
    ('C', '19fefd0001000000000002a1a2a3a4a5a6a7a8002000010000000000023ca0a04f6ecfb4dfe3b8d3ac7cfbc052fad42c1a'
          '2132ec46'),
))

#: Per datagram: its protochain, and ``(cid, epoch, sequence number, length)``
#: of each ``tls12_cid`` record in it, as tshark reports them.
TSHARK = (
    ('UDP:DTLS 1.2', ()),
    ('UDP:DTLS 1.2', ()),
    ('UDP:DTLS 1.2', ()),
    ('UDP:DTLS 1.2:DTLS 1.2', ()),
    ('UDP:DTLS 1.2:DTLS 1.2:DTLS 1.2', ((SERVER_CID, 1, 0, 48),)),
    ('UDP:DTLS 1.2:DTLS 1.2:DTLS 1.2', ((CLIENT_CID, 1, 0, 48),)),
    ('UDP:DTLS 1.2', ((SERVER_CID, 1, 1, 80),)),
    ('UDP:DTLS 1.2', ((CLIENT_CID, 1, 1, 160),)),
    ('UDP:DTLS 1.2', ((CLIENT_CID, 1, 2, 32),)),
    ('UDP:DTLS 1.2', ((SERVER_CID, 1, 2, 32),)),
)

#: A legacy-format ``change_cipher_spec`` record, DTLS 1.2.
CCS = b'\x14\xfe\xfd\x00\x00' + (1).to_bytes(6, 'big') + b'\x00\x01\x01'


def _cid_record(cid: bytes, fragment: bytes, *, version: bytes = b'\xfe\xfd',
                epoch: int = 1, sequence_number: int = 1) -> bytes:
    """A ``tls12_cid`` record, as RFC 9146 section 4's Figure 3 lays it out."""
    return (b'\x19' + version + epoch.to_bytes(2, 'big') + sequence_number.to_bytes(6, 'big')
            + cid + len(fragment).to_bytes(2, 'big') + fragment)


def _udp(payload: bytes, from_client: bool = True) -> bytes:
    """An 8-octet UDP header between port 50000 and port 5684, plus ``payload``."""
    ports = (50000, 5684) if from_client else (5684, 50000)
    return struct.pack('!HHHH', *ports, 8 + len(payload), 0) + payload


def _dtls_layers(proto: 'Any') -> 'tuple[list, Any]':
    """Each DTLS layer of ``proto``'s chain, in order, and the layer that ends it."""
    from pcapkit.protocols.application.dtls import DTLS

    layers = []
    while isinstance(proto, DTLS):
        layers.append(proto)
        proto = proto.payload
    return layers, proto


def _cid_layers(proto: 'Any') -> 'tuple':
    """``(cid, epoch, sequence number, length)`` of each ``tls12_cid`` layer under ``proto``."""
    from pcapkit.protocols.data.application.dtls import DTLSCIDCiphertext

    return tuple((layer.info.cid, layer.info.epoch, layer.info.sequence_number, layer.info.length)
                 for layer in _dtls_layers(proto)[0] if isinstance(layer.info, DTLSCIDCiphertext))


def _ethernet_pcap(datagrams: 'tuple[tuple[bool, bytes], ...]') -> str:
    """Write ``datagrams`` as an Ethernet/IPv4/UDP PCAP file in a temporary directory."""
    path = os.path.join(tempfile.mkdtemp(prefix='pcapkit-dtls-cid-'), 'dtls-cid.pcap')
    client, server = bytes([192, 0, 2, 1]), bytes([192, 0, 2, 2])
    with open(path, 'wb') as file:
        file.write(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1))
        for index, (from_client, payload) in enumerate(datagrams):
            src, dst = (client, server) if from_client else (server, client)
            udp = _udp(payload, from_client)
            header = struct.pack('!BBHHHBBH4s4s', 0x45, 0, 20 + len(udp), index, 0, 64, 17, 0, src, dst)
            total = sum(struct.unpack('!10H', header))
            total = (total & 0xFFFF) + (total >> 16)
            header = header[:10] + struct.pack('!H', ~total & 0xFFFF) + header[12:]
            frame = bytes(6) + bytes(6) + b'\x08\x00' + header + udp
            file.write(struct.pack('<IIII', index, 0, len(frame), len(frame)) + frame)
    return path


class ConnectionIdExtensionTests(unittest.TestCase):
    """The ``connection_id`` extension decodes in a hello (RFC 9146 section 3)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_hello_decodes_the_id_its_sender_receives(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.tls import ConnectionId

        for name, (_, wire), cid in (('ClientHello', MBEDTLS[0], CLIENT_CID),
                                     ('ServerHello', MBEDTLS[3], SERVER_CID)):
            with self.subTest(hello=name):
                parsed = DTLS(wire, len(wire))
                extensions = parsed.info.content[0].body.extensions
                found = [ext.data for ext in extensions if ext.type == ExtensionType.connection_id]
                self.assertEqual(found, [ConnectionId(cid=cid)])
                self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_malformed_extension_stays_raw_and_teaches_nothing(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        # The ``cid`` vector says 5 octets, but 4 follow it.
        bad = MBEDTLS[0][1].replace(bytes.fromhex('0036000504c1c2c3c4'), bytes.fromhex('0036000505c1c2c3c4'))
        parsed = DTLS(bad, len(bad))
        ext, = [ext for ext in parsed.info.content[0].body.extensions if ext.type == ExtensionType.connection_id]
        self.assertEqual(ext.data, bytes.fromhex('05c1c2c3c4'))
        self.assertIsNone(parsed.context.match(['DTLS'], DTLSContext))
        self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), bad.hex())

    def test_the_extension_is_made_from_a_cid(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.const.tls.handshake_type import HandshakeType
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.data.application.tls import ConnectionId, Extension

        maker = object.__new__(DTLS)
        for name, extension in (('from kwargs', (ExtensionType.connection_id, {'cid': b'\x01\x02'})),
                                ('from data', Extension(type=ExtensionType.connection_id,
                                                        data=ConnectionId(cid=b'\x01\x02')))):
            with self.subTest(case=name):
                made = maker._make_tls_extensions([extension], msg_type=HandshakeType.client_hello)  # pylint: disable=protected-access
                self.assertEqual(made.hex(), '00360003020102')

    def test_a_tls_hello_carrying_the_extension_decodes_it_too(self) -> None:
        """RFC 9146 section 10.2 makes it DTLS-only; TLS shares the decoder regardless."""
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.protocols.application.tls import TLS
        from pcapkit.protocols.data.application.tls import ConnectionId

        extensions = bytes.fromhex('0036000302abcd')
        body = (b'\x03\x03' + bytes(32) + b'\x00' + b'\x00\x02\x13\x01' + b'\x01\x00'
                + len(extensions).to_bytes(2, 'big') + extensions)
        fragment = b'\x01' + len(body).to_bytes(3, 'big') + body
        wire = b'\x16\x03\x03' + len(fragment).to_bytes(2, 'big') + fragment
        parsed = TLS(wire, len(wire))
        ext, = parsed.info.content[0].body.extensions
        self.assertEqual((ext.type, ext.data), (ExtensionType.connection_id, ConnectionId(cid=b'\xab\xcd')))
        self.assertEqual(bytes(TLS.from_data(parsed.info)).hex(), wire.hex())

    def test_handing_back_the_shipped_entry_is_a_silent_no_op(self) -> None:
        from pcapkit.const.tls.extension_type import ExtensionType
        from pcapkit.foundation.registry.protocols import register_tls_extension
        from pcapkit.protocols.application.ssl import SSL

        shipped = dict(SSL.__extension__)
        self.assertEqual(shipped[ExtensionType.connection_id], 'connection_id')
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            register_tls_extension(ExtensionType.connection_id, 'connection_id')
        self.assertEqual(dict(SSL.__extension__), shipped)


class CaptureTests(unittest.TestCase):
    """The Mbed TLS exchange reads as tshark reads it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_handshake_teaches_each_direction_its_id(self) -> None:
        from pcapkit.corekit.context import ContextRegistry
        from pcapkit.protocols.application.dtls import DTLSContext
        from pcapkit.protocols.transport.udp import UDP

        registry = ContextRegistry()
        for index, ((from_client, payload), (chain, records)) in enumerate(zip(MBEDTLS, TSHARK), 1):
            with self.subTest(datagram=index):
                datagram = _udp(payload, from_client)
                proto = UDP(datagram, len(datagram), __context__=registry)
                self.assertEqual(str(proto.protochain), chain)
                self.assertEqual(_cid_layers(proto.payload), records)
        context = registry.match(['DTLS'], DTLSContext)
        self.assertEqual(context.connection_ids, (CLIENT_CID, SERVER_CID))  # type: ignore[union-attr]

    def test_an_extraction_carries_the_ids_across_its_frames(self) -> None:
        import pcapkit

        path = _ethernet_pcap(MBEDTLS)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extraction = pcapkit.extract(fin=path, nofile=True)
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

        for index in range(6, 10):
            (from_client, payload), (chain, records) = MBEDTLS[index], TSHARK[index]
            with self.subTest(datagram=index + 1):
                context = DTLSContext(cid_length=len(records[0][0]))
                datagram = _udp(payload, from_client)
                proto = UDP(datagram, len(datagram), __context__=context)
                self.assertEqual(str(proto.protochain), chain)
                self.assertEqual(_cid_layers(proto.payload), records)


class InstanceMemoryTests(unittest.TestCase):
    """Learned connection IDs belong to one ``DTLSContext`` instance, and nowhere else.

    Each test fails if a class-level, module-level or otherwise shared store
    carries IDs from one instance or extraction to another.

    """

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extract(self, datagrams: 'tuple', **kwargs: 'Any') -> 'Any':
        import pcapkit

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extraction = pcapkit.extract(fin=_ethernet_pcap(datagrams), nofile=True, **kwargs)
        self.addCleanup(close_extractor, extraction)
        return extraction

    def test_two_fresh_instances_share_nothing(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        first = DTLSContext()
        first.register(SERVER_CID)
        wire = MBEDTLS[3][1]  # a ServerHello, which teaches the instance its parse holds
        DTLS(wire, len(wire), __context__=DTLSContext())
        DTLS(wire, len(wire))

        second = DTLSContext()
        record = MBEDTLS[6][1]
        self.assertEqual(first.connection_ids, (SERVER_CID,))
        self.assertEqual(second.connection_ids, ())
        self.assertIsNone(second.match(record[11:]))
        for name, kwargs in (('a fresh instance', {'__context__': DTLSContext()}), ('no context', {})):
            with self.subTest(parse=name), \
                    self.assertRaisesRegex(ProtocolError, 'no connection ID length is known'):
                DTLS(record, len(record), **kwargs)

    #: The Mbed TLS ClientHello, asking for ``d1d2d3d4`` instead, so that an
    #: extraction of it holds an instance of its own.
    OTHER_HELLO = (True, MBEDTLS[0][1].replace(CLIENT_CID, bytes.fromhex('d1d2d3d4')))

    def test_consecutive_extractions_without_a_context_share_nothing(self) -> None:
        """A CID record whose hellos were in the previous extraction stays raw."""
        first = self._extract(MBEDTLS)
        self.assertEqual(str(first.frame[6].protochain), 'Ethernet:IPv4:UDP:DTLS 1.2')
        for name, datagrams in (('no hellos', (MBEDTLS[6],)),
                                ('a hello asking for another ID', (self.OTHER_HELLO, MBEDTLS[6]))):
            with self.subTest(second=name):
                second = self._extract(datagrams)
                self.assertEqual(str(second.frame[-1].protochain), 'Ethernet:IPv4:UDP:Raw')

    def test_concurrent_extractions_without_a_context_share_nothing(self) -> None:
        """The CID-record extraction runs in its own thread, after the other has learned."""
        learned = threading.Event()
        chains = {}  # type: dict[str, str]

        def run(name: str, datagrams: 'tuple', wait: bool) -> None:
            if wait:
                learned.wait(60)
            chains[name] = str(self._extract(datagrams).frame[-1].protochain)
            learned.set()

        threads = [threading.Thread(target=run, args=('handshake', MBEDTLS[:7], False)),
                   threading.Thread(target=run, args=('record', (self.OTHER_HELLO, MBEDTLS[6]), True))]
        for thread in reversed(threads):
            thread.start()
        for thread in threads:
            thread.join(120)
        self.assertEqual(chains, {'handshake': 'Ethernet:IPv4:UDP:DTLS 1.2',
                                  'record': 'Ethernet:IPv4:UDP:Raw'})

    def test_a_reused_caller_instance_keeps_its_ids(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext

        context = DTLSContext()
        self._extract(MBEDTLS, context=context)
        self.assertEqual(context.connection_ids, (CLIENT_CID, SERVER_CID))

        again = self._extract((MBEDTLS[6],), context=context)
        self.assertEqual(str(again.frame[0].protochain), 'Ethernet:IPv4:UDP:DTLS 1.2')
        self.assertEqual(_cid_layers(again.frame[0]['UDP'].payload), TSHARK[6][1])

        for name, datagrams in (('no hellos', (MBEDTLS[6],)),
                                ('a hello asking for another ID', (self.OTHER_HELLO, MBEDTLS[6]))):
            with self.subTest(fresh=name):
                fresh = self._extract(datagrams, context=DTLSContext())
                self.assertEqual(str(fresh.frame[-1].protochain), 'Ethernet:IPv4:UDP:Raw')

    def test_a_constructed_payload_registers_on_the_instance_in_use(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        def build(**kwargs: 'Any') -> 'Any':
            inner = DTLS(content_type=ContentType.tls12_cid, epoch=1, sequence_number=0, cid=SERVER_CID,
                         content=bytes(range(32)))
            return DTLS(content_type=ContentType.change_cipher_spec, epoch=0, sequence_number=3,
                        content=b'\x01', payload=inner, **kwargs)

        context = DTLSContext()
        self.assertEqual(str(build(__context__=context).protochain), 'DTLS 1.2:DTLS 1.2')
        self.assertEqual(context.connection_ids, (SERVER_CID,))

        own = build()
        self.assertEqual(own.context.match(['DTLS'], DTLSContext).connection_ids, (SERVER_CID,))
        self.assertEqual(DTLSContext().connection_ids, ())
        record = _cid_record(SERVER_CID, bytes(range(32)), sequence_number=0)
        with self.assertRaisesRegex(ProtocolError, 'no connection ID length is known'):
            DTLS(record, len(record))


class QuietRefusalTests(unittest.TestCase):
    """A record whose connection ID is unknown is ``Raw``, quietly, on dispatch."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
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

        for index in range(6, 10):
            from_client, payload = MBEDTLS[index]
            with self.subTest(datagram=index + 1):
                datagram = _udp(payload, from_client)
                with capture(logger) as package, capture(exceptions.logger) as module:
                    proto = UDP(datagram, len(datagram))
                self.assertEqual(str(proto.protochain), 'UDP:Raw')
                self.assertIs(type(proto.payload), Raw)
                self.assertRegex(str(proto.payload.info.error),
                                 r'^DTLS: invalid format: no connection ID length is known')
                self.assertEqual(package.messages + module.messages, [])
                self.assertIs(sys.excepthook, self.sys_sentinel)
                self.assertIs(threading.excepthook, self.threading_sentinel)
                self.assertEqual(bytes(UDP.from_data(proto.info)).hex(), datagram.hex())

    def test_a_direct_parse_raises(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        wire = MBEDTLS[6][1]
        with self.assertRaisesRegex(ProtocolError, 'no connection ID length is known'):
            DTLS(wire, len(wire))


class ResolutionTests(unittest.TestCase):
    """How ``DTLSContext`` finds a record's connection ID length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_learned_id_comes_before_cid_length(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        wire = MBEDTLS[6][1]
        parsed = DTLS(wire, len(wire), __context__=DTLSContext(SERVER_CID, cid_length=4))
        self.assertEqual(parsed.info.cid, SERVER_CID)
        self.assertEqual(parsed.info.length, 80)

    def test_the_longest_id_whose_record_fits(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        fragment = b'\xff\xff' + bytes(14)
        for name, cid, ids in (
                ('both ids open it, the longer fits', b'\xab\xcd\xef\x01', (b'\xab', b'\xab\xcd\xef\x01')),
                ('the longer opens it but does not fit', b'\xab', (b'\xab', b'\xab\x00\x10')),
        ):
            with self.subTest(case=name):
                wire = _cid_record(cid, fragment)
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(*ids))
                self.assertEqual((parsed.info.cid, parsed.info.content), (cid, fragment))
                self.assertEqual(parsed.length, 13 + len(cid))

    def test_a_record_no_candidate_fits_reports_its_overrun(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        wire = _cid_record(SERVER_CID, bytes(16))[:-1]
        self.assertEqual(DTLSContext(SERVER_CID).match(wire[11:]), len(SERVER_CID))
        with warnings.catch_warnings(), \
                self.assertRaisesRegex(ProtocolError, r'^DTLS 1\.2: invalid format: record length 16 runs past'):
            warnings.simplefilter('ignore')  # the schema's short read, as for a legacy record
            DTLS(wire, len(wire), __context__=DTLSContext(SERVER_CID))

    def test_only_dtls_1_2_carries_tls12_cid(self) -> None:
        """RFC 9146 section 10.3 applies the content type to DTLS 1.2 alone."""
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        wire = _cid_record(SERVER_CID, bytes(16), version=b'\xfe\xff')
        context = DTLSContext(SERVER_CID)
        with self.assertRaisesRegex(ProtocolError, r'^DTLS: invalid format: legacy record version 0xfeff'):
            DTLS(wire, len(wire), __context__=context)
        parsed = DTLS(CCS + wire, len(CCS + wire), __context__=context)
        self.assertEqual(str(parsed.protochain), 'DTLS 1.2:Raw')
        self.assertIsNone(parsed.payload.info.error)

    def test_an_empty_id_is_not_learned(self) -> None:
        """A zero-length ``connection_id`` asks for no ID (RFC 9146 section 3)."""
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        # An empty ``connection_id``, then an unknown empty extension (0xFFCE),
        # in the 9 octets the vector's own extension takes.
        wire = MBEDTLS[0][1].replace(bytes.fromhex('0036000504c1c2c3c4'), bytes.fromhex('0036000100ffce0000'))
        parsed = DTLS(wire, len(wire))
        self.assertIsNone(parsed.context.match(['DTLS'], DTLSContext))
        self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

    def test_a_context_of_another_type_is_left_alone(self) -> None:
        from pcapkit.corekit.context import ContextRegistry, ProtocolContext
        from pcapkit.protocols.application.dtls import DTLS

        class Other(ProtocolContext):
            """A context some other code keeps under ``DTLS``."""

            @classmethod
            def protocol(cls) -> 'tuple[str, ...]':
                return ('DTLS',)

        registry = ContextRegistry(Other())
        wire = MBEDTLS[3][1]
        DTLS(wire, len(wire), __context__=registry)
        self.assertIsInstance(registry['DTLS'], Other)
        self.assertEqual(len(registry), 1)

    def test_the_context_validates_what_it_is_given(self) -> None:
        from pcapkit.protocols.application.dtls import DTLSContext
        from pcapkit.utilities.exceptions import ProtocolError

        for name, args, kwargs in (('an empty id', (b'',), {}), ('a 256-octet id', (bytes(256),), {}),
                                   ('a str id', ('ab',), {}), ('cid_length 0', (), {'cid_length': 0}),
                                   ('cid_length 256', (), {'cid_length': 256}),
                                   ('cid_length True', (), {'cid_length': True}),
                                   ('cid_length a str', (), {'cid_length': '8'})):
            with self.subTest(case=name), self.assertRaises(ProtocolError):
                DTLSContext(*args, **kwargs)  # type: ignore[arg-type]
        context = DTLSContext(b'\x01', bytes(255), b'\x01', cid_length=255)
        self.assertEqual(context.connection_ids, (b'\x01', bytes(255)))
        self.assertEqual(context.cid_length, 255)
        self.assertEqual(context.protocol(), ('DTLS',))
        self.assertIsNone(DTLSContext().match(bytes(20)))


class ChainTests(unittest.TestCase):
    """A ``tls12_cid`` record chains with the records sharing its datagram (#2535)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_records_either_side_of_one_are_further_layers(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext

        record = _cid_record(CLIENT_CID, bytes(range(24)))
        for name, wire, chain in (('after a legacy record', CCS + record, 'DTLS 1.2:DTLS 1.2'),
                                  ('before a legacy record', record + CCS, 'DTLS 1.2:DTLS 1.2'),
                                  ('two of them', record + record, 'DTLS 1.2:DTLS 1.2')):
            with self.subTest(case=name):
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(CLIENT_CID))
                self.assertEqual(str(parsed.protochain), chain)
                layers, _ = _dtls_layers(parsed)
                self.assertEqual(sum(1 for layer in layers if layer.info.content_type == 25),
                                 wire.count(b'\x19\xfe\xfd'))
                self.assertEqual(bytes(DTLS.from_data(parsed.info)).hex(), wire.hex())

    def test_an_unknown_id_after_a_record_stays_raw_without_an_error(self) -> None:
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.protocols.misc.raw import Raw

        record = _cid_record(CLIENT_CID, bytes(range(24)))
        parsed = DTLS(CCS + record, len(CCS + record))
        self.assertEqual(str(parsed.protochain), 'DTLS 1.2:Raw')
        self.assertIs(type(parsed.payload), Raw)
        self.assertEqual(bytes(parsed.payload), record)
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
        for index, (from_client, payload) in enumerate(MBEDTLS, 1):
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
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS, DTLSContext
        from pcapkit.protocols.data.application.dtls import DTLSCIDCiphertext

        for index in (4, 5, 6, 7):
            wire = MBEDTLS[index][1]
            with self.subTest(datagram=index + 1):
                parsed = DTLS(wire, len(wire), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
                maker = object.__new__(DTLS)
                schema = b''  # type: object
                for layer in reversed(_dtls_layers(parsed)[0]):
                    info = layer.info
                    extra = {'cid': info.cid} if isinstance(info, DTLSCIDCiphertext) else {}
                    schema = maker.make(content_type=info.content_type, version=info.version, epoch=info.epoch,
                                        sequence_number=info.sequence_number, content=info.content,
                                        payload=schema, **extra)
                made = bytes(schema)  # type: ignore[call-overload]
                self.assertEqual(made.hex(), wire.hex())

                again = DTLS(made, len(made), __context__=DTLSContext(CLIENT_CID, SERVER_CID))
                self.assertEqual(str(again.protochain), str(parsed.protochain))
                self.assertEqual(_cid_layers(again), _cid_layers(parsed))

        made = DTLS(content_type=ContentType.tls12_cid, epoch=3, sequence_number=7, cid=b'\x0a\x0b',
                    content=bytes(range(20)))
        self.assertEqual(bytes(made).hex(), _cid_record(b'\x0a\x0b', bytes(range(20)), epoch=3,
                                                        sequence_number=7).hex())
        self.assertEqual((made.alias, made.length, made.info.cid, made.info.length), ('DTLS 1.2', 15, b'\x0a\x0b', 20))

    def test_a_record_made_with_a_payload_parses_it_again(self) -> None:
        """The constructed payload's connection IDs are registered for its parse."""
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS

        inner = DTLS(content_type=ContentType.tls12_cid, epoch=1, sequence_number=0, cid=SERVER_CID,
                     content=bytes(range(32)))
        outer = DTLS(content_type=ContentType.change_cipher_spec, epoch=0, sequence_number=3,
                     content=b'\x01', payload=inner)
        self.assertEqual(str(outer.protochain), 'DTLS 1.2:DTLS 1.2')
        self.assertEqual(_cid_layers(outer), ((SERVER_CID, 1, 0, 32),))

    def test_make_refuses_a_misplaced_or_invalid_id(self) -> None:
        from pcapkit.const.tls.content_type import ContentType
        from pcapkit.protocols.application.dtls import DTLS
        from pcapkit.utilities.exceptions import ProtocolError

        maker = object.__new__(DTLS)
        for name, kwargs in (('none for tls12_cid', {'content_type': ContentType.tls12_cid}),
                             ('an empty one', {'content_type': ContentType.tls12_cid, 'cid': b''}),
                             ('a 256-octet one', {'content_type': ContentType.tls12_cid, 'cid': bytes(256)}),
                             ('one on application_data', {'content_type': ContentType.application_data,
                                                          'cid': b'\x01'}),
                             ('one on a unified header', {'ciphertext': True, 'content': bytes(16),
                                                          'cid': b'\x01'})):
            with self.subTest(case=name), self.assertRaisesRegex(ProtocolError, 'invalid connection ID'):
                maker.make(**kwargs)


if __name__ == '__main__':
    unittest.main()
