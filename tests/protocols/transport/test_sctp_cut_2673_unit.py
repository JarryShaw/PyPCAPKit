# -*- coding: utf-8 -*-
"""An SCTP packet cut short of the length its envelope declares rebuilds as captured (#2673).

SCTP has no length field, so a capture cut short leaves the IPv4 Total Length or IPv6
Payload Length declaring more than the octets present. The SCTP schema sized its chunk
area by that declared length, so ``Schema.unpack`` recorded the data as ending inside
``chunks`` while ``ChunkListField`` handed the octets after the last whole chunk to
``trailer``. Packing then cut the chunks back and dropped the trailer: 13 octets in, 12
out. ``bytes(schema)`` counted the trailer's octets twice as well.

Every case builds its own octets.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): a sweep that cuts each packet at every offset.
__tier__ = 'LATEST'


def _tlv(code: int, value: bytes) -> bytes:
    """A parameter or error cause, its Length excluding the padding (RFC 9260, section 3.2.1)."""
    body = struct.pack('!HH', code, 4 + len(value)) + value
    return body + bytes(-len(body) % 4)


def _chunk(code: int, flags: int, value: bytes) -> bytes:
    """A chunk, its Length excluding the padding (RFC 9260, section 3.2)."""
    body = struct.pack('!BBH', code, flags, 4 + len(value)) + value
    return body + bytes(-len(body) % 4)


def _packet(*chunks: bytes) -> bytes:
    """An SCTP packet from port 5000 to 5001 carrying ``chunks``, with its CRC32c."""
    from pcapkit.protocols.transport.sctp import SCTP

    raw = struct.pack('!HHI', 5000, 5001, 0x11223344) + bytes(4) + b''.join(chunks)
    return raw[:8] + SCTP.calculate_checksum(raw) + raw[12:]


#: INIT fixed part (RFC 9260, section 3.3.2): initiate tag, a_rwnd, outbound and
#: inbound streams, initial TSN.
INIT_HEAD = struct.pack('!IIHHI', 0xaabbccdd, 65536, 10, 10, 1)
#: INIT ACK fixed part, laid out as INIT's (RFC 9260, section 3.3.3).
INIT_ACK_HEAD = struct.pack('!IIHHI', 1, 2, 3, 4, 5)
#: DATA chunk TSN, stream identifier, stream sequence number and PPID (RFC 9260,
#: section 3.3.1).
DATA_HEAD = struct.pack('!IHHI', 7, 1, 2, 0)


def _shapes() -> 'dict[str, tuple[bytes, list[int]]]':
    """Packets of several chunks, each with parameters or causes, and their chunk types."""
    return {
        # INIT with IPv4 Address (5), Supported Address Types (12), Host Name Address
        # (11) and Cookie Preservative (9); DATA (0) of five octets; HEARTBEAT (4)
        # with Heartbeat Info (1)
        'init-data-heartbeat': (_packet(
            _chunk(1, 0, INIT_HEAD + _tlv(5, bytes.fromhex('c0000201')) + _tlv(12, b'\x00\x05')
                   + _tlv(11, b'localhost\x00') + _tlv(9, struct.pack('!I', 1000))),
            _chunk(0, 0x03, DATA_HEAD + b'abcde'),
            _chunk(4, 0, _tlv(1, b'xyz'))), [1, 0, 4]),
        # SACK (3) with two gap ack blocks and a duplicate TSN; ERROR (9) with Stale
        # Cookie (3) and Unrecognized Chunk Type (6); ABORT (6) with Invalid Stream
        # Identifier (1), Missing Mandatory Parameter (2) and User-Initiated Abort (12)
        'sack-error-abort': (_packet(
            _chunk(3, 0, struct.pack('!IIHHHHHHI', 9, 4096, 2, 1, 1, 2, 4, 5, 8)),
            _chunk(9, 0, _tlv(3, struct.pack('!I', 500)) + _tlv(6, b'ab')),
            _chunk(6, 0x01, _tlv(1, b'\x00\x02\x00\x00') + _tlv(2, struct.pack('!IHH', 2, 5, 6))
                   + _tlv(12, b'bye'))), [3, 9, 6]),
        # INIT ACK with State Cookie (7), Unrecognized Parameter (8) and IPv6 Address
        # (6); COOKIE ECHO (10); SHUTDOWN (7)
        'init-ack-cookie-shutdown': (_packet(
            _chunk(2, 0, INIT_ACK_HEAD + _tlv(7, b'\x01\x02\x03\x04\x05')
                   + _tlv(8, _tlv(0x8001, b'\x09' * 4)) + _tlv(6, bytes(15) + b'\x01')),
            _chunk(10, 0, b'cookie'),
            _chunk(7, 0, struct.pack('!I', 77))), [2, 10, 7]),
        # one DATA chunk of three octets, as the option-coverage capture carries
        'data': (_packet(_chunk(0, 0x03, DATA_HEAD + b'\x01\x02\x03')), [0]),
    }


class SCTPCutTests(unittest.TestCase):
    """SCTP packets cut at every offset, through an envelope and on their own."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        # a cut header warns that its length runs past the data, which is the point
        warnings.simplefilter('ignore')

    def assert_rebuilds(self, sctp: 'object', raw: bytes) -> None:
        """``sctp`` holds ``raw`` and rebuilds it three ways."""
        from pcapkit.protocols.transport.sctp import SCTP

        assert isinstance(sctp, SCTP)
        self.assertEqual(sctp.data, raw)
        self.assertEqual(bytes(sctp.__header__), raw)
        self.assertEqual(SCTP.from_data(sctp.info).data, raw)
        self.assertEqual(SCTP.from_data(sctp.info.to_dict()).data, raw)

    def test_cut_through_ipv4_at_every_offset(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            packet = wire.ipv4(whole, proto=132)
            for keep in range(12, len(whole) + 1):
                raw = packet[:20 + keep]
                with self.subTest(case=name, keep=keep):
                    ipv4 = IPv4(raw, len(raw))
                    self.assertIsInstance(ipv4.payload, SCTP)
                    self.assert_rebuilds(ipv4.payload, whole[:keep])
                    self.assertEqual(IPv4.from_data(ipv4.info).data, raw)
                    self.assertEqual(IPv4.from_data(ipv4.info.to_dict()).data, raw)

    def test_cut_through_ipv6_at_every_offset(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            packet = wire.ipv6(whole, nxt=132)
            for keep in range(12, len(whole) + 1):
                raw = packet[:40 + keep]
                with self.subTest(case=name, keep=keep):
                    ipv6 = IPv6(raw, len(raw))
                    self.assertIsInstance(ipv6.payload, SCTP)
                    self.assert_rebuilds(ipv6.payload, whole[:keep])
                    self.assertEqual(IPv6.from_data(ipv6.info).data, raw)
                    self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, raw)

    def test_cut_with_the_whole_length_declared(self) -> None:
        # the envelope's case, with no envelope: the length given exceeds the data
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            for keep in range(12, len(whole) + 1):
                raw = whole[:keep]
                with self.subTest(case=name, keep=keep):
                    self.assert_rebuilds(SCTP(raw, len(whole)), raw)
                    self.assert_rebuilds(SCTP(io.BytesIO(raw), len(whole)), raw)

    def test_cut_with_its_own_length_is_the_control(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            for keep in range(12, len(whole) + 1):
                raw = whole[:keep]
                with self.subTest(case=name, keep=keep):
                    self.assert_rebuilds(SCTP(raw, len(raw)), raw)

    def test_a_chunk_cut_short_is_the_trailer(self) -> None:
        # ten octets into the DATA chunk, after the whole INIT
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.internet.ipv4 import IPv4

        whole, _ = _shapes()['init-data-heartbeat']
        init = 4 + len(INIT_HEAD) + 8 + 8 + 16 + 8
        raw = wire.ipv4(whole, proto=132)[:20 + 12 + init + 10]
        sctp = IPv4(raw, len(raw)).payload

        self.assertNotIn('__short_read__', sctp.info)
        self.assertEqual(sctp.info.trailer, whole[12 + init:12 + init + 10])
        self.assertEqual(list(sctp.info.chunks), [Chunk.Initiation])
        chunk = sctp.info.chunks[Chunk.Initiation]
        # RFC 9260, section 3.3.2: the INIT Length counts every parameter, and the
        # parameter Lengths exclude their padding (section 3.2.1)
        self.assertEqual(chunk.length, init)
        self.assertEqual([param.length for param in chunk.parameters.values()], [8, 6, 14, 8])

    def test_a_cut_inside_the_last_padding_is_a_short_read(self) -> None:
        # one of the DATA chunk's three padding octets, ahead of the HEARTBEAT
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.internet.ipv4 import IPv4

        whole, _ = _shapes()['init-data-heartbeat']
        init = 4 + len(INIT_HEAD) + 8 + 8 + 16 + 8
        data = 4 + len(DATA_HEAD) + 5
        raw = wire.ipv4(whole, proto=132)[:20 + 12 + init + data + 1]
        sctp = IPv4(raw, len(raw)).payload

        self.assertEqual(sctp.info['__short_read__'], ('chunks', init + data + 1))
        self.assertNotIn('trailer', sctp.info)
        self.assertEqual(list(sctp.info.chunks), [Chunk.Initiation, Chunk.Payload_Data])
        self.assertEqual(sctp.info.chunks[Chunk.Payload_Data].length, data)
        self.assertEqual(sctp.info.chunks[Chunk.Payload_Data].padding, b'\x00')
        self.assert_rebuilds(sctp, whole[:12 + init + data + 1])

    def test_schema_reads_no_further_than_the_octets_present(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            for keep in range(12, len(whole) + 1):
                raw = whole[:keep]
                with self.subTest(case=name, keep=keep):
                    schema = SCTP.unpack(raw, len(whole))
                    self.assertEqual(bytes(schema), raw)
                    self.assertEqual(schema.pack(), raw)

                    # a stream read from the middle, with the octets ahead left alone
                    stream = io.BytesIO(b'\xff' * 3 + raw)
                    stream.seek(3)
                    schema = SCTP.unpack(stream, len(whole))
                    self.assertEqual(stream.tell(), 3 + keep)
                    self.assertEqual(bytes(schema), raw)
                    self.assertEqual(schema.pack(), raw)

    def test_schema_given_no_length_past_the_data_is_the_control(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP

        for name, (whole, _) in _shapes().items():
            for given in (len(whole), None):
                with self.subTest(case=name, length=given):
                    data = whole + b'\xee' * 4 if given is not None else whole
                    schema = SCTP.unpack(data, given)
                    self.assertEqual(schema.trailer, b'')
                    self.assertNotIn('__short_read__', schema.__dict__)
                    self.assertEqual(schema.pack(), whole)

    def test_whole_packets_are_the_control(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.transport.sctp import SCTP

        for name, (whole, types) in _shapes().items():
            for via, sctp in (('IPv4', IPv4(wire.ipv4(whole, proto=132)).payload),
                              ('SCTP', SCTP(whole, len(whole)))):
                with self.subTest(case=name, via=via):
                    self.assertNotIn('__short_read__', sctp.info)
                    self.assertNotIn('trailer', sctp.info)
                    self.assertTrue(sctp.checksum_valid)
                    self.assertEqual([int(code) for code in sctp.info.chunks], types)
                    self.assert_rebuilds(sctp, whole)


if __name__ == '__main__':
    unittest.main()
