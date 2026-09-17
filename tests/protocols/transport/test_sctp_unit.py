"""Unit tests for :mod:`pcapkit.protocols.transport.sctp`.

Every chunk type is exercised three ways, because each catches a different class
of mistake:

* **Round trip** -- ``make`` the chunk, pack it, read it back, and compare field
  by field. This catches a constructor and a parser that disagree, but it cannot
  catch the two of them being wrong in the same way.
* **Wire conformance** -- parse a byte string written out by hand from the packet
  diagrams in :rfc:`9260`, and assert the field values those diagrams imply.
  This is what catches a misread of the RFC, which a round trip cannot.
* **Cross-check against scapy** -- build the same chunk with
  :mod:`scapy.layers.sctp`, write it to a capture, and assert :mod:`pcapkit`
  reads the values scapy put in. This is the independent check: it catches a
  misreading that happens to be self-consistent across our own reader and
  writer, and it catches the byte order of the CRC32c checksum.

"""

from __future__ import annotations

import contextlib
import importlib.util
import unittest
from unittest import mock

from tests._support import close_extractor

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_SCAPY = importlib.util.find_spec('scapy') is not None


def bitfield_packs_zero_bits() -> bool:
    """Whether :class:`~pcapkit.corekit.fields.strings.BitField` packs a clear bit.

    ``BitField.pre_process`` seeds its working buffer with NUL bytes and then
    writes the ASCII characters ``b'0'`` and ``b'1'`` into it, before collapsing
    the buffer by truth-testing each byte -- and ``b'0'`` is ``0x30``, which is
    truthy. Every named bit therefore comes out **set** regardless of its value,
    so a flag word constructed with any bit clear does not survive a round trip.

    That is a library-wide defect in :mod:`pcapkit.corekit`, not an SCTP one, and
    it is being fixed separately. The tests that need clear bits on the
    *construction* side are gated on this probe so that they start running of
    their own accord once the fix lands. Parsing is unaffected --
    ``BitField.post_process`` is correct -- so the wire-conformance and scapy
    cross-check tests below exercise mixed flags unconditionally.

    """
    from pcapkit.corekit.fields.strings import BitField

    field = BitField(length=1, namespace={'a': (0, 1), 'b': (7, 1)})
    return field.pre_process({'a': 0, 'b': 1}, {}) == b'\x01'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SCTPUnitTests(unittest.TestCase):
    # NOTE: Unlike the sibling TCP/UDP unit tests, this module does not purge
    # and re-import :mod:`pcapkit` per test: nothing here depends on import-time
    # behaviour, and the re-import costs several seconds a test. Every test that
    # mutates a class-level registry restores it -- ``__proto__`` through the
    # ``_proto_registry`` helper below, the sub-registries in a ``finally``.

    ##########################################################################
    # Helpers.
    ##########################################################################

    @staticmethod
    def _packet(raw: bytes):
        """Parse ``raw`` as a whole SCTP packet."""
        import io

        from pcapkit.protocols.transport.sctp import SCTP

        return SCTP(io.BytesIO(raw), len(raw))

    @staticmethod
    @contextlib.contextmanager
    def _proto_registry():
        """Restore ``SCTP.__proto__`` on the way out, defaults included.

        ``SCTP.__proto__.clear()`` was a sound teardown while the registry
        started empty. It is not one now: NGAP is registered on PPIDs 60 and 66
        by default, and clearing the registry leaves every later test in the
        process running against a registry that no import repopulates -- an
        order-dependent failure that only appears in whichever test happens to
        run second.

        """
        from pcapkit.protocols.transport.sctp import SCTP

        saved = dict(SCTP.__proto__)
        try:
            yield SCTP.__proto__
        finally:
            SCTP.__proto__.clear()
            SCTP.__proto__.update(saved)

    @staticmethod
    def _build(chunks, **kwargs) -> bytes:
        """Construct a whole SCTP packet from a list of chunk specifications."""
        from pcapkit.protocols.transport.sctp import SCTP

        proto = SCTP.__new__(SCTP)
        params = {'srcport': 9899, 'dstport': 38412, 'vtag': 0x11223344}
        params.update(kwargs)
        return SCTP.make(proto, chunks=chunks, **params).pack()

    ##########################################################################
    # Common header and CRC32c checksum.
    ##########################################################################

    def test_crc32c_matches_the_rfc9260_appendix_a_table(self) -> None:
        from pcapkit.protocols.transport.sctp import CRC32C_TABLE, SCTP

        # Spot values quoted verbatim from the crc_c[] table in RFC 9260
        # Appendix A, which is what pins the polynomial and the reflection.
        self.assertEqual(len(CRC32C_TABLE), 256)
        self.assertEqual(CRC32C_TABLE[0], 0x00000000)
        self.assertEqual(CRC32C_TABLE[1], 0xF26B8303)
        self.assertEqual(CRC32C_TABLE[2], 0xE13B70F7)
        self.assertEqual(CRC32C_TABLE[3], 0x1350F3F4)
        self.assertEqual(CRC32C_TABLE[16], 0x105EC76F)

        # The CRC32c of the empty string is 0, and of b'123456789' is the
        # Castagnoli check value 0xE3069283.
        self.assertEqual(SCTP.crc32c(b''), 0x00000000)
        self.assertEqual(SCTP.crc32c(b'123456789'), 0xE3069283)

    def test_common_header_wire_conformance(self) -> None:
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.const.sctp.chunk import Chunk

        # RFC 9260 section 3.1: source port, destination port, verification
        # tag, checksum -- then chunks. Followed by a COOKIE ACK chunk, which
        # is the shortest chunk there is (length 4, no value).
        raw = bytes.fromhex(
            '26ab'      # source port      = 9899
            '960c'      # destination port = 38412
            '11223344'  # verification tag
            '00000000'  # checksum, zeroed
            '0b000004'  # COOKIE ACK chunk: type 11, flags 0, length 4
        )
        proto = self._packet(raw)
        info = proto.info

        self.assertEqual(info.srcport.port, 9899)
        self.assertEqual(info.dstport.port, 38412)
        self.assertEqual(info.srcport, AppType.get(9899, proto=TransportProtocol.sctp))
        self.assertEqual(info.vtag, 0x11223344)
        self.assertEqual(info.chksum, b'\x00\x00\x00\x00')
        self.assertEqual(list(info.chunks.keys()), [Chunk.Cookie_Acknowledgement])

        self.assertEqual(proto.length, 12)
        self.assertEqual(proto.__length_hint__(), 12)
        self.assertEqual(proto.name, 'Stream Control Transmission Protocol')
        self.assertEqual(proto.src.port, 9899)
        self.assertEqual(proto.dst.port, 38412)

        # A zeroed checksum is not the CRC32c of this packet.
        self.assertFalse(proto.checksum_valid)

    def test_constructed_ports_carry_the_same_type_as_parsed_ones(self) -> None:
        """A bare :obj:`int` port is resolved on construction, not left as it is.

        SCTP never tripped over this the way TCP and UDP did -- it keys its next
        layer on the DATA chunk's PPID rather than on a port, so it never read
        ``srcport.port`` off the schema -- but it did leave a constructed packet
        holding an :obj:`int` where a parsed one holds an
        :class:`~pcapkit.const.reg.apptype.AppType`.

        """
        from pcapkit.const.reg.apptype import AppType, TransportProtocol
        from pcapkit.protocols.transport.sctp import SCTP

        proto = SCTP.__new__(SCTP)
        schema = SCTP.make(proto, srcport=9899, dstport=38412, vtag=0x11223344)

        self.assertIsInstance(schema.srcport, AppType)
        self.assertEqual(schema.srcport.port, 9899)
        self.assertEqual(schema.srcport,
                         AppType.get(9899, proto=TransportProtocol.sctp))
        self.assertEqual(schema.dstport.port, 38412)
        self.assertEqual(schema.pack()[:4], b'\x26\xab\x96\x0c')

    def test_checksum_is_the_little_endian_crc32c_of_the_zeroed_packet(self) -> None:
        import struct

        from pcapkit.protocols.transport.sctp import SCTP

        raw = self._build([])
        self.assertEqual(len(raw), 12)

        zeroed = raw[:8] + b'\x00\x00\x00\x00'
        expect = struct.pack('<I', SCTP.crc32c(zeroed))

        # RFC 9260 Appendix A byte-swaps the reflected remainder and then writes
        # it with htonl(), which is the same thing as writing the un-swapped
        # value little-endian. Getting this backwards is the classic SCTP bug,
        # so assert the orientation rather than just self-consistency.
        self.assertEqual(raw[8:12], expect)
        self.assertNotEqual(raw[8:12], struct.pack('>I', SCTP.crc32c(zeroed)))

        self.assertTrue(SCTP.validate_checksum(raw))
        self.assertEqual(SCTP.calculate_checksum(raw), raw[8:12])
        # calculate_checksum must ignore whatever is already in the field.
        self.assertEqual(SCTP.calculate_checksum(raw[:8] + b'\xff\xff\xff\xff'), raw[8:12])
        self.assertFalse(SCTP.validate_checksum(raw[:8] + b'\xff\xff\xff\xff'))

        self.assertTrue(self._packet(raw).checksum_valid)

    def test_checksum_helpers_reject_a_short_packet(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            SCTP.calculate_checksum(b'\x00' * 11)
        with self.assertRaises(ProtocolError):
            SCTP.validate_checksum(b'\x00' * 11)

    def test_index_is_the_iana_protocol_number(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.transport.sctp import SCTP

        self.assertEqual(SCTP.__index__(), TransType.SCTP)
        self.assertEqual(int(SCTP.__index__()), 132)

    def test_internet_dispatches_protocol_132_to_sctp(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.internet.internet import Internet
        from pcapkit.protocols.transport.sctp import SCTP

        entry = Internet.__proto__[TransType.SCTP]
        if isinstance(entry, ModuleDescriptor):
            entry = entry.klass
        self.assertIs(entry, SCTP)

    ##########################################################################
    # Chunks: round trip.
    ##########################################################################

    def test_every_chunk_type_round_trips(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        # Every flag in the flag-carrying chunks is set, so that the tests are
        # not blocked on the BitField construction defect described by
        # :func:`bitfield_packs_zero_bits`; mixed flags are covered on the
        # parsing side by the wire-conformance and scapy tests below, and on the
        # construction side by the gated test that follows this one.
        cases = [
            (Chunk.Payload_Data,
             dict(I=True, U=True, B=True, E=True, tsn=0x0A0B0C0D, stream_id=1,
                  stream_seq=2, ppid=60, data=b'ngap-pdu'),
             dict(length=24, tsn=0x0A0B0C0D, stream_id=1, stream_seq=2, ppid=60,
                  data=b'ngap-pdu')),
            (Chunk.Initiation,
             dict(init_tag=0x11223344, a_rwnd=106496, outbound_streams=10,
                  inbound_streams=10, init_tsn=0x55667788,
                  parameters=[(Parameter.IPv4_Address, {'address': '10.0.0.1'})]),
             dict(length=28, init_tag=0x11223344, a_rwnd=106496, outbound_streams=10,
                  inbound_streams=10, init_tsn=0x55667788)),
            (Chunk.Initiation_Acknowledgement,
             dict(init_tag=0x99AABBCC, a_rwnd=4660, outbound_streams=3,
                  inbound_streams=4, init_tsn=7,
                  parameters=[(Parameter.State_Cookie, {'cookie': b'\xde\xad\xbe\xef\x01'})]),
             dict(length=32, init_tag=0x99AABBCC, a_rwnd=4660, outbound_streams=3,
                  inbound_streams=4, init_tsn=7)),
            (Chunk.Selective_Acknowledgement,
             dict(cum_tsn_ack=12, a_rwnd=4660, gap_blocks=[(2, 3), (5, 5)],
                  dup_tsn=[19, 19]),
             dict(length=32, cum_tsn_ack=12, a_rwnd=4660, num_gap_blocks=2,
                  num_dup_tsn=2, dup_tsn=(19, 19))),
            (Chunk.Heartbeat_Request,
             dict(parameters=[(Parameter.Heartbeat_Info, {'info': b'\xca\xfe\xba\xbe'})]),
             dict(length=12)),
            (Chunk.Heartbeat_Acknowledgement,
             dict(parameters=[(Parameter.Heartbeat_Info, {'info': b'\xca\xfe\xba\xbe'})]),
             dict(length=12)),
            (Chunk.Abort,
             dict(T=True, error=[(CauseCode.User_Initiated_Abort, {'info': b'bye'})]),
             dict(length=12)),
            (Chunk.Shutdown,
             dict(cum_tsn_ack=0x0A0B0C10),
             dict(length=8, cum_tsn_ack=0x0A0B0C10)),
            (Chunk.Shutdown_Acknowledgement, {}, dict(length=4)),
            (Chunk.Operation_Error,
             dict(error=[(CauseCode.Invalid_Stream_Identifier, {'stream_id': 9})]),
             dict(length=12)),
            (Chunk.State_Cookie,
             dict(cookie=b'\xde\xad\xbe\xef\xfe\xed'),
             dict(length=10, cookie=b'\xde\xad\xbe\xef\xfe\xed')),
            (Chunk.Cookie_Acknowledgement, {}, dict(length=4)),
            (Chunk.Shutdown_Complete, dict(T=True), dict(length=4)),
        ]

        for code, args, expect in cases:
            with self.subTest(chunk=code.name):
                raw = self._build([(code, args)])
                # The whole packet is always a multiple of four bytes: each
                # chunk pads itself per RFC 9260 section 3.2.
                self.assertEqual(len(raw) % 4, 0)

                proto = self._packet(raw)
                self.assertTrue(proto.checksum_valid)

                chunk = proto.info.chunks[code]
                self.assertEqual(chunk.type, code)
                for key, value in expect.items():
                    self.assertEqual(getattr(chunk, key), value,
                                     f'{code.name}.{key}')

        # Flags survive the round trip when every named bit is set.
        raw = self._build([(Chunk.Payload_Data,
                            dict(I=True, U=True, B=True, E=True, tsn=1, data=b'x'))])
        flags = self._packet(raw).info.chunks[Chunk.Payload_Data].flags
        self.assertTrue(flags.I and flags.U and flags.B and flags.E)

        raw = self._build([(Chunk.Abort, dict(T=True))])
        self.assertTrue(self._packet(raw).info.chunks[Chunk.Abort].flags.T)

        raw = self._build([(Chunk.Shutdown_Complete, dict(T=True))])
        self.assertTrue(self._packet(raw).info.chunks[Chunk.Shutdown_Complete].flags.T)

    def test_chunk_flags_round_trip_with_mixed_bits(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        if not bitfield_packs_zero_bits():
            self.skipTest('BitField.pre_process sets every named bit regardless '
                          'of value; see bitfield_packs_zero_bits()')

        raw = self._build([(Chunk.Payload_Data,
                            dict(I=False, U=False, B=True, E=True, tsn=1, data=b'x'))])
        flags = self._packet(raw).info.chunks[Chunk.Payload_Data].flags
        self.assertFalse(flags.I)
        self.assertFalse(flags.U)
        self.assertTrue(flags.B)
        self.assertTrue(flags.E)

        raw = self._build([(Chunk.Abort, dict(T=False))])
        self.assertFalse(self._packet(raw).info.chunks[Chunk.Abort].flags.T)

    def test_bundled_chunks_all_parse(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        raw = self._build([
            (Chunk.Selective_Acknowledgement, dict(cum_tsn_ack=5, a_rwnd=4660)),
            (Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=6,
                                      ppid=60, data=b'seven')),
            (Chunk.Cookie_Acknowledgement, {}),
        ])
        proto = self._packet(raw)
        self.assertTrue(proto.checksum_valid)
        self.assertEqual(list(proto.info.chunks.keys()),
                         [Chunk.Selective_Acknowledgement, Chunk.Payload_Data,
                          Chunk.Cookie_Acknowledgement])
        # A five-byte payload leaves the DATA chunk needing three bytes of
        # padding; the COOKIE ACK after it must still land on its type byte.
        self.assertEqual(proto.info.chunks[Chunk.Payload_Data].data, b'seven')
        self.assertEqual(proto.info.chunks[Chunk.Cookie_Acknowledgement].length, 4)

    def test_make_data_reconstructs_the_packet(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        raw = self._build([
            (Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=9,
                                      stream_id=1, stream_seq=2, ppid=60,
                                      data=b'payload')),
            (Chunk.Cookie_Acknowledgement, {}),
        ])
        proto = self._packet(raw)

        values = SCTP._make_data(proto.info)
        self.assertEqual(values['srcport'], proto.info.srcport)
        self.assertEqual(values['dstport'], proto.info.dstport)
        self.assertEqual(values['vtag'], 0x11223344)
        self.assertEqual(values['chksum'], proto.info.chksum)
        self.assertIs(values['chunks'], proto.info.chunks)
        # SCTP has no payload argument: user data lives inside a DATA chunk.
        self.assertNotIn('payload', values)

        rebuilt = SCTP.from_data(proto.info)
        self.assertEqual(bytes(rebuilt), raw)

    ##########################################################################
    # Chunks: wire conformance, from the RFC 9260 packet diagrams.
    ##########################################################################

    def test_chunk_wire_conformance(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        header = bytes.fromhex('26ab960c1122334400000000')

        # RFC 9260 section 3.3.1: type 0, Res|I|U|B|E, length, TSN, stream id,
        # stream sequence number, PPID, user data. Flags 0x03 is B|E, i.e. an
        # unfragmented message -- which pins B at bit 6 and E at bit 7.
        proto = self._packet(header + bytes.fromhex(
            '00' '03' '0018' '0a0b0c0d' '0001' '0002' '0000003c'
            '0015000800000400'))
        chunk = proto.info.chunks[Chunk.Payload_Data]
        self.assertEqual(chunk.length, 24)
        self.assertFalse(chunk.flags.I)
        self.assertFalse(chunk.flags.U)
        self.assertTrue(chunk.flags.B)
        self.assertTrue(chunk.flags.E)
        self.assertEqual(chunk.tsn, 0x0A0B0C0D)
        self.assertEqual(chunk.stream_id, 1)
        self.assertEqual(chunk.stream_seq, 2)
        self.assertEqual(chunk.ppid, 60)
        self.assertEqual(chunk.data, bytes.fromhex('0015000800000400'))

        # Flags 0x0c is I|U, which pins I at bit 4 and U at bit 5.
        proto = self._packet(header + bytes.fromhex(
            '00' '0c' '0011' '00000001' '0000' '0000' '00000000' '41000000'))
        chunk = proto.info.chunks[Chunk.Payload_Data]
        self.assertTrue(chunk.flags.I)
        self.assertTrue(chunk.flags.U)
        self.assertFalse(chunk.flags.B)
        self.assertFalse(chunk.flags.E)
        self.assertEqual(chunk.data, b'A')

        # RFC 9260 section 3.3.2: type 1, flags, length, initiate tag, a_rwnd,
        # outbound streams, inbound streams, initial TSN, then parameters.
        proto = self._packet(header + bytes.fromhex(
            '01' '00' '0024' '11223344' '0001a000' '000a' '000a' '55667788'
            '00050008' '0a000001'
            '000c0008' '0005' '0006'))
        chunk = proto.info.chunks[Chunk.Initiation]
        self.assertEqual(chunk.length, 36)
        self.assertEqual(chunk.init_tag, 0x11223344)
        self.assertEqual(chunk.a_rwnd, 106496)
        self.assertEqual(chunk.outbound_streams, 10)
        self.assertEqual(chunk.inbound_streams, 10)
        self.assertEqual(chunk.init_tsn, 0x55667788)
        self.assertEqual(list(chunk.parameters.keys()),
                         [Parameter.IPv4_Address, Parameter.Supported_Address_Types])

        # RFC 9260 section 3.3.3: same fixed fields as INIT, type 2.
        proto = self._packet(header + bytes.fromhex(
            '02' '00' '0020' '99aabbcc' '00001234' '0003' '0004' '00000007'
            '00070009' 'deadbeef01' '000000'))
        chunk = proto.info.chunks[Chunk.Initiation_Acknowledgement]
        self.assertEqual(chunk.init_tag, 0x99AABBCC)
        self.assertEqual(chunk.a_rwnd, 4660)
        self.assertEqual(chunk.outbound_streams, 3)
        self.assertEqual(chunk.inbound_streams, 4)
        self.assertEqual(chunk.init_tsn, 7)
        cookie = chunk.parameters[Parameter.State_Cookie]
        self.assertEqual(cookie.cookie, bytes.fromhex('deadbeef01'))

        # RFC 9260 section 3.3.4, using the worked example from that section:
        # cumulative TSN ack 12, a_rwnd 4660, two gap ack blocks (2..3 and
        # 5..5), no duplicates -- plus two duplicate TSNs of 19, from the
        # duplicate-TSN example immediately below it.
        proto = self._packet(header + bytes.fromhex(
            '03' '00' '0020' '0000000c' '00001234' '0002' '0002'
            '0002' '0003' '0005' '0005' '00000013' '00000013'))
        chunk = proto.info.chunks[Chunk.Selective_Acknowledgement]
        self.assertEqual(chunk.length, 32)
        self.assertEqual(chunk.cum_tsn_ack, 12)
        self.assertEqual(chunk.a_rwnd, 4660)
        self.assertEqual(chunk.num_gap_blocks, 2)
        self.assertEqual(chunk.num_dup_tsn, 2)
        self.assertEqual([(b.start, b.end) for b in chunk.gap_blocks], [(2, 3), (5, 5)])
        self.assertEqual(chunk.dup_tsn, (19, 19))

        # RFC 9260 sections 3.3.5 and 3.3.6: type 4 / 5 with one heartbeat info
        # parameter.
        for type_byte, code in (('04', Chunk.Heartbeat_Request),
                                ('05', Chunk.Heartbeat_Acknowledgement)):
            proto = self._packet(header + bytes.fromhex(
                type_byte + '00' '000c' '00010008' 'cafebabe'))
            chunk = proto.info.chunks[code]
            self.assertEqual(chunk.length, 12)
            info = chunk.parameters[Parameter.Heartbeat_Info]
            self.assertEqual(info.info, bytes.fromhex('cafebabe'))

        # RFC 9260 section 3.3.7: type 6, Reserved|T, length, error causes.
        # Flags 0x01 sets T, which pins T at bit 7.
        proto = self._packet(header + bytes.fromhex(
            '06' '01' '000c' '000c0007' '62796500'))
        chunk = proto.info.chunks[Chunk.Abort]
        self.assertEqual(chunk.length, 12)
        self.assertTrue(chunk.flags.T)
        self.assertEqual(chunk.error[CauseCode.User_Initiated_Abort].info, b'bye')

        proto = self._packet(header + bytes.fromhex('06' '00' '0004'))
        chunk = proto.info.chunks[Chunk.Abort]
        self.assertFalse(chunk.flags.T)
        self.assertEqual(len(chunk.error), 0)

        # RFC 9260 section 3.3.8: type 7, length 8, cumulative TSN ack.
        proto = self._packet(header + bytes.fromhex('07' '00' '0008' '0a0b0c10'))
        chunk = proto.info.chunks[Chunk.Shutdown]
        self.assertEqual(chunk.length, 8)
        self.assertEqual(chunk.cum_tsn_ack, 0x0A0B0C10)

        # RFC 9260 section 3.3.9: type 8, length 4, no parameters.
        proto = self._packet(header + bytes.fromhex('08' '00' '0004'))
        self.assertEqual(proto.info.chunks[Chunk.Shutdown_Acknowledgement].length, 4)

        # RFC 9260 section 3.3.10: type 9, one or more error causes.
        proto = self._packet(header + bytes.fromhex(
            '09' '00' '0010' '00010008' '0009' '0000' '00040004'))
        chunk = proto.info.chunks[Chunk.Operation_Error]
        self.assertEqual(chunk.length, 16)
        self.assertEqual(list(chunk.error.keys()),
                         [CauseCode.Invalid_Stream_Identifier, CauseCode.Out_of_Resource])
        self.assertEqual(chunk.error[CauseCode.Invalid_Stream_Identifier].stream_id, 9)

        # RFC 9260 section 3.3.11: type 10, length, cookie -- the cookie is the
        # *contents* of the state cookie parameter, not the parameter itself.
        proto = self._packet(header + bytes.fromhex(
            '0a' '00' '000a' 'deadbeeffeed' '0000'))
        chunk = proto.info.chunks[Chunk.State_Cookie]
        self.assertEqual(chunk.length, 10)
        self.assertEqual(chunk.cookie, bytes.fromhex('deadbeeffeed'))

        # RFC 9260 section 3.3.12: type 11, length 4.
        proto = self._packet(header + bytes.fromhex('0b' '00' '0004'))
        self.assertEqual(proto.info.chunks[Chunk.Cookie_Acknowledgement].length, 4)

        # RFC 9260 section 3.3.13: type 14, Reserved|T, length 4.
        proto = self._packet(header + bytes.fromhex('0e' '01' '0004'))
        chunk = proto.info.chunks[Chunk.Shutdown_Complete]
        self.assertEqual(chunk.length, 4)
        self.assertTrue(chunk.flags.T)

        proto = self._packet(header + bytes.fromhex('0e' '00' '0004'))
        self.assertFalse(proto.info.chunks[Chunk.Shutdown_Complete].flags.T)

    def test_final_chunk_padding_may_be_omitted_from_the_length(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        header = bytes.fromhex('26ab960c1122334400000000')

        # RFC 9260 section 3.2 says a robust implementation accepts a chunk
        # whether or not the final padding is counted in the chunk length. Here
        # the INIT ACK declares 29 (the state cookie's own three padding bytes
        # excluded) while 32 bytes are actually present, and a COOKIE ACK
        # follows -- so a parser that trusts the length blindly loses alignment
        # and misreads the next chunk.
        proto = self._packet(header + bytes.fromhex(
            '02' '00' '001d' '99aabbcc' '00001234' '0003' '0004' '00000007'
            '00070009' 'deadbeef01' '000000'
            '0b000004'))
        self.assertEqual(list(proto.info.chunks.keys()),
                         [Chunk.Initiation_Acknowledgement, Chunk.Cookie_Acknowledgement])
        chunk = proto.info.chunks[Chunk.Initiation_Acknowledgement]
        self.assertEqual(chunk.length, 29)
        self.assertEqual(chunk.parameters[Parameter.State_Cookie].cookie,
                         bytes.fromhex('deadbeef01'))
        self.assertEqual(proto.info.chunks[Chunk.Cookie_Acknowledgement].length, 4)

    ##########################################################################
    # Chunk parameters.
    ##########################################################################

    def test_chunk_parameter_wire_conformance(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        header = bytes.fromhex('26ab960c1122334400000000')
        params = bytes.fromhex(
            '00050008' '0a000001'                          # IPv4 address, s. 3.3.2.1.1
            '00060014' '20010db8000000000000000000000001'   # IPv6 address, s. 3.3.2.1.2
            '00090008' '000003e8'                          # cookie preservative, s. 3.3.2.1.3
            '000b000e' '6c6f63616c686f737400' '0000'       # host name, s. 3.3.2.1.4
            '000c0008' '0005' '0006'                       # supported addr types, s. 3.3.2.1.5
            '00070008' 'deadbeef'                          # state cookie, s. 3.3.3.1.1
            '00080008' '80000004'                          # unrecognized param, s. 3.3.3.1.2
            '00010008' 'cafebabe'                          # heartbeat info, s. 3.3.5
            '99990006' '4142' '0000'                       # unassigned type -> generic
        )
        length = 20 + len(params)
        raw = (header + bytes.fromhex('0100') + length.to_bytes(2, 'big')
               + bytes.fromhex('11223344' '0001a000' '000a' '000a' '55667788') + params)
        chunk = self._packet(raw).info.chunks[Chunk.Initiation]

        self.assertEqual(chunk.length, length)
        self.assertEqual(list(chunk.parameters.keys()), [
            Parameter.IPv4_Address, Parameter.IPv6_Address, Parameter.Cookie_Preservative,
            Parameter.Host_Name_Address, Parameter.Supported_Address_Types,
            Parameter.State_Cookie, Parameter.Unrecognized_Parameter,
            Parameter.Heartbeat_Info, Parameter.get(0x9999),
        ])

        import ipaddress

        self.assertEqual(chunk.parameters[Parameter.IPv4_Address].address,
                         ipaddress.IPv4Address('10.0.0.1'))
        self.assertEqual(chunk.parameters[Parameter.IPv6_Address].address,
                         ipaddress.IPv6Address('2001:db8::1'))
        self.assertEqual(chunk.parameters[Parameter.Cookie_Preservative].increment, 1000)
        self.assertEqual(chunk.parameters[Parameter.Host_Name_Address].name,
                         b'localhost\x00')
        self.assertEqual(chunk.parameters[Parameter.Supported_Address_Types].types,
                         (Parameter.IPv4_Address, Parameter.IPv6_Address))
        self.assertEqual(chunk.parameters[Parameter.State_Cookie].cookie,
                         bytes.fromhex('deadbeef'))
        self.assertEqual(chunk.parameters[Parameter.Unrecognized_Parameter].value,
                         bytes.fromhex('80000004'))
        self.assertEqual(chunk.parameters[Parameter.Heartbeat_Info].info,
                         bytes.fromhex('cafebabe'))
        # An unassigned parameter type falls through to the generic handler
        # rather than raising, and keeps its value verbatim.
        generic = chunk.parameters[Parameter.get(0x9999)]
        self.assertEqual(generic.length, 6)
        self.assertEqual(generic.value, b'AB')

    def test_every_chunk_parameter_round_trips(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        cases = [
            (Parameter.Heartbeat_Info, {'info': b'\xca\xfe\xba\xbe'}, 'info',
             b'\xca\xfe\xba\xbe'),
            (Parameter.IPv4_Address, {'address': '10.0.0.1'}, 'address', None),
            (Parameter.IPv6_Address, {'address': '2001:db8::1'}, 'address', None),
            (Parameter.State_Cookie, {'cookie': b'\xde\xad\xbe\xef'}, 'cookie',
             b'\xde\xad\xbe\xef'),
            (Parameter.Unrecognized_Parameter, {'value': b'\x80\x00\x00\x04'}, 'value',
             b'\x80\x00\x00\x04'),
            (Parameter.Cookie_Preservative, {'increment': 1000}, 'increment', 1000),
            (Parameter.Host_Name_Address, {'name': b'localhost\x00'}, 'name',
             b'localhost\x00'),
            (Parameter.Supported_Address_Types,
             {'types': [Parameter.IPv4_Address, Parameter.IPv6_Address]}, 'types',
             (Parameter.IPv4_Address, Parameter.IPv6_Address)),
            (Parameter.get(0x9999), {'value': b'AB'}, 'value', b'AB'),
        ]

        for code, args, attr, expect in cases:
            with self.subTest(parameter=code.name):
                raw = self._build([(Chunk.Initiation,
                                    dict(init_tag=1, parameters=[(code, args)]))])
                self.assertEqual(len(raw) % 4, 0)
                chunk = self._packet(raw).info.chunks[Chunk.Initiation]
                param = chunk.parameters[code]
                self.assertEqual(param.type, code)
                if expect is not None:
                    self.assertEqual(getattr(param, attr), expect)
                else:
                    self.assertEqual(str(getattr(param, attr)), args['address'])

    def test_host_name_parameter_must_be_null_terminated(self) -> None:
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError):
            SCTP._make_param_hostname(proto, Parameter.Host_Name_Address,
                                      name=b'localhost')

    ##########################################################################
    # Error causes.
    ##########################################################################

    def test_every_error_cause_wire_conformance(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        header = bytes.fromhex('26ab960c1122334400000000')
        causes = bytes.fromhex(
            '00010008' '0009' '0000'                # invalid stream identifier, s. 3.3.10.1
            '0002000a' '00000001' '0007' '0000'     # missing mandatory param, s. 3.3.10.2
            '00030008' '000003e8'                   # stale cookie, s. 3.3.10.3
            '00040004'                              # out of resource, s. 3.3.10.4
            '0005000c' '00050008' '0a000001'        # unresolvable address, s. 3.3.10.5
            '00060008' '9900' '0004'                # unrecognized chunk type, s. 3.3.10.6
            '00070004'                              # invalid mandatory param, s. 3.3.10.7
            '00080008' '80000004'                   # unrecognized parameters, s. 3.3.10.8
            '00090008' '0000000c'                   # no user data, s. 3.3.10.9
            '000a0004'                              # cookie while shutting down, s. 3.3.10.10
            '000b000c' '00050008' '0a000002'        # restart with new addresses, s. 3.3.10.11
            '000c0007' '62796500'                   # user-initiated abort, s. 3.3.10.12
            '000d0008' '6e6f7065'                   # protocol violation, s. 3.3.10.13
            '01010006' '4142' '0000'                # unassigned code -> generic
        )
        length = 4 + len(causes)
        raw = (header + bytes.fromhex('0900') + length.to_bytes(2, 'big') + causes)
        chunk = self._packet(raw).info.chunks[Chunk.Operation_Error]
        error = chunk.error

        self.assertEqual(chunk.length, length)
        self.assertEqual(list(error.keys()), [
            CauseCode.Invalid_Stream_Identifier, CauseCode.Missing_Mandatory_Parameter,
            CauseCode.Stale_Cookie, CauseCode.Out_of_Resource,
            CauseCode.Unresolvable_Address, CauseCode.Unrecognized_Chunk_Type,
            CauseCode.Invalid_Mandatory_Parameter, CauseCode.Unrecognized_Parameters,
            CauseCode.No_User_Data, CauseCode.Cookie_Received_While_Shutting_Down,
            CauseCode.Restart_of_an_Association_with_New_Addresses,
            CauseCode.User_Initiated_Abort, CauseCode.Protocol_Violation,
            CauseCode.get(0x0101),
        ])

        self.assertEqual(error[CauseCode.Invalid_Stream_Identifier].stream_id, 9)

        missing = error[CauseCode.Missing_Mandatory_Parameter]
        self.assertEqual(missing.num, 1)
        self.assertEqual(missing.types, (Parameter.State_Cookie,))

        self.assertEqual(error[CauseCode.Stale_Cookie].staleness, 1000)
        self.assertEqual(error[CauseCode.Out_of_Resource].length, 4)
        self.assertEqual(error[CauseCode.Unresolvable_Address].value,
                         bytes.fromhex('000500080a000001'))
        self.assertEqual(error[CauseCode.Unrecognized_Chunk_Type].value,
                         bytes.fromhex('99000004'))
        self.assertEqual(error[CauseCode.Invalid_Mandatory_Parameter].length, 4)
        self.assertEqual(error[CauseCode.Unrecognized_Parameters].value,
                         bytes.fromhex('80000004'))
        self.assertEqual(error[CauseCode.No_User_Data].tsn, 12)
        self.assertEqual(error[CauseCode.Cookie_Received_While_Shutting_Down].length, 4)
        self.assertEqual(error[CauseCode.Restart_of_an_Association_with_New_Addresses].value,
                         bytes.fromhex('000500080a000002'))
        self.assertEqual(error[CauseCode.User_Initiated_Abort].info, b'bye')
        self.assertEqual(error[CauseCode.Protocol_Violation].info, b'nope')

        # An unassigned cause code falls through to the generic handler.
        generic = error[CauseCode.get(0x0101)]
        self.assertEqual(generic.length, 6)
        self.assertEqual(generic.value, b'AB')

    def test_every_error_cause_round_trips(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter

        cases = [
            (CauseCode.Invalid_Stream_Identifier, {'stream_id': 9}, 'stream_id', 9),
            (CauseCode.Missing_Mandatory_Parameter,
             {'types': [Parameter.State_Cookie, Parameter.IPv4_Address]}, 'types',
             (Parameter.State_Cookie, Parameter.IPv4_Address)),
            (CauseCode.Stale_Cookie, {'staleness': 1000}, 'staleness', 1000),
            (CauseCode.Out_of_Resource, {}, 'length', 4),
            (CauseCode.Unresolvable_Address, {'value': b'\x00\x05\x00\x08\x0a\x00\x00\x01'},
             'value', b'\x00\x05\x00\x08\x0a\x00\x00\x01'),
            (CauseCode.Unrecognized_Chunk_Type, {'value': b'\x99\x00\x00\x04'}, 'value',
             b'\x99\x00\x00\x04'),
            (CauseCode.Invalid_Mandatory_Parameter, {}, 'length', 4),
            (CauseCode.Unrecognized_Parameters, {'value': b'\x80\x00\x00\x04'}, 'value',
             b'\x80\x00\x00\x04'),
            (CauseCode.No_User_Data, {'tsn': 12}, 'tsn', 12),
            (CauseCode.Cookie_Received_While_Shutting_Down, {}, 'length', 4),
            (CauseCode.Restart_of_an_Association_with_New_Addresses,
             {'value': b'\x00\x05\x00\x08\x0a\x00\x00\x02'}, 'value',
             b'\x00\x05\x00\x08\x0a\x00\x00\x02'),
            (CauseCode.User_Initiated_Abort, {'info': b'bye'}, 'info', b'bye'),
            (CauseCode.Protocol_Violation, {'info': b'nope'}, 'info', b'nope'),
            (CauseCode.get(0x0101), {'value': b'AB'}, 'value', b'AB'),
        ]

        for code, args, attr, expect in cases:
            with self.subTest(cause=code.name):
                raw = self._build([(Chunk.Operation_Error,
                                    dict(error=[(code, args)]))])
                self.assertEqual(len(raw) % 4, 0)
                chunk = self._packet(raw).info.chunks[Chunk.Operation_Error]
                cause = chunk.error[code]
                self.assertEqual(cause.code, code)
                self.assertEqual(getattr(cause, attr), expect)

    def test_missing_mandatory_parameter_count_must_match_the_length(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        header = bytes.fromhex('26ab960c1122334400000000')
        # Declares two missing parameters but carries only one.
        with self.assertRaises(ProtocolError):
            self._packet(header + bytes.fromhex(
                '09' '00' '000e' '0002000a' '00000002' '0007' '0000'))

    ##########################################################################
    # Unknown chunk types.
    ##########################################################################

    def test_unknown_chunk_types_fall_through_to_the_generic_handler(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        header = bytes.fromhex('26ab960c1122334400000000')

        # Unassigned (200), reserved for IETF extensions (63), an extension
        # chunk pcapkit does not implement (AUTH, 15), and the two chunk types
        # RFC 9260 defines but reserves (ECNE 12 and CWR 13). None of these may
        # raise -- they carry their raw flags and value through instead.
        for code, type_byte in ((Chunk.get(200), 'c8'),
                                (Chunk.Reserved_for_IETF_defined_Chunk_Extensions_63, '3f'),
                                (Chunk.Authentication_Chunk, '0f'),
                                (Chunk.Reserved_for_Explicit_Congestion_Notification_Echo,
                                 '0c'),
                                (Chunk.Reserved_for_Congestion_Window_Reduced, '0d')):
            with self.subTest(chunk=code.name):
                proto = self._packet(header + bytes.fromhex(
                    type_byte + 'ab' '0007' '010203' '00'))
                chunk = proto.info.chunks[code]
                self.assertEqual(chunk.type, code)
                self.assertEqual(chunk.length, 7)
                self.assertEqual(chunk.flags, b'\xab')
                self.assertEqual(chunk.value, bytes.fromhex('010203'))

        # ... and a bundle whose first chunk is unknown still yields the rest.
        proto = self._packet(header + bytes.fromhex('c8ab0007010203' '00' '0b000004'))
        self.assertEqual(list(proto.info.chunks.keys()),
                         [Chunk.get(200), Chunk.Cookie_Acknowledgement])

    def test_unknown_chunk_round_trips_through_the_generic_constructor(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        code = Chunk.get(200)
        raw = self._build([(code, dict(flags=b'\xab', value=b'\x01\x02\x03'))])
        chunk = self._packet(raw).info.chunks[code]
        self.assertEqual(chunk.flags, b'\xab')
        self.assertEqual(chunk.value, b'\x01\x02\x03')
        self.assertEqual(chunk.length, 7)

    def test_generic_chunk_constructor_rejects_a_bad_flags_width(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError):
            SCTP._make_chunk_donone(proto, Chunk.get(200), flags=b'\x00\x00')

    ##########################################################################
    # Malformed lengths.
    ##########################################################################

    def test_malformed_chunk_lengths_raise(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        header = bytes.fromhex('26ab960c1122334400000000')
        # Each case declares a length that the chunk's own definition forbids,
        # while still spanning exactly the bytes supplied -- so the failure is
        # the read handler rejecting the length, not the schema running off the
        # end of the buffer.
        cases = {
            # DATA carries no user data, but RFC 9260 3.3.1 requires at least
            # one byte, i.e. a length above 16.
            'data': '00' '03' '0010' '0a0b0c0d' '0001' '0002' '0000003c',
            # INIT is shorter than its own mandatory fixed fields.
            'init': '01' '00' '0010' '11223344' '0001a000' '000a' '000a' '55667788',
            # SACK declares three gap ack blocks but a length that fits two.
            'sack': '03' '00' '0018' '0000000c' '00001234' '0003' '0000'
                    '0002' '0003' '0005' '0005',
            # SHUTDOWN must be exactly 8.
            'shutdown': '07' '00' '0004' '0a0b0c10',
            # SHUTDOWN ACK must be exactly 4.
            'shutdown_ack': '08' '00' '0008',
            # COOKIE ACK must be exactly 4.
            'cookie_ack': '0b' '00' '0008',
            # SHUTDOWN COMPLETE must be exactly 4.
            'shutdown_complete': '0e' '00' '0008',
        }
        for name, body in cases.items():
            with self.subTest(chunk=name):
                with self.assertRaises(ProtocolError):
                    self._packet(header + bytes.fromhex(body))

    def test_data_chunk_constructor_requires_user_data(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        proto = SCTP.__new__(SCTP)
        with self.assertRaises(ProtocolError):
            SCTP._make_chunk_data(proto, Chunk.Payload_Data, data=b'')

    ##########################################################################
    # The payload protocol identifier dispatch hook.
    ##########################################################################

    def test_ppid_dispatch_hook(self) -> None:
        """Both NGAP PPIDs dispatch, and a junk payload still degrades.

        Both PPIDs are registered as defaults on
        :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>`
        rather than by a ``register_sctp`` call at import time, so the assertion
        is on the registry's declared contents.

        Dispatching is all the two have in common, and the assertion is
        deliberately no stronger than that. Only PPID 60 can decode: a PPID 66
        payload is an NGAP PDU inside a DTLS record, and with no DTLS
        implementation those bytes are never aligned PER, so 66 degrades to
        :class:`Raw` on every well-formed capture as well as on this junk one.

        ``b'ngap-pdu'`` is not an aligned PER ``NGAP-PDU``, which is the point:
        the failure has to reach :class:`Raw` through
        :func:`~pcapkit.utilities.decorators.beholder` rather than escape, and
        the payload has to keep the PPID's name while doing so. For PPID 60 that
        path is also what a capture parsed *without* ``pycrate`` installed takes
        on every NGAP packet.

        """
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.protocols.application.ngap import NGAP
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport import sctp as sctp_module
        from pcapkit.protocols.transport.sctp import SCTP

        NGAP_PPID = PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NG_Application_Protocol  # noqa: E501
        DTLS_PPID = PayloadProtocolIdentifier.PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP  # noqa: E501
        self.assertEqual(int(NGAP_PPID), 60)
        self.assertEqual(int(DTLS_PPID), 66)

        for ppid in (NGAP_PPID, DTLS_PPID):
            with self.subTest(ppid=int(ppid)):
                self.assertIn(ppid, SCTP.__proto__)
                entry = SCTP.__proto__[ppid]
                module = getattr(entry, 'module', None)
                if module is None:      # already imported by an earlier test
                    self.assertIs(entry, NGAP)
                else:
                    self.assertEqual(module, 'pcapkit.protocols.application.ngap')
                    self.assertEqual(entry.name, 'NGAP')

        raw = self._build([(Chunk.Payload_Data,
                            dict(I=True, U=True, B=True, E=True, tsn=1, ppid=NGAP_PPID,
                                 data=b'ngap-pdu'))])

        proto = self._packet(raw)
        self.assertEqual(proto.ppid, NGAP_PPID)
        self.assertIsInstance(proto.payload, Raw)
        self.assertEqual(bytes(proto.payload), b'ngap-pdu')
        self.assertEqual(str(proto.protochain),
                         'SCTP:PayloadProtocolIdentifier_3GPP_NG_Application_Protocol')

        # A PPID registered over the default dispatches to the new class. The
        # overwrite warning is expected here -- 60 is no longer a free slot --
        # and is asserted rather than allowed to litter the test output.
        with self._proto_registry():
            with mock.patch.object(sctp_module, 'warn') as warned:
                SCTP.register(NGAP_PPID, Raw)
            self.assertEqual(warned.call_count, 1)
            self.assertIs(SCTP.__proto__[NGAP_PPID], Raw)
            self.assertIs(SCTP.__proto__[60], Raw)

            proto = self._packet(raw)
            self.assertIsInstance(proto.payload, Raw)
            self.assertEqual(bytes(proto.payload), b'ngap-pdu')

    def test_unregistered_ppid_does_not_mutate_the_class_registry(self) -> None:
        """An unregistered PPID reaches :class:`Raw` without touching ``__proto__``.

        :attr:`SCTP.__proto__ <pcapkit.protocols.transport.sctp.SCTP.__proto__>`
        is a :class:`collections.defaultdict`, so *reading* a missing key
        inserts it. Dispatching an unregistered PPID through that read mutates
        class-level state shared by every later :class:`SCTP` instance in the
        process, and it makes
        :meth:`SCTP.register <pcapkit.protocols.transport.sctp.SCTP.register>`
        subsequently claim the PPID was "already registered".

        The symptom is invisible unless looked for, hence the before/after
        comparison of the registry's keys and the second instance: a leak is
        class-level, so it shows up on the *next* packet rather than this one.

        """
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.payload_protocol_identifier import PayloadProtocolIdentifier
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport import sctp as sctp_module
        from pcapkit.protocols.transport.sctp import SCTP

        # 4243 is the first code in the trailing "Unassigned" block of the IANA
        # registry, i.e. a PPID that is well-formed but cannot be registered.
        UNREGISTERED = 4243
        self.assertEqual(PayloadProtocolIdentifier(UNREGISTERED).name, 'Unassigned_4243')

        raw = self._build([(Chunk.Payload_Data,
                            dict(I=True, U=True, B=True, E=True, tsn=1,
                                 ppid=UNREGISTERED, data=b'unknown-pdu'))])

        with self._proto_registry():
            before = set(SCTP.__proto__)
            self.assertNotIn(UNREGISTERED, before)

            first = self._packet(raw)

            # (a) The payload is still reachable, as Raw, and is still labelled
            #     with its real PPID rather than being anonymised to ``None``.
            #     This is how Internet.__proto__ names an unregistered code --
            #     cf. ``IPv4:Use_for_experimentation_and_testing_253``.
            self.assertIsInstance(first.payload, Raw)
            self.assertEqual(bytes(first.payload), b'unknown-pdu')
            self.assertEqual(int(first.ppid), UNREGISTERED)
            self.assertEqual(first.payload.info.protocol, UNREGISTERED)
            self.assertEqual(str(first.protochain), 'SCTP:Unassigned_4243')

            # (b) The class-level registry gained nothing: no ``None`` key, and
            #     no key for the unregistered PPID either.
            self.assertNotIn(None, SCTP.__proto__)
            self.assertNotIn(UNREGISTERED, SCTP.__proto__)
            self.assertEqual(set(SCTP.__proto__), before)

            # A second instance in the same process must see the same registry
            # and behave identically -- class-level leakage would show here.
            second = self._packet(raw)
            self.assertIsInstance(second.payload, Raw)
            self.assertEqual(bytes(second.payload), b'unknown-pdu')
            self.assertEqual(str(second.protochain), 'SCTP:Unassigned_4243')
            self.assertEqual(set(SCTP.__proto__), before)

            # And the PPID is still registrable without a bogus overwrite
            # warning, which a leaked key would have triggered.
            with mock.patch.object(sctp_module, 'warn') as warned:
                SCTP.register(UNREGISTERED, Raw)
            self.assertEqual(warned.call_count, 0)

    def test_packet_without_a_data_chunk_has_no_payload(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.misc.null import NoPayload

        raw = self._build([(Chunk.Cookie_Acknowledgement, {})])
        proto = self._packet(raw)
        self.assertIsNone(proto.ppid)
        self.assertEqual(proto._get_payload(), b'')
        self.assertIsInstance(proto.payload, NoPayload)

    def test_first_data_chunk_of_a_bundle_selects_the_next_layer(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk

        raw = self._build([
            (Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=1,
                                      ppid=60, data=b'first')),
            (Chunk.Payload_Data, dict(I=True, U=True, B=True, E=True, tsn=2,
                                      ppid=53, data=b'second')),
        ])
        proto = self._packet(raw)
        self.assertEqual(proto.ppid, 60)
        self.assertEqual(proto._get_payload(), b'first')
        # The bundled chunk is still recorded, just not dispatched.
        self.assertEqual([c.data for c in proto.info.chunks.getlist(Chunk.Payload_Data)],
                         [b'first', b'second'])

    def test_register_rejects_a_non_protocol(self) -> None:
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            SCTP.register(60, int)  # type: ignore[arg-type]

    def test_register_warns_on_overwrite(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport import sctp as sctp_module
        from pcapkit.protocols.transport.sctp import SCTP

        # 4243 rather than 60: NGAP holds 60 by default, so registering it once
        # would already be the overwrite this test means to trigger on the
        # *second* call, and the assertion on the call count would pass for the
        # wrong reason.
        with self._proto_registry():
            SCTP.register(4243, Raw)
            with mock.patch.object(sctp_module, 'warn') as warned:
                SCTP.register(4243, Raw)
            self.assertEqual(warned.call_count, 1)
            self.assertIn('payload protocol identifier', warned.call_args.args[0])

    def test_register_sctp_wrapper_writes_the_ppid_registry(self) -> None:
        from pcapkit.foundation.registry.protocols import register_sctp
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.transport.sctp import SCTP

        with self._proto_registry():
            register_sctp(4243, 'pcapkit.protocols.misc.raw', 'Raw')
            self.assertIs(SCTP.__proto__[4243], Raw)

    ##########################################################################
    # Sub-registry registration.
    ##########################################################################

    def test_sub_registries_warn_on_overwrite(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport import sctp as sctp_module
        from pcapkit.protocols.transport.sctp import SCTP

        for register, code, registry in (
            (SCTP.register_chunk, Chunk.Payload_Data, SCTP.__chunk__),
            (SCTP.register_parameter, Parameter.Heartbeat_Info, SCTP.__parameter__),
            (SCTP.register_cause, CauseCode.Stale_Cookie, SCTP.__cause__),
        ):
            with self.subTest(register=register.__name__):
                original = registry[code]
                try:
                    with mock.patch.object(sctp_module, 'warn') as warned:
                        register(code, 'donone')
                    self.assertEqual(warned.call_count, 1)
                    self.assertEqual(registry[code], 'donone')
                finally:
                    registry[code] = original

    def test_unregistered_sub_registry_codes_do_not_mutate_the_class(self) -> None:
        """Parsing must not write to ``__chunk__``, ``__parameter__`` or ``__cause__``.

        #425's defect, on SCTP's three sub-registries. Each is a
        :class:`collections.defaultdict` on a class attribute shared by every
        :class:`~pcapkit.protocols.transport.sctp.SCTP` instance in the process,
        so ``registry[code]`` inserted every unregistered chunk type, parameter
        type and error cause code a capture happened to carry -- and the value it
        inserted was ``'donone'``, which the default factory returns anyway. The
        entries bought nothing and made
        :meth:`~pcapkit.protocols.transport.sctp.SCTP.register_chunk` and its
        siblings report an overwrite of something nobody registered.

        The chunk type is unassigned by IANA, and both the parameter type and the
        error cause code are drawn from the ``0xFFF0``-and-up range :rfc:`9260`
        reserves for IETF-Defined extensions, so nothing is expected to register
        them.

        """
        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport import sctp as sctp_module
        from pcapkit.protocols.transport.sctp import SCTP

        header = bytes.fromhex('26ab960c1122334400000000')
        for register, code, registry, chunk in (
            # an unassigned chunk type, on its own
            (SCTP.register_chunk, Chunk(200), SCTP.__dict__['__chunk__'],
             'c8' '00' '0004'),
            # INIT, length 24 = 4 header + 16 fixed + one 4-octet parameter
            (SCTP.register_parameter, Parameter(0xFFF0), SCTP.__dict__['__parameter__'],
             '01' '00' '0018' '11223344' '0001a000' '000a' '000a' '55667788' 'fff00004'),
            # ERROR, length 8 = 4 header + one 4-octet error cause
            (SCTP.register_cause, CauseCode(0xFFF0), SCTP.__dict__['__cause__'],
             '09' '00' '0008' 'fff00004'),
        ):
            with self.subTest(register=register.__name__):
                before = set(registry)
                self.assertNotIn(code, before)

                body = bytes.fromhex(chunk)
                # the chunk length field has to be the octets actually supplied,
                # or the parser is reading past the end of the packet and the
                # test is exercising a code path no real capture reaches
                self.assertEqual(int.from_bytes(body[2:4], 'big'), len(body))

                try:
                    self._packet(header + body)
                    self.assertEqual(set(registry), before)

                    with mock.patch.object(sctp_module, 'warn') as warned:
                        register(code, 'donone')
                    self.assertEqual(warned.call_count, 0)
                finally:
                    registry.pop(code, None)

    def test_callable_sub_registry_entries_are_used(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.transport.sctp import SCTP

        sentinel = object()
        parser = mock.Mock(return_value=sentinel)
        constructor = mock.Mock()
        original = SCTP.__chunk__[Chunk.Cookie_Acknowledgement]
        try:
            SCTP.__chunk__[Chunk.Cookie_Acknowledgement] = (parser, constructor)
            raw = bytes.fromhex('26ab960c1122334400000000' '0b000004')
            proto = self._packet(raw)
            self.assertIs(proto.info.chunks[Chunk.Cookie_Acknowledgement], sentinel)
            self.assertEqual(parser.call_count, 1)

            proto = SCTP.__new__(SCTP)
            SCTP._make_sctp_chunk(proto, Chunk.Cookie_Acknowledgement, None)
            self.assertEqual(constructor.call_count, 1)
        finally:
            SCTP.__chunk__[Chunk.Cookie_Acknowledgement] = original

    def test_chunks_accept_prebuilt_schemas_and_raw_bytes(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.protocols.schema.transport.sctp import CookieACKChunk

        schema = CookieACKChunk(type=Chunk.Cookie_Acknowledgement, flags=b'\x00', length=4)
        raw = self._build([schema, bytes.fromhex('08000004')])
        proto = self._packet(raw)
        self.assertEqual(list(proto.info.chunks.keys()),
                         [Chunk.Cookie_Acknowledgement, Chunk.Shutdown_Acknowledgement])

    ##########################################################################
    # Cross-check against scapy.
    ##########################################################################

    @unittest.skipUnless(HAS_SCAPY, 'scapy not installed')
    def test_scapy_cross_check(self) -> None:
        import ipaddress
        import os
        import tempfile

        from scapy.layers.inet import IP
        from scapy.layers.l2 import Ether
        from scapy.layers.sctp import SCTP as Scapy_SCTP
        from scapy.layers.sctp import (SCTPChunkAbort, SCTPChunkCookieEcho, SCTPChunkData,
                                       SCTPChunkHeartbeatReq, SCTPChunkInit,
                                       SCTPChunkParamHeartbeatInfo, SCTPChunkParamIPv4Addr,
                                       SCTPChunkParamSupportedAddrTypes, SCTPChunkSACK,
                                       SCTPChunkShutdown)
        from scapy.utils import wrpcap

        from pcapkit.const.sctp.cause_code import CauseCode
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.interface import extract

        def frame(chunk):
            return (Ether(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
                    / IP(src='10.0.0.1', dst='10.0.0.2') / chunk)

        packets = [
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0)
                  / SCTPChunkInit(init_tag=0x11223344, a_rwnd=106496, n_out_streams=10,
                                  n_in_streams=10, init_tsn=0x55667788,
                                  params=[SCTPChunkParamIPv4Addr(addr='10.0.0.1'),
                                          SCTPChunkParamSupportedAddrTypes(
                                              addr_type_list=[5, 6])])),
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0x11223344)
                  / SCTPChunkData(delay_sack=0, unordered=0, beginning=1, ending=1,
                                  tsn=0x0A0B0C0D, stream_id=1, stream_seq=2,
                                  proto_id=60, data=b'\x00\x15\x00\x08\x00\x00\x04\x00')),
            frame(Scapy_SCTP(sport=38412, dport=9899, tag=0x11223344)
                  / SCTPChunkSACK(cumul_tsn_ack=0x0A0B0C0D, a_rwnd=106496,
                                  gap_ack_list=[(2, 3), (5, 5)], dup_tsn_list=[19, 19])),
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0x11223344)
                  / SCTPChunkHeartbeatReq(
                      params=[SCTPChunkParamHeartbeatInfo(data=b'\xca\xfe\xba\xbe')])),
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0x11223344)
                  / SCTPChunkShutdown(cumul_tsn_ack=0x0A0B0C10)),
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0x11223344)
                  / SCTPChunkCookieEcho(cookie=b'\xde\xad\xbe\xef\xfe\xed')),
            frame(Scapy_SCTP(sport=9899, dport=38412, tag=0x11223344)
                  / SCTPChunkAbort(TCB=1)),
        ]

        handle, path = tempfile.mkstemp(prefix='pcapkit-sctp-', suffix='.pcap', dir='/tmp')
        os.close(handle)
        self.addCleanup(os.unlink, path)
        wrpcap(path, packets)

        # Round-trip the scapy packets through bytes, so that the fields scapy
        # computes at build time -- the chunk lengths and the CRC32c checksum --
        # are populated. Comparing against these is comparing against what
        # actually went on the wire, not against what we asked for.
        packets = [Ether(bytes(packet)) for packet in packets]

        extractor = extract(fin=path, nofile=True, store=True)
        self.addCleanup(close_extractor, extractor)
        frames = list(extractor.frame)
        self.assertEqual(len(frames), len(packets))

        from pcapkit.protocols.transport.sctp import SCTP

        parsed = []
        for index, got in enumerate(frames):
            with self.subTest(frame=index):
                self.assertEqual(str(got.protochain).split(':')[:3],
                                 ['Ethernet', 'IPv4', 'SCTP'])
                sctp = got[SCTP].info
                parsed.append(sctp)
                scapy_sctp = packets[index]['SCTP']
                self.assertEqual(sctp.vtag, scapy_sctp.tag)
                self.assertEqual(sctp.srcport.port, scapy_sctp.sport)
                self.assertEqual(sctp.dstport.port, scapy_sctp.dport)
                # scapy computes the CRC32c itself, so validating the checksum
                # it wrote is an independent check that our polynomial and byte
                # order match a second implementation.
                on_the_wire = bytes(scapy_sctp)
                self.assertEqual(sctp.chksum, on_the_wire[8:12])
                self.assertTrue(SCTP.validate_checksum(on_the_wire))

        # INIT, field by field against what scapy was told to emit.
        init = parsed[0].chunks[Chunk.Initiation]
        scapy_init = packets[0]['SCTPChunkInit']
        self.assertEqual(init.length, scapy_init.len)
        self.assertEqual(init.init_tag, scapy_init.init_tag)
        self.assertEqual(init.a_rwnd, scapy_init.a_rwnd)
        self.assertEqual(init.outbound_streams, scapy_init.n_out_streams)
        self.assertEqual(init.inbound_streams, scapy_init.n_in_streams)
        self.assertEqual(init.init_tsn, scapy_init.init_tsn)
        self.assertEqual(list(init.parameters.keys()),
                         [Parameter.IPv4_Address, Parameter.Supported_Address_Types])
        self.assertEqual(init.parameters[Parameter.IPv4_Address].address,
                         ipaddress.IPv4Address(scapy_init.params[0].addr))
        self.assertEqual(init.parameters[Parameter.Supported_Address_Types].types,
                         tuple(Parameter.get(item)
                               for item in scapy_init.params[1].addr_type_list))

        # DATA, field by field.
        data = parsed[1].chunks[Chunk.Payload_Data]
        scapy_data = packets[1]['SCTPChunkData']
        self.assertEqual(data.length, scapy_data.len)
        self.assertEqual(data.tsn, scapy_data.tsn)
        self.assertEqual(data.stream_id, scapy_data.stream_id)
        self.assertEqual(data.stream_seq, scapy_data.stream_seq)
        self.assertEqual(int(data.ppid), scapy_data.proto_id)
        self.assertEqual(data.data, scapy_data.data)
        self.assertEqual(data.flags.I, bool(scapy_data.delay_sack))
        self.assertEqual(data.flags.U, bool(scapy_data.unordered))
        self.assertEqual(data.flags.B, bool(scapy_data.beginning))
        self.assertEqual(data.flags.E, bool(scapy_data.ending))

        # SACK, field by field.
        sack = parsed[2].chunks[Chunk.Selective_Acknowledgement]
        scapy_sack = packets[2]['SCTPChunkSACK']
        self.assertEqual(sack.length, scapy_sack.len)
        self.assertEqual(sack.cum_tsn_ack, scapy_sack.cumul_tsn_ack)
        self.assertEqual(sack.a_rwnd, scapy_sack.a_rwnd)
        self.assertEqual(sack.num_gap_blocks, len(scapy_sack.gap_ack_list))
        self.assertEqual(sack.num_dup_tsn, len(scapy_sack.dup_tsn_list))
        # A re-parsed scapy SACK renders each gap ack block as a ``'start:end'``
        # string rather than as the tuple it was built from.
        def gap_pair(item):
            if isinstance(item, str):
                start, end = item.split(':')
                return int(start), int(end)
            return tuple(item)

        self.assertEqual([(b.start, b.end) for b in sack.gap_blocks],
                         [gap_pair(item) for item in scapy_sack.gap_ack_list])
        self.assertEqual(list(sack.dup_tsn), list(scapy_sack.dup_tsn_list))

        # HEARTBEAT, SHUTDOWN, COOKIE ECHO, ABORT.
        heartbeat = parsed[3].chunks[Chunk.Heartbeat_Request]
        self.assertEqual(heartbeat.length, packets[3]['SCTPChunkHeartbeatReq'].len)
        self.assertEqual(heartbeat.parameters[Parameter.Heartbeat_Info].info,
                         packets[3]['SCTPChunkParamHeartbeatInfo'].data)

        shutdown = parsed[4].chunks[Chunk.Shutdown]
        self.assertEqual(shutdown.length, 8)
        self.assertEqual(shutdown.cum_tsn_ack,
                         packets[4]['SCTPChunkShutdown'].cumul_tsn_ack)

        echo = parsed[5].chunks[Chunk.State_Cookie]
        self.assertEqual(echo.length, packets[5]['SCTPChunkCookieEcho'].len)
        self.assertEqual(echo.cookie, packets[5]['SCTPChunkCookieEcho'].cookie)

        abort = parsed[6].chunks[Chunk.Abort]
        self.assertEqual(abort.length, 4)
        self.assertTrue(abort.flags.T)
        self.assertEqual(len(abort.error), 0)
        self.assertNotIn(CauseCode.Out_of_Resource, abort.error)


if __name__ == '__main__':
    unittest.main()
