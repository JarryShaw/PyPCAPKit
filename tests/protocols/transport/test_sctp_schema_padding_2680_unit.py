# -*- coding: utf-8 -*-
"""An SCTP schema cut inside the padding of its last item packs back as captured (#2680).

``Schema_SCTP.unpack(raw)`` and ``unpack(raw, len(raw))`` read a final chunk cut inside
its padding, and packed it back at full width: a DATA chunk of Length 21 cut after one of
its three pad octets gave 34 octets in and 36 out, and ``DATAChunk.unpack`` alone 22 in
and 24 out. ``padding_length`` capped the padding at the octets left, so the read never
came up short and ``Schema.unpack`` recorded nothing for ``Schema.pack`` to cut back to.

Each final chunk, parameter or cause below has a Length that leaves one, two or three pad
octets to follow (RFC 9260, section 3.2), and each is cut at every offset inside that
padding. Every case builds its own octets.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

#: Test tier (#1958): a sweep that cuts each packet at every offset of its padding.
__tier__ = 'LATEST'

#: SCTP common header from port 5000 to 5001 (RFC 9260, section 3.1), its checksum
#: zero, which nothing here checks.
COMMON = struct.pack('!HHII', 5000, 5001, 0x11223344, 0)
#: DATA chunk TSN, stream identifier, stream sequence number and PPID (RFC 9260,
#: section 3.3.1).
DATA_HEAD = struct.pack('!IHHI', 7, 1, 2, 0)
#: INIT and INIT ACK fixed part (RFC 9260, sections 3.3.2 and 3.3.3), then a whole
#: IPv4 Address parameter.
INIT_HEAD = struct.pack('!IIHHI', 0xaabbccdd, 65536, 10, 10, 1) + struct.pack('!HH4s', 5, 8, b'\xc0\x00\x02\x01')
#: A chunk type with no schema of its own (RFC 9260, section 3.2): upper bits 00.
UNKNOWN_CHUNK = 0x3f
#: A parameter type and a cause code with no schema of their own.
UNKNOWN_TLV = 0x3fff


def _tlv(code: int, value: bytes) -> bytes:
    """A parameter or error cause, unpadded, its Length excluding the padding (section 3.2.1)."""
    return struct.pack('!HH', code, 4 + len(value)) + value


def _chunk(code: int, flags: int, value: bytes) -> bytes:
    """A chunk, unpadded, its Length excluding the padding and the last parameter's (section 3.2)."""
    return struct.pack('!BBH', code, flags, 4 + len(value)) + value


def _pad(octets: bytes) -> bytes:
    """``octets`` with the zeros that round them up to four (section 3.2)."""
    return octets + bytes(-len(octets) % 4)


def _items(width: int) -> 'dict[str, tuple[str, int, bytes]]':
    """Parameters and causes whose Length leaves ``width`` pad octets, unpadded, by kind.

    Each is the base schema's name, its code and its octets.

    """
    size = 4 - width
    return {
        # Host Name Address (11), its name ending in a NUL (section 3.3.2.1)
        'host-name': ('Parameter', 11, _tlv(11, b'h' * (size - 1) + b'\x00')),
        # State Cookie (7)
        'state-cookie': ('Parameter', 7, _tlv(7, b's' * size)),
        # Heartbeat Info (1)
        'heartbeat-info': ('Parameter', 1, _tlv(1, b'i' * size)),
        'unknown-parameter': ('Parameter', UNKNOWN_TLV, _tlv(UNKNOWN_TLV, b'p' * size)),
        # Unrecognized Chunk Type (6)
        'unrecognized-chunk': ('ErrorCause', 6, _tlv(6, b'e' * size)),
        # User-Initiated Abort (12)
        'user-abort': ('ErrorCause', 12, _tlv(12, b'a' * size)),
        'unknown-cause': ('ErrorCause', UNKNOWN_TLV, _tlv(UNKNOWN_TLV, b'u' * size)),
    }


def _final(width: int) -> 'dict[str, bytes]':
    """Final chunks whose Length leaves ``width`` pad octets, unpadded, by kind."""
    size, items = 4 - width, _items(width)
    return {
        'data': _chunk(0, 0x03, DATA_HEAD + b'd' * size),
        'cookie-echo': _chunk(10, 0, b'c' * size),
        'unknown': _chunk(UNKNOWN_CHUNK, 0, b'x' * size),
        'init': _chunk(1, 0, INIT_HEAD + items['host-name'][2]),
        'init-ack': _chunk(2, 0, INIT_HEAD + items['state-cookie'][2]),
        'heartbeat': _chunk(4, 0, items['heartbeat-info'][2]),
        'heartbeat-ack': _chunk(5, 0, items['unknown-parameter'][2]),
        'error': _chunk(9, 0, items['unrecognized-chunk'][2]),
        'abort': _chunk(6, 0x01, items['user-abort'][2]),
    }


#: Whole chunks ahead of the final one in a multi-chunk packet: a SACK (section
#: 3.3.4) with no gap blocks, then a DATA chunk with its three pad octets.
LEADING = _chunk(3, 0, struct.pack('!IIHH', 9, 4096, 0, 0)) + _pad(_chunk(0, 0x03, DATA_HEAD + b'x'))


def _cut(whole: bytes, width: int) -> 'list[tuple[int, bytes]]':
    """Pad octets kept and octets, for every cut of ``whole`` inside its last ``width``."""
    return [(kept, whole[:len(whole) - width + kept]) for kept in range(width)]


def _cases() -> 'list[tuple[str, int, int, bytes]]':
    """Name, padding width, pad octets kept and octets, for every cut packet."""
    return [(f'{shape}-{kind}', width, kept, raw)
            for width in (1, 2, 3) for kind, chunk in _final(width).items()
            for shape, ahead in (('single', b''), ('multi', LEADING))
            for kept, raw in _cut(COMMON + ahead + _pad(chunk), width)]


def _wholes() -> 'list[tuple[str, int, bytes]]':
    """Name, padding width and octets of every packet above, with all its padding."""
    return [(f'{shape}-{kind}', width, COMMON + ahead + _pad(chunk))
            for width in (1, 2, 3) for kind, chunk in _final(width).items()
            for shape, ahead in (('single', b''), ('multi', LEADING))]


def _last_item(schema: 'object') -> 'object':
    """The item ``schema``'s data ends in: its last chunk, or that chunk's last parameter or cause."""
    item = schema.chunks[-1]  # type: ignore[attr-defined]
    for name in ('parameters', 'error'):
        nested = item.__dict__.get(name)
        if nested:
            return nested[-1]
    return item


class SCTPSchemaPaddingCutTests(unittest.TestCase):
    """SCTP packets cut inside the padding of their final chunk, at the schema level."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def assert_packs_as_captured(self, schema: 'object', raw: bytes, kept: int) -> None:
        """``schema`` records the cut in its last item's padding and packs ``raw`` back."""
        from pcapkit.protocols.schema.transport.sctp import SCTP

        assert isinstance(schema, SCTP)
        self.assertEqual(_last_item(schema).__dict__['__short_read__'], ('padding', kept))
        self.assertEqual(schema.trailer, b'')
        self.assertEqual(bytes(schema), raw)
        self.assertEqual(schema.pack(), raw)
        self.assertEqual(SCTP.from_dict(schema.to_dict()).pack(), raw)

        # a field ahead of the cut, changed, still packs no further than the octets read
        schema.vtag = 0x55667788
        self.assertEqual(schema.pack(), raw[:4] + b'\x55\x66\x77\x88' + raw[8:])

    def test_bytes_cut_inside_the_padding(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP

        for name, width, kept, raw in _cases():
            for given in (None, len(raw)):
                with self.subTest(case=name, width=width, kept=kept, length=given):
                    schema = SCTP.unpack(raw, given)
                    # every chunk parsed, the last one's Length short of a multiple of
                    # four by its padding (RFC 9260, section 3.2)
                    self.assertEqual(len(schema.chunks), 3 if name.startswith('multi') else 1)
                    self.assertEqual(-schema.chunks[-1].length % 4, width)
                    self.assert_packs_as_captured(schema, raw, kept)

    def test_stream_cut_inside_the_padding(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP

        for name, width, kept, raw in _cases():
            with self.subTest(case=name, width=width, kept=kept, length=None):
                # read from the middle of a stream, to its end
                stream = io.BytesIO(b'\xff' * 3 + raw)
                stream.seek(3)
                schema = SCTP.unpack(stream)
                self.assertEqual(stream.tell(), 3 + len(raw))
                self.assert_packs_as_captured(schema, raw, kept)

            with self.subTest(case=name, width=width, kept=kept, length=len(raw)):
                # the length given stops short of the octets after it
                stream = io.BytesIO(b'\xff' * 3 + raw + b'\xee' * 4)
                stream.seek(3)
                schema = SCTP.unpack(stream, len(raw))
                self.assertEqual(stream.tell(), 3 + len(raw))
                self.assert_packs_as_captured(schema, raw, kept)

    def test_chunk_schema_on_its_own(self) -> None:
        from pcapkit.const.sctp.chunk import Chunk as Enum_Chunk
        from pcapkit.protocols.schema.transport.sctp import Chunk

        for width in (1, 2, 3):
            for kind, chunk in _final(width).items():
                schema_cls = Chunk.registry[Enum_Chunk.get(chunk[0])]
                for kept, raw in _cut(_pad(chunk), width):
                    for via in ('bytes', 'stream'):
                        with self.subTest(case=kind, schema=schema_cls.__name__, width=width,
                                          kept=kept, via=via):
                            schema = schema_cls.unpack(raw if via == 'bytes' else io.BytesIO(raw))
                            nested = schema.__dict__.get('parameters') or schema.__dict__.get('error')
                            item = nested[-1] if nested else schema
                            self.assertEqual(item.__dict__['__short_read__'], ('padding', kept))
                            self.assertEqual(bytes(schema), raw)
                            self.assertEqual(schema.pack(), raw)

    def test_parameter_and_cause_schemas_on_their_own(self) -> None:
        from pcapkit.const.sctp.cause_code import CauseCode as Enum_CauseCode
        from pcapkit.const.sctp.parameter import Parameter as Enum_Parameter
        from pcapkit.protocols.schema.transport.sctp import ErrorCause, Parameter

        bases = {'Parameter': (Parameter, Enum_Parameter), 'ErrorCause': (ErrorCause, Enum_CauseCode)}
        for width in (1, 2, 3):
            for kind, (base, code, item) in _items(width).items():
                registry, enum = bases[base]
                schema_cls = registry.registry[enum.get(code)]
                for kept, raw in _cut(_pad(item), width):
                    with self.subTest(case=kind, schema=schema_cls.__name__, width=width, kept=kept):
                        schema = schema_cls.unpack(raw)
                        self.assertEqual(schema.__dict__['__short_read__'], ('padding', kept))
                        self.assertEqual(schema.padding, raw[len(item):])
                        self.assertEqual(bytes(schema), raw)
                        self.assertEqual(schema.pack(), raw)

    def test_parsed_header_packs_as_captured(self) -> None:
        # the protocol's own info is as before: the cut is the chunk's, not the packet's
        from pcapkit.protocols.transport.sctp import SCTP

        for name, width, kept, raw in _cases():
            with self.subTest(case=name, width=width, kept=kept):
                sctp = SCTP(raw, len(raw))
                self.assertNotIn('__short_read__', sctp.info)
                self.assertEqual(sctp.data, raw)
                self.assertEqual(bytes(sctp.__header__), raw)
                self.assertEqual(sctp.__header__.pack(), raw)
                self.assertEqual(SCTP.from_data(sctp.info).data, raw)
                self.assertEqual(SCTP.from_data(sctp.info.to_dict()).data, raw)

    def test_envelope_declaring_the_octets(self) -> None:
        # an IPv4 Total Length or IPv6 Payload Length that ends where the capture does
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.transport.sctp import SCTP

        for name, width, kept, raw in _cases():
            for cls, packet in ((IPv4, wire.ipv4(raw, proto=132)), (IPv6, wire.ipv6(raw, nxt=132))):
                with self.subTest(case=name, width=width, kept=kept, via=cls.__name__):
                    outer = cls(packet, len(packet))
                    sctp = outer.payload
                    self.assertIsInstance(sctp, SCTP)
                    self.assertEqual(sctp.__header__.pack(), raw)
                    self.assertEqual(cls.from_data(outer.info).data, packet)
                    self.assertEqual(cls.from_data(outer.info.to_dict()).data, packet)

    def test_an_item_running_past_its_chunk_is_refused(self) -> None:
        # only a cut inside the padding is kept: a Length past the chunk is an overrun (#1325)
        from pcapkit.protocols.schema.transport.sctp import SCTP, ErrorChunk, INITChunk
        from pcapkit.utilities.exceptions import ProtocolError

        # a Host Name Address parameter and an Unrecognized Chunk Type cause each
        # declaring 12 octets, of which their chunk holds 8
        chunks = {
            'init': (INITChunk, _chunk(1, 0, INIT_HEAD + struct.pack('!HH', 11, 12) + b'hhhh')),
            'error': (ErrorChunk, _chunk(9, 0, struct.pack('!HH', 6, 12) + b'eeee')),
        }
        for name, (schema_cls, chunk) in chunks.items():
            self.assertEqual(len(chunk) % 4, 0)
            for via, call in (('chunk', lambda: schema_cls.unpack(chunk)),
                              ('packet', lambda: SCTP.unpack(COMMON + chunk)),
                              ('bundled', lambda: SCTP.unpack(COMMON + chunk + _chunk(11, 0, b'')))):
                with self.subTest(case=name, via=via):
                    with self.assertRaisesRegex(ProtocolError, 'runs past the end of the data'):
                        call()

    def test_a_header_cut_keeps_its_own_record(self) -> None:
        # a longer declared length must not displace the field the data ended inside
        from pcapkit.protocols.schema.transport.sctp import SCTP

        names = ('srcport', 'dstport', 'vtag', 'chksum')
        widths = (2, 2, 4, 4)
        for keep in range(1, 12):
            raw = COMMON[:keep]
            field, offset = next((name, keep - start) for name, start, width in zip(
                names, (0, 2, 4, 8), widths) if keep < start + width)
            for given in (None, keep, 40):
                with self.subTest(keep=keep, length=given):
                    schema = SCTP.unpack(raw, given)
                    self.assertEqual(schema.__dict__['__short_read__'], (field, offset))
                    self.assertEqual(bytes(schema), raw)
                    self.assertEqual(schema.pack(), raw)

    def test_whole_padding_is_the_control(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP
        from pcapkit.protocols.transport.sctp import SCTP as Protocol_SCTP

        for name, width, whole in _wholes():
            for given in (None, len(whole)):
                with self.subTest(case=name, width=width, length=given):
                    schema = SCTP.unpack(whole, given)
                    self.assertNotIn('__short_read__', schema.__dict__)
                    self.assertNotIn('__short_read__', _last_item(schema).__dict__)
                    self.assertEqual(schema.trailer, b'')
                    self.assertEqual(schema.pack(), whole)

            with self.subTest(case=name, width=width, via='protocol'):
                self.assertNotIn('__short_read__', Protocol_SCTP(whole, len(whole)).info)

    def test_issue_2680_repro(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP, DATAChunk

        data = struct.pack('!BBHIHHI', 0, 3, 21, 7, 1, 2, 0) + b'abcde'
        raw = (struct.pack('!HHI', 5000, 5001, 1) + bytes(4) + data + bytes(3))[:34]
        for given in (None, 34):
            with self.subTest(length=given):
                schema = SCTP.unpack(raw, given)
                self.assertEqual(len(bytes(schema)), 34)
                self.assertEqual(len(schema.pack()), 34)

        chunk = DATAChunk.unpack(raw[12:])
        self.assertEqual(chunk.__dict__['__short_read__'], ('padding', 1))
        self.assertEqual(len(chunk.pack()), 22)


if __name__ == '__main__':
    unittest.main()
