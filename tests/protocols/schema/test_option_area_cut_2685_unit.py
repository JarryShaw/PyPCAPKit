# -*- coding: utf-8 -*-
"""An option area the data ends inside hands back only the octets present (#2685).

``Schema.unpack`` gave back the rest of an ``OptionField``'s declared area by rewinding
the stream the full width of ``option_padding``, and kept ``length - option_padding``
octets of the area, even when the read had come back short. It also charged the cut to
the option field before the field had parsed, so that ``_cut_short_read`` then emptied
the fields after it. A TCP header of data offset 8, its options ``NOP NOP EOL`` then
zeros, cut 25 octets in with the whole 40 declared, rewound into its own checksum:
``bytes(schema)`` gave 32 octets and ``schema.pack()`` 23.

#2679 had worked round the same defect for SCTP alone, in an ``SCTP.unpack`` override
that measured the stream, and so could not read one that does not seek.

Every case builds its own octets.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: TCP header of data offset 8 (RFC 9293, section 3.1): options NOP, NOP and
#: End of Option List, then nine octets of zero padding, then eight of payload.
TCP_WHOLE = (struct.pack('!HHIIBBHHH', 1, 2, 3, 4, 8 << 4, 0x10, 0xffff, 0, 0)
             + bytes([1, 1, 0]) + bytes(9) + b'abcdefgh')
#: Where the option area's padding starts and ends.
TCP_PADDING = (23, 32)

#: SCTP common header (RFC 9260, section 3.1), a DATA chunk of five octets of user
#: data with its three pad octets (section 3.3.1), then a COOKIE ACK (section 3.3.12).
SCTP_WHOLE = (struct.pack('!HHII', 5000, 5001, 1, 0)
              + struct.pack('!BBHIHHI', 0, 3, 21, 7, 1, 2, 0) + b'abcde' + bytes(3)
              + struct.pack('!BBH', 11, 0, 4))


def _over_reporting_schemas():  # type: ignore[no-untyped-def]
    """An option list whose type-1 option reports four octets having read two.

    Its ``post_process`` returns a schema it packs itself, as an option may
    return a schema other than the one read. No shipped option does this, so
    the schemas are built here.

    """
    import collections

    from pcapkit.corekit.fields.collections import OptionField
    from pcapkit.corekit.fields.numbers import UInt8Field
    from pcapkit.corekit.fields.strings import BytesField
    from pcapkit.protocols.schema.schema import Schema

    class Wide(Schema):
        type: 'int' = UInt8Field()
        value: 'bytes' = BytesField(length=3)

    class Option(Schema):
        type: 'int' = UInt8Field()
        value: 'bytes' = BytesField(length=lambda pkt: 1 if pkt['type'] else 0)

        def post_process(self, packet):  # type: ignore[no-untyped-def]
            if not self.type:
                return self
            wide = Wide(type=self.type, value=self.value + bytes(2))
            wide.pack()
            return wide

    registry = collections.defaultdict(lambda: Option)

    def outer(area: int) -> type:
        class Outer(Schema):
            options: 'list[Option]' = OptionField(length=lambda pkt: area, base_schema=Option,
                                                  type_name='type', registry=registry, eool=0)
        return Outer

    return outer


class _Unseekable(io.RawIOBase):
    """A readable stream that cannot seek, as a pipe or a socket is."""

    def __init__(self, data: bytes) -> None:
        super().__init__()
        self._data = data
        self._offset = 0

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: 'bytearray') -> int:  # type: ignore[override]
        chunk = self._data[self._offset:self._offset + len(buffer)]
        buffer[:len(chunk)] = chunk
        self._offset += len(chunk)
        return len(chunk)


class OptionAreaCutTests(unittest.TestCase):
    """Schemas whose option area the data ends inside, unpacked with a longer length."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def test_tcp_cut_at_every_offset_packs_as_captured(self) -> None:
        from pcapkit.protocols.schema.transport.tcp import TCP

        for keep in range(20, len(TCP_WHOLE) + 1):
            raw = TCP_WHOLE[:keep]
            for via in ('bytes', 'stream'):
                with self.subTest(keep=keep, via=via):
                    schema = TCP.unpack(raw if via == 'bytes' else io.BytesIO(raw), len(TCP_WHOLE))
                    self.assertEqual(bytes(schema), raw)
                    self.assertEqual(schema.pack(), raw)
                    self.assertEqual(schema.__buffer__['options'], raw[20:TCP_PADDING[0]])
                    if keep <= TCP_PADDING[0]:
                        # nothing of the area is given back, so the cut is the options' own
                        self.assertEqual(schema.__dict__['__short_read__'], ('options', keep - 20))
                    elif keep < TCP_PADDING[1]:
                        # the options are whole, and the data ends in the padding after them
                        self.assertEqual(schema.__dict__['__short_read__'], ('padding', keep - TCP_PADDING[0]))
                    else:
                        self.assertNotIn('__short_read__', schema.__dict__)

    def test_tcp_cut_inside_the_padding_leaves_the_header_alone(self) -> None:
        from pcapkit.protocols.schema.transport.tcp import TCP

        raw = TCP_WHOLE[:25]
        schema = TCP.unpack(raw, len(TCP_WHOLE))
        self.assertEqual(schema.checksum, b'\x00\x00')
        self.assertEqual(schema.padding, bytes(2))
        self.assertEqual(schema.payload, b'')

    def test_an_option_reporting_more_than_it_read_still_records_the_cut(self) -> None:
        # the options' reported size, four octets, passes the two read: an area of
        # 8 gives back none of its remainder, and one of 4 has none to give back
        outer = _over_reporting_schemas()
        raw = b'\x01\x02'
        for area in (8, 4):
            for via in ('bytes', 'stream'):
                with self.subTest(area=area, via=via):
                    data = raw if via == 'bytes' else io.BytesIO(raw)
                    schema = outer(area).unpack(data, area)
                    if via == 'stream':
                        self.assertEqual(data.tell(), len(raw))  # type: ignore[union-attr]
                    self.assertEqual(schema.__buffer__['options'], raw)
                    self.assertEqual(schema.__dict__['__short_read__'], ('options', len(raw)))

    def test_sctp_on_a_stream_that_cannot_seek(self) -> None:
        from pcapkit.protocols.schema.transport.sctp import SCTP

        data_end = 12 + 24
        cases = {
            'whole': (SCTP_WHOLE, len(SCTP_WHOLE)),
            # one of the DATA chunk's three pad octets, then nothing
            'padding, own length': (SCTP_WHOLE[:data_end - 2], data_end - 2),
            'padding, whole length declared': (SCTP_WHOLE[:data_end - 2], len(SCTP_WHOLE)),
            'after a whole chunk, whole length declared': (SCTP_WHOLE[:data_end], len(SCTP_WHOLE)),
        }
        for name, (raw, given) in cases.items():
            with self.subTest(case=name):
                schema = SCTP.unpack(io.BufferedReader(_Unseekable(raw)), given)
                self.assertEqual(bytes(schema), raw)
                self.assertEqual(schema.pack(), raw)


if __name__ == '__main__':
    unittest.main()
