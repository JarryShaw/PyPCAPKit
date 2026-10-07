# -*- coding: utf-8 -*-
"""A computed ``PayloadField`` length of zero reads an empty payload.

GitHub issue #1275: :meth:`Schema.unpack
<pcapkit.protocols.schema.schema.Schema.unpack>` sized the payload as
``length or packet['__length__']``, so a length that evaluated to zero was
taken as "unset" and the payload swallowed every octet after it, leaving the
following fields to be zero-filled.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import unittest

from tests._support import reimport_once_per_class


class TestPayloadFieldZeroLength(unittest.TestCase):
    """Pin the split between a zero-length payload and the fields after it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _schema(self) -> 'type':
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema

        class S(Schema):
            n: 'int' = UInt8Field()
            body: 'bytes' = PayloadField(length=lambda p: p['n'])
            tail: 'bytes' = BytesField(length=2)

        return S

    def test_zero_length_payload_is_empty(self) -> None:
        S = self._schema()
        for data, body in ((b'\x00ab', b''), (b'\x01xab', b'x')):
            with self.subTest(data=data):
                schema = S.unpack(io.BytesIO(data), len(data), {'__length__': len(data)})
                self.assertEqual(schema.body, body)
                self.assertEqual(schema.tail, b'ab')
                self.assertEqual(bytes(schema), data)

    def _unset_schema(self) -> 'type':
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema

        class R(Schema):
            n: 'int' = UInt8Field()
            body: 'bytes' = PayloadField()

        return R

    def test_unset_length_takes_the_rest(self) -> None:
        R = self._unset_schema()

        data = b'\x07rest'
        schema = R.unpack(io.BytesIO(data), len(data), {'__length__': len(data)})
        self.assertEqual(schema.body, b'rest')
        self.assertEqual(bytes(schema), data)

    def test_unset_length_stops_at_the_declared_length(self) -> None:
        """An unset payload is bounded by ``__length__``, never by the stream.

        The declared length is the authority even when the stream holds more:
        the octets past it belong to whatever encloses this schema, so reading
        them is an over-read that also leaves ``__length__`` mis-decremented --
        it used to come back *larger* than before the payload was read.

        """
        R = self._unset_schema()

        data = b'\x07abcdefgh'
        for declared, body, left in ((3, b'ab', 0), (1, b'', 0), (0, b'', -1)):
            with self.subTest(declared=declared):
                stream = io.BytesIO(data)
                packet = {'__length__': declared}
                schema = R.unpack(stream, declared, packet)
                self.assertEqual(schema.body, body)
                self.assertEqual(stream.tell(), 1 + len(body))
                self.assertEqual(packet['__length__'], left)


if __name__ == '__main__':
    unittest.main()
