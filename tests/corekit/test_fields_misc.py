from __future__ import annotations

import unittest

from tests._support import purge_modules


class SchemaFieldDefaultTests(unittest.TestCase):
    """Regression coverage for `#444 <https://github.com/JarryShaw/PyPCAPKit/issues/444>`__.

    :class:`~pcapkit.corekit.fields.misc.SchemaField` accepts a documented,
    typed ``default: bytes`` constructor argument and unpacks it eagerly, via
    ``schema.unpack(default)`` -- a single positional argument. That call
    shape reached
    :func:`~pcapkit.utilities.decorators.prepare`, which read ``length`` and
    ``packet`` out of ``args[2]``/``args[3]`` unconditionally, so any call
    shorter than three positional arguments raised ``IndexError`` instead of
    falling back to the documented ``None`` default -- making
    ``SchemaField(schema=..., default=b'...')`` unusable for exactly the
    ``bytes`` default it exists to accept.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class TwoField(Schema):
            a: 'int' = UInt8Field()
            b: 'int' = UInt8Field()

        self.SchemaField = SchemaField
        self.TwoField = TwoField

    def test_schema_field_accepts_a_bytes_default(self) -> None:
        field = self.SchemaField(schema=self.TwoField, default=b'\x01\x02')

        self.assertIsInstance(field.default, self.TwoField)
        self.assertEqual(field.default.a, 1)
        self.assertEqual(field.default.b, 2)


if __name__ == '__main__':
    unittest.main()
