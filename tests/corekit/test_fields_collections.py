from __future__ import annotations

import collections
import unittest
from typing import TYPE_CHECKING

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any


class OptionFieldTests(unittest.TestCase):
    """Option-list parsing by :class:`~pcapkit.corekit.fields.collections.OptionField`.

    The schemas below stand in for the real TLV protocols: a base schema holding
    the option type and length, and two option schemas of *different* total
    widths registered against it, so that a stream left in the wrong place by
    the type lookup shows up as the second option decoding wrongly rather than
    as a silent shift.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.corekit.fields.numbers import UInt16Field
        from pcapkit.corekit.fields.strings import BytesField, PaddingField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        #: Every schema unpacked while parsing an option list, in order.
        self.unpacked = []  # type: list[str]
        unpacked = self.unpacked

        class Base(Schema):
            """Base schema: a two-octet type, then a two-octet body length."""

            kind: 'int' = UInt16Field()
            size: 'int' = UInt16Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                unpacked.append(cls.__name__)

        @schema_final
        class Body(Base):
            """An option carrying ``size`` octets of body after the header."""

            body: 'bytes' = BytesField(length=lambda pkt: pkt['size'])

        @schema_final
        class End(Base):
            """The end-of-option-list marker: header only, no body."""

        registry = collections.defaultdict(
            lambda: Body, {1: Body, 0: End},
        )  # type: collections.defaultdict[int, type[Base]]

        @schema_final
        class Options(Schema):
            options: 'list[Base]' = OptionField(
                length=13, base_schema=Base, type_name='kind',
                registry=registry, eool=0,
            )
            pad: 'bytes' = PaddingField(
                length=lambda pkt: pkt.get('__option_padding__', 0),
            )

        self.Base = Base
        self.Body = Body
        self.End = End
        self.Options = Options

        #: A 7-octet ``Body`` option, then a 4-octet ``End``, then 2 spare
        #: octets inside the field's declared 13.
        self.buffer = b'\x00\x01\x00\x03abc' b'\x00\x00\x00\x00' b'\xde\xad'

    def test_each_option_is_unpacked_exactly_once(self) -> None:
        """Selecting an option schema must not parse the option first.

        Reading the option type by unpacking the whole base schema and throwing
        the result away parsed every option twice -- two schema unpacks per
        option, the first of which was used for nothing but its type field. The
        base schema must therefore not appear here at all, and each option
        schema exactly once.

        """
        self.Options.unpack(self.buffer, 13, {})

        self.assertEqual(self.unpacked, ['Body', 'End'])

    def test_options_of_differing_widths_parse_in_sequence(self) -> None:
        """The stream must be left exactly at each option's first octet."""
        options = self.Options.unpack(self.buffer, 13, {}).options

        self.assertEqual([type(opt).__name__ for opt in options], ['Body', 'End'])
        self.assertEqual(options[0].kind, 1)
        self.assertEqual(options[0].size, 3)
        self.assertEqual(options[0].body, b'abc')
        self.assertEqual(options[1].kind, 0)

    def test_the_area_left_unread_after_the_eool_is_reported_as_padding(self) -> None:
        """The area past the end-of-option-list marker is handed back.

        ``OptionField`` reports it through ``__option_padding__``, which is what
        the following field sizes itself from -- so the two spare octets landing
        in ``pad`` is the whole rewind-and-truncate arithmetic being right.

        """
        schema = self.Options.unpack(self.buffer, 13, {})

        self.assertEqual(schema.pad, b'\xde\xad')


if __name__ == '__main__':
    unittest.main()
