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


class OptionFieldForeignBaseSchemaTests(unittest.TestCase):
    """Base schemas that the read-the-type-field-only shortcut does not fit.

    Nothing in this package declares one -- all 34 ``OptionField`` declarations put
    the type field first as a fixed-width number -- but ``OptionField`` is public
    and :mod:`pcapkit.foundation.registry` invites third-party protocols to
    register their own base schemas, which need not.

    Such a base schema must be **unpacked in full**, as it was before the shortcut
    existed. Getting this wrong does not raise: reading the wrong octets as the type
    code selects the wrong option schema and the packet is silently misparsed, which
    is why each case below asserts the parsed result and not merely that the slow
    path ran.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        #: Every schema unpacked while parsing an option list, in order. The base
        #: schema appearing here is what distinguishes the full unpack from the
        #: shortcut.
        self.unpacked = []  # type: list[str]

    def _options_for(self, base: 'Any', body: 'Any', end: 'Any') -> 'Any':
        """Wrap a base schema and its two option schemas in an enclosing schema.

        Args:
            base: Base schema carrying the option type and body length.
            body: Option schema for a body-bearing option, code ``1``.
            end: Option schema for the end-of-option-list marker, code ``0``.

        Returns:
            The enclosing schema class, ready to unpack an 8-octet option area.

        """
        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        registry = collections.defaultdict(lambda: body, {1: body, 0: end})

        @schema_final
        class Options(Schema):
            options: 'list[Any]' = OptionField(
                length=8, base_schema=base, type_name='kind',
                registry=registry, eool=0,
            )
            pad: 'bytes' = PaddingField(
                length=lambda pkt: pkt.get('__option_padding__', 0),
            )

        return Options

    def _type_second(self) -> 'Any':
        """A base schema whose type field is its *second* field."""
        from pcapkit.corekit.fields.numbers import UInt16Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        unpacked = self.unpacked

        class Base(Schema):
            """Body length first on the wire, option type second."""

            size: 'int' = UInt16Field()
            kind: 'int' = UInt16Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                unpacked.append(cls.__name__)

        @schema_final
        class Body(Base):
            body: 'bytes' = BytesField(length=lambda pkt: pkt['size'])

        @schema_final
        class End(Base):
            pass

        return self._options_for(Base, Body, End)

    def _type_first(self, callable_length: 'bool' = False) -> 'Any':
        """A base schema whose type field is its first field.

        Args:
            callable_length: Whether the type field's width is a callable rather
                than a fixed integer.

        Returns:
            The enclosing schema class, ready to unpack.

        """
        from pcapkit.corekit.fields.numbers import UInt16Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        unpacked = self.unpacked
        kind_field = UInt16Field(length=lambda pkt: 2) if callable_length else UInt16Field()

        class Base(Schema):
            """Option type first on the wire, body length second."""

            kind: 'int' = kind_field
            size: 'int' = UInt16Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                unpacked.append(cls.__name__)

        @schema_final
        class Body(Base):
            body: 'bytes' = BytesField(length=lambda pkt: pkt['size'])

        @schema_final
        class End(Base):
            pass

        return self._options_for(Base, Body, End)

    def test_a_type_field_that_is_not_first_falls_back_to_the_full_unpack(self) -> None:
        # A ``Body`` option with an empty body, then the end marker. With the type
        # field second, the first four octets read ``size=0, kind=1``; a reader that
        # takes the *leading* two octets as the type code sees 0, which is the
        # end-of-option-list code, so it stops without parsing the option at all --
        # measured, before the fallback existed: ['End'] and four octets of padding.
        Options = self._type_second()

        schema = Options.unpack(b'\x00\x00\x00\x01' b'\x00\x00\x00\x00', 8, {})

        self.assertEqual([type(opt).__name__ for opt in schema.options],
                         ['Body', 'End'])
        self.assertEqual(schema.options[0].kind, 1)
        self.assertEqual(schema.pad, b'')
        # ... and it got there by unpacking the base schema, not by the shortcut
        self.assertEqual(self.unpacked, ['Base', 'Body', 'Base', 'End'])

    def test_a_type_field_with_a_callable_length_falls_back_to_the_full_unpack(self) -> None:
        # A callable length is resolved against the packet, and the shortcut runs
        # before the full unpack has put the base schema's own fields there, so its
        # width could differ from the one Schema.unpack would have used.
        Options = self._type_first(callable_length=True)

        schema = Options.unpack(b'\x00\x01\x00\x00' b'\x00\x00\x00\x00', 8, {})

        self.assertEqual([type(opt).__name__ for opt in schema.options],
                         ['Body', 'End'])
        self.assertEqual(self.unpacked, ['Base', 'Body', 'Base', 'End'])

    def test_a_plain_first_type_field_still_takes_the_shortcut(self) -> None:
        # The control: the same construction with the type field first and a fixed
        # width must *not* fall back, or the guard above would have quietly undone
        # the optimisation for everything.
        Options = self._type_first()

        schema = Options.unpack(b'\x00\x01\x00\x00' b'\x00\x00\x00\x00', 8, {})

        self.assertEqual([type(opt).__name__ for opt in schema.options],
                         ['Body', 'End'])
        self.assertEqual(self.unpacked, ['Body', 'End'])


class OptionFieldPackageDeclarationTests(unittest.TestCase):
    """Every ``OptionField`` this package declares must still take the shortcut.

    The fallback added for foreign base schemas is selected from the base schema's
    shape, so a base schema declared here in a shape the shortcut does not fit
    would silently drop back to parsing every one of its options twice -- correct,
    but giving up the whole point of the change with nothing to show it. This is
    the guard against that happening unnoticed.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_no_declaration_in_the_package_falls_back(self) -> None:
        import pcapkit.all  # noqa: F401  (realises every schema declaration)
        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.protocols.schema.schema import Schema

        def subclasses(cls: 'Any') -> 'Any':
            for sub in cls.__subclasses__():
                yield sub
                yield from subclasses(sub)

        fell_back = []  # type: list[str]
        total = 0
        for cls in set(subclasses(Schema)):
            for name, field in getattr(cls, '__fields__', {}).items():
                if not isinstance(field, OptionField):
                    continue
                total += 1
                if field._type_field is None:  # pylint: disable=protected-access
                    fell_back.append(f'{cls.__module__}.{cls.__name__}.{name}')

        self.assertGreater(total, 0, 'no OptionField declarations were found, so '
                                     'this test proves nothing')
        self.assertEqual(sorted(fell_back), [])


class ListFieldSchemaItemTests(unittest.TestCase):
    """``ListField.unpack``'s schema branch must unpack from the *configured*
    per-item field, not from ``self._item_type`` itself.

    ``field = self._item_type(packet)`` builds a per-item copy through
    :meth:`SchemaField.__call__ <pcapkit.corekit.fields.misc.SchemaField.__call__>`,
    which applies both ``callback`` and ``length_callback`` to that copy -- the
    schema branch then unpacked from ``self._item_type`` instead of from
    ``field``, discarding whatever the copy carries. C.f. #433.

    No declaration in this package passes either argument, so nothing here
    parses differently today; both cases below construct a ``ListField``
    directly rather than through one of the four in-tree declarations, since
    those are exactly the shape that hides the bug.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_length_callback_is_honoured(self) -> None:
        """The per-item field's own resolved length must reach its schema.

        ``field``'s ``length_callback`` resolves to ``2``; ``self._item_type``,
        never having been called, is stuck at the ``-1`` its constructor left
        it with. ``SchemaField.unpack`` threads its own ``self.length`` through
        to ``Item.unpack``'s ``length`` argument, which lands in
        ``packet['__length__']`` -- so which one was used is directly visible
        to ``Item.pre_unpack`` without ``Item`` ever needing to consume it.

        """
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        recorded = []  # type: list[int]

        @schema_final
        class Item(Schema):
            """A single fixed-width byte: its own width never depends on
            ``__length__``, so the list keeps making progress whichever length
            got recorded."""

            marker: 'int' = UInt8Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                recorded.append(packet['__length__'])

        item_field = SchemaField(schema=Item, length=lambda pkt: 2)
        list_field = ListField(length=2, item_type=item_field)

        list_field.unpack(b'\x01\x02', {})

        self.assertEqual(recorded, [2, 2])

    def test_a_callback_is_honoured(self) -> None:
        """The per-item field's ``callback`` mutation must reach ``unpack``.

        The callback is evaluated regardless: ``field = self._item_type(packet)``
        runs it for its side effect even on the unpatched code. So what this
        proves is not that the callback *fires*, but that the mutation it made
        on its copy is what ``unpack`` actually used. It alternates
        ``field._schema`` between two otherwise-identical schemas, one per
        item; unpacking from ``self._item_type`` instead would use the schema
        fixed at construction time for every item.

        """
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        seen = []  # type: list[str]

        @schema_final
        class TypeA(Schema):
            marker: 'int' = UInt8Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                seen.append('A')

        @schema_final
        class TypeB(Schema):
            marker: 'int' = UInt8Field()

            @classmethod
            def pre_unpack(cls, packet: 'dict[str, Any]') -> 'None':
                seen.append('B')

        counter = {'n': 0}

        def alternate(field: 'Any', packet: 'dict[str, Any]') -> 'None':
            field._schema = TypeB if counter['n'] % 2 else TypeA  # pylint: disable=protected-access
            counter['n'] += 1

        item_field = SchemaField(length=1, schema=TypeA, callback=alternate)
        list_field = ListField(length=2, item_type=item_field)

        list_field.unpack(b'\x01\x02', {})

        self.assertEqual(seen, ['A', 'B'])


if __name__ == '__main__':
    unittest.main()
