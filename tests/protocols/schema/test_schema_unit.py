from __future__ import annotations

import collections
import enum
import importlib.util
import io
import unittest
import warnings
from unittest import mock

from tests._support import purge_modules, time_limit

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SchemaUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_schema_classes(self):
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import ConditionalField, ForwardMatchField, PayloadField, SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class NestedSchema(Schema):
            marker: int = UInt8Field(default=0xEE)

        @schema_final
        class FeatureSchema(Schema):
            kind: int = UInt8Field(default=1)
            maybe: int = ConditionalField(UInt8Field(default=0xCC), lambda packet: packet['kind'] == 9)
            peek: int = ForwardMatchField(UInt8Field(default=0))
            repeated: list[int] = ListField(length=2, item_type=UInt8Field())
            nested: NestedSchema = SchemaField(length=1, schema=NestedSchema, default=NestedSchema(marker=0x33))
            pad: bytes = PaddingField(length=2)
            payload: bytes = PayloadField(length=lambda packet: packet['__length__'], default=b'')

        @schema_final
        class PayloadOnlySchema(Schema):
            payload: bytes = PayloadField(length=lambda packet: packet['__length__'], default=b'')

        @schema_final
        class ConditionalSchema(Schema):
            flag: int = UInt8Field(default=0)
            maybe: int = ConditionalField(UInt8Field(default=0xAA), lambda packet: packet['flag'] == 1)

        @schema_final
        class BuiltinNameSchema(Schema):
            items: int = UInt8Field(default=1)

        return NestedSchema, FeatureSchema, PayloadOnlySchema, ConditionalSchema, BuiltinNameSchema

    def test_schema_pack_unpack_and_mapping_methods(self) -> None:
        NestedSchema, FeatureSchema, _, _, _ = self._make_schema_classes()

        schema = FeatureSchema(
            kind=9,
            maybe=0xAB,
            peek=0xFE,
            repeated=[0x10, 0x11],
            nested=NestedSchema(marker=0x44),
            payload=b'body',
        )

        self.assertEqual(bytes(schema), b'\x09\xab\x10\x11\x44\x00\x00body')
        self.assertEqual(len(schema), 11)
        self.assertEqual(schema.to_bytes(), bytes(schema))
        self.assertEqual(schema.get_payload(), b'body')
        self.assertEqual(schema['kind'], 9)
        self.assertIn('kind=9', str(schema))
        self.assertIn('NestedSchema(...)', repr(schema))
        # ``pad`` is absent: the generated ``__init__`` seeds every field, but
        # ``__post_init__`` keeps only the ones it can fill, and a padding field
        # declaring no default has nothing to be filled with
        self.assertEqual(list(schema), ['kind', 'maybe', 'peek', 'repeated', 'nested', 'payload'])

        as_dict = schema.to_dict()
        self.assertEqual(as_dict['nested'], {'marker': 0x44})
        self.assertEqual(as_dict['payload'], b'body')

        schema.kind = 1
        self.assertEqual(schema.kind, 1)
        del schema.kind
        schema.kind = 9
        self.assertEqual(schema['kind'], 9)

        unpacked = FeatureSchema.unpack(b'\x01\x08\x09\x33\x00\x00zz', None, None)
        self.assertEqual(unpacked.kind, 1)
        self.assertIsNone(unpacked.maybe)
        self.assertEqual(unpacked.peek, 8)
        self.assertEqual(unpacked.repeated, [8, 9])
        self.assertEqual(unpacked.nested.marker, 0x33)
        self.assertEqual(unpacked.payload, b'zz')
        # unpacking reads every field off the wire, so unlike the construction
        # above it leaves none of them absent
        self.assertEqual(list(unpacked), list(FeatureSchema.__fields__))

    def test_list_field_pack_accepts_a_tuple_like_it_accepts_a_list(self) -> None:
        """A ``ListField`` value packs identically whether it is a list or a tuple.

        See #476: several data models declare a ``ListField``-backed attribute as
        ``tuple[...]`` (HIP's ``group_id``, MH's ``prefixes``/``fid``/``bid``, and
        others), and ``_read_*`` hands one straight back to ``_make_*`` on a
        parse-then-reconstruct cycle. Before the fix, :meth:`Schema.pack
        <pcapkit.protocols.schema.schema.Schema.pack>` accepted a :obj:`list` but
        raised :exc:`ProtocolUnbound` on the tuple -- a case no unit test that
        builds the schema directly with a list could ever see.

        """
        NestedSchema, FeatureSchema, _, _, _ = self._make_schema_classes()
        from pcapkit.utilities.exceptions import ProtocolUnbound

        as_list = FeatureSchema(
            kind=9, maybe=0xAB, peek=0xFE, repeated=[0x10, 0x11],
            nested=NestedSchema(marker=0x44), payload=b'body',
        )
        as_tuple = FeatureSchema(
            kind=9, maybe=0xAB, peek=0xFE, repeated=(0x10, 0x11),
            nested=NestedSchema(marker=0x44), payload=b'body',
        )
        self.assertEqual(bytes(as_tuple), bytes(as_list))
        self.assertEqual(bytes(as_tuple), b'\x09\xab\x10\x11\x44\x00\x00body')

        # The branch still rejects what it always rejected: a tuple is accepted
        # because it is a sequence ``ListField.pack`` can iterate, not because
        # the check grew permissive. A :obj:`str` is also a sequence but is not
        # what any data model here declares, so it stays out, same as
        # ``object()`` did before this fix.
        with self.assertRaises(ProtocolUnbound):
            bytes(FeatureSchema(
                kind=1, repeated='xy',  # type: ignore[arg-type]
                nested=NestedSchema(marker=0x33), payload=b'',
            ))

    def test_schema_update_unknown_fields_and_builtin_field_mapping(self) -> None:
        _, _, _, _, BuiltinNameSchema = self._make_schema_classes()

        schema = BuiltinNameSchema.__new__(BuiltinNameSchema)
        schema.__update__([('items', 7)])

        self.assertEqual(schema['items'], 7)
        self.assertEqual(list(schema), ['items'])
        self.assertEqual(schema.to_dict(), {'items': 7})
        self.assertIn('items=7', str(schema))
        self.assertIn('items=7', repr(schema))

        with mock.patch('pcapkit.protocols.schema.schema.warn') as warn:
            schema.__update__([('missing', 1)])
        self.assertEqual(warn.call_count, 1)

    def test_payload_field_accepts_bytes_schema_protocol_and_rejects_other_types(self) -> None:
        NestedSchema, _, PayloadOnlySchema, _, _ = self._make_schema_classes()
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.corekit.protochain import ProtoChain
        from pcapkit.protocols.data.data import Data
        from pcapkit.protocols.protocol import Protocol
        from pcapkit.utilities.exceptions import ProtocolUnbound

        @info_final
        class DummyData(Data):
            pass

        class DummyProtocol(Protocol[DummyData, PayloadOnlySchema],
                            schema=PayloadOnlySchema, data=DummyData):
            @property
            def name(self) -> str:
                return 'Dummy'

            @property
            def length(self) -> int:
                return 0

            def read(self, length: int | None = None, **kwargs: object) -> DummyData:
                from pcapkit.protocols.misc.null import NoPayload
                self._next = NoPayload()
                self._protos = ProtoChain(self.__class__, self.alias)
                return DummyData()

            def make(self, packet: bytes = b'', **kwargs: object) -> PayloadOnlySchema:
                return PayloadOnlySchema(payload=packet)

            @classmethod
            def __index__(cls) -> int:
                return 0

        self.assertEqual(bytes(PayloadOnlySchema(payload=b'bytes')), b'bytes')
        self.assertEqual(bytes(PayloadOnlySchema(payload=NestedSchema(marker=0x55))), b'\x55')
        self.assertEqual(bytes(PayloadOnlySchema(payload=DummyProtocol(packet=b'proto'))), b'proto')

        with self.assertRaises(ProtocolUnbound):
            bytes(PayloadOnlySchema(payload=object()))  # type: ignore[arg-type]

        schema = PayloadOnlySchema(payload=b'data')
        with self.assertRaises(ProtocolUnbound):
            schema.get_payload('missing')
        with self.assertRaises(ProtocolUnbound):
            NestedSchema(marker=1).get_payload('marker')

    def test_conditional_list_padding_and_unpack_warning_branches(self) -> None:
        NestedSchema, FeatureSchema, _, ConditionalSchema, _ = self._make_schema_classes()

        self.assertEqual(bytes(ConditionalSchema(flag=0, maybe=0xFE)), b'\x00')
        self.assertEqual(bytes(ConditionalSchema(flag=1, maybe=0xFE)), b'\x01\xfe')

        as_bytes = FeatureSchema(kind=1, repeated=b'\x01\x02', nested=NestedSchema(marker=0x33), payload=b'end')
        self.assertEqual(bytes(as_bytes), b'\x01\x01\x02\x33\x00\x00end')

        as_none = FeatureSchema(kind=1, repeated=None, nested=NestedSchema(marker=0x33), payload=b'')
        self.assertEqual(bytes(as_none), b'\x01\x33\x00\x00')

        with mock.patch('pcapkit.protocols.schema.schema.warn') as warn:
            unpacked = ConditionalSchema.unpack(b'\x01', 1, None)
        self.assertEqual(unpacked.flag, 1)
        self.assertEqual(unpacked.maybe, 0)
        self.assertEqual(warn.call_count, 1)

    def test_from_dict_hooks_schema_final_and_enum_schema_registry(self) -> None:
        NestedSchema, FeatureSchema, _, _, _ = self._make_schema_classes()
        from pcapkit.protocols.schema.schema import EnumSchema, schema_final

        schema = FeatureSchema.from_dict([
            ('kind', 9),
            ('maybe', 1),
            ('peek', 0),
            ('repeated', [2, 3]),
            ('nested', NestedSchema(marker=4)),
            ('pad', b''),
            ('payload', b'x'),
        ])
        self.assertEqual(bytes(schema), b'\x09\x01\x02\x03\x04\x00\x00x')

        packet: dict[str, object] = {}
        schema.pre_pack(packet)
        FeatureSchema.pre_unpack(packet)
        self.assertIs(schema.post_process(packet), schema)

        with mock.patch('pcapkit.protocols.schema.schema.warn') as warn:
            schema_final(NestedSchema)
        self.assertEqual(warn.call_count, 1)

        class Code(enum.IntEnum):
            one = 1
            two = 2
            three = 3

        class BaseEnumSchema(EnumSchema[Code]):
            pass

        class OneSchema(BaseEnumSchema, code=Code.one):
            pass

        class ManySchema(BaseEnumSchema, code=[Code.two, Code.three]):
            pass

        self.assertIs(BaseEnumSchema.registry[Code.one], OneSchema)
        self.assertIs(BaseEnumSchema.registry[Code.two], ManySchema)
        self.assertIs(BaseEnumSchema.registry[Code.three], ManySchema)

        # ``Code.two`` is held by ``ManySchema``, so this is a genuine overwrite
        # and now reports one. Captured and asserted rather than left to escape:
        # an unasserted warning is noise in every later run of the suite, and the
        # capture is what stops this line from quietly becoming a second, silent
        # copy of the behaviour ``EnumSchemaRegistryOverwriteTests`` pins.
        from pcapkit.utilities.warnings import RegistryWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            BaseEnumSchema.register(Code.two, OneSchema)

        overwrites = [str(item.message) for item in caught
                      if issubclass(item.category, RegistryWarning)]
        self.assertEqual(len(overwrites), 1)
        self.assertIn(repr(ManySchema), overwrites[0])
        self.assertIn(repr(OneSchema), overwrites[0])

        self.assertIs(BaseEnumSchema.registry[Code.two], OneSchema)
        self.assertIs(BaseEnumSchema.from_dict().registry, BaseEnumSchema.registry)

    def test_schema_final_generated_init(self) -> None:
        """``schema_final`` generates a typed ``__init__`` from the field table.

        This used to also cover a ``sys.version_info``-mocked "legacy version"
        branch in ``SchemaMeta.__new__``, which no longer exists: that branch
        was GitHub issue #439's workaround for a class-keyword collision with
        ``abc.ABCMeta.__new__`` on Python < 3.11, and the fix removed it (and
        the ``sys`` import along with it) in favour of renaming the one
        keyword that actually collided. ``SchemaMeta.__new__`` no longer
        branches on the interpreter version at all, so there is nothing left
        for a mocked ``sys.version_info`` to exercise here.

        """
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class GeneratedInitSchema(Schema):
            value: int = UInt8Field(default=1)

        @schema_final
        class EmptyGeneratedSchema(Schema):
            pass

        self.assertEqual(bytes(GeneratedInitSchema(value=2)), b'\x02')
        self.assertEqual(bytes(GeneratedInitSchema()), b'\x01')
        self.assertEqual(bytes(EmptyGeneratedSchema()), b'')

    def test_generated_init_is_installed_and_runs_post_init(self) -> None:
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field
        from pcapkit.protocols.schema.misc.null import NoPayload
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class HeaderSchema(Schema):
            kind: int = UInt8Field(default=3)
            size: int = UInt16Field(default=0x0102)
            spare: int = UInt8Field()
            trailer: list[int] = ListField(length=2, item_type=UInt8Field())

        # the guard read ``hasattr(cls, '__init__')``, which every class satisfies
        # through :obj:`object`, so the generated method was never installed and
        # ``__init__`` stayed bound to ``Schema.__update__``
        self.assertIsNot(HeaderSchema.__init__, Schema.__update__)
        self.assertEqual(HeaderSchema.__init__.__qualname__, 'HeaderSchema.__init__')

        schema = HeaderSchema(kind=9)

        # ``__post_init__`` ran: ``size`` carries its declared default, and the
        # two that declare none are left absent rather than holding the
        # ``NoValue`` the generated ``__init__`` seeded them with
        self.assertEqual(schema.to_dict(), {'kind': 9, 'size': 0x0102})

        # so the schema packs, where before the fix the fields left out reached
        # the packing as the field objects themselves
        self.assertEqual(bytes(schema), b'\x09\x01\x02\x00')

        # and the two construction paths now agree
        self.assertEqual(bytes(HeaderSchema.from_dict({'kind': 9})), bytes(schema))

        # a packet context is what makes packing at construction possible, so it
        # is what asks for it
        eager = HeaderSchema(kind=9, __packet__={})
        self.assertFalse(eager.__updated__)
        self.assertEqual(eager.__buffer__['size'], b'\x01\x02')

        # a schema declaring an ``__init__`` of its own keeps it
        self.assertEqual(NoPayload.__init__.__qualname__, 'NoPayload.__init__')
        self.assertEqual(bytes(NoPayload()), b'')

    def test_post_init_fills_the_unset_and_keeps_an_explicit_none(self) -> None:
        from pcapkit.corekit.fields.misc import ConditionalField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class OptionalSchema(Schema):
            kind: int = UInt8Field(default=1)
            #: declares a default of its own, and is off the wire unless kind is 9
            maybe: int = ConditionalField(UInt8Field(default=0xCC),
                                          lambda packet: packet['kind'] == 9)
            #: declares no default
            spare: int = UInt8Field()

        # a field the caller left out is filled from its declared default, and one
        # declaring none is left absent rather than holding ``NoValue``
        self.assertEqual(OptionalSchema(kind=9).to_dict(), {'kind': 9, 'maybe': 0xCC})

        # a ``None`` the caller passed is a value they chose, not a field they
        # omitted, so it survives even where the field declares a default
        self.assertEqual(OptionalSchema(kind=9, maybe=None, spare=None).to_dict(),
                         {'kind': 9, 'maybe': None, 'spare': None})

        # keeping it costs nothing on the wire, since ``FieldBase.pack`` resolves a
        # ``None`` from the field's own default anyway
        self.assertEqual(bytes(OptionalSchema(kind=9, maybe=None)),
                         bytes(OptionalSchema(kind=9)))

        # and it is what keeps a constructed schema agreeing with a parsed one:
        # ``unpack`` stores ``None`` for a conditional field whose test fails, so
        # substituting the default would stop ``to_dict`` surviving ``from_dict``
        parsed = OptionalSchema.unpack(b'\x01\x07', 2, None)
        self.assertIsNone(parsed.maybe)
        self.assertEqual(OptionalSchema.from_dict(parsed.to_dict()).to_dict(),
                         parsed.to_dict())

    def test_schema_mapping_payload_list_and_default_edge_branches(self) -> None:
        NestedSchema, FeatureSchema, PayloadOnlySchema, _, _ = self._make_schema_classes()
        from pcapkit.corekit.fields.field import NoValue
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final
        from pcapkit.utilities.exceptions import ProtocolUnbound

        @schema_final
        class ConflictSchema(Schema):
            value: int = UInt8Field(default=1)

        schema = ConflictSchema(value=2)
        schema.__builtin__.add('value')
        schema.__excluded__.append('value')
        schema.__update__([('value', 4)])

        mapped_name = f'_{type(schema).__name__}value'
        self.assertEqual(schema.__map__['value'], mapped_name)
        self.assertEqual(schema.__map_reverse__[mapped_name], 'value')
        self.assertEqual(schema['value'], 4)

        schema.extra = 'kept'
        self.assertEqual(schema.extra, 'kept')
        del schema.extra
        self.assertFalse(hasattr(schema, 'extra'))
        with self.assertRaises(KeyError):
            schema['missing']

        self.assertEqual(bytes(PayloadOnlySchema(payload=None)), b'')

        with self.assertRaises(ProtocolUnbound):
            bytes(FeatureSchema(
                kind=1,
                repeated=object(),  # type: ignore[arg-type]
                nested=NestedSchema(marker=0x33),
                payload=b'',
            ))

        @schema_final
        class NoDefaultSchema(Schema):
            value: int = UInt8Field()

        no_default = NoDefaultSchema(value=1)
        no_default.value = None
        self.assertEqual(bytes(no_default), b'\x00')

    def test_schema_option_field_unpack_records_padding(self) -> None:
        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import PaddingField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class TinyOption(Schema):
            type: int = UInt8Field(default=0)
            value: int = UInt8Field(default=0)

        observed_padding: list[int] = []

        @schema_final
        class TinyOptionsSchema(Schema):
            options: list[TinyOption] = OptionField(
                length=3,
                base_schema=TinyOption,
                registry=collections.defaultdict(lambda: TinyOption, {0: TinyOption}),
                eool=0,
            )
            pad: bytes = PaddingField(
                length=lambda packet: observed_padding.append(packet['__option_padding__']) or 0,
            )

        unpacked = TinyOptionsSchema.unpack(b'\x00\xaa\xff', 3, {})

        self.assertEqual(len(unpacked.options), 1)
        self.assertEqual(unpacked.options[0].value, 0xAA)
        self.assertEqual(unpacked.pad, b'')
        self.assertEqual(observed_padding, [1])

    def test_schema_option_field_unpack_rejects_an_option_consuming_nothing(self) -> None:
        """An option area that cannot be advanced past is an error, not a hang.

        :meth:`OptionField.unpack
        <pcapkit.corekit.fields.collections.OptionField.unpack>` sizes each
        option by ``len(data)``, the size of the schema the option reported,
        which is not the number of octets it took from the stream. ``Wrapper``
        below is the smallest thing that separates the two, and is the shape
        every wrapper option schema in the package has: it reads two octets and
        returns a nested schema that recorded one. So the first option leaves the
        stream one octet ahead of where ``length`` thinks it is, the second
        option consumes the last of it, and the third finds the stream exhausted,
        reads ``b''`` for every field, and reports ``len(data) == 0`` -- against
        which ``length -= len(data)`` makes no progress at all. C.f. #431, where
        this spun forever on an eight-octet HOPOPT header.

        The deadline is part of the test: without it a regression here does not
        fail, it hangs the run.

        """
        from pcapkit.utilities.exceptions import FieldValueError

        schema = self._make_wrapped_options_schema()

        with self.assertRaisesRegex(FieldValueError, 'consumed no data'):
            with time_limit(5):
                schema.unpack(b'\x01\xff\x00', 3, {})

    def test_schema_option_field_unpack_reports_a_field_relative_offset(self) -> None:
        """The offset in the diagnostic counts from the option area, not the stream.

        :meth:`OptionField.unpack
        <pcapkit.corekit.fields.collections.OptionField.unpack>` is handed a
        :obj:`bytes` buffer by
        :meth:`Schema.unpack <pcapkit.protocols.schema.schema.Schema.unpack>`, so
        its stream starts at zero and the two readings coincide -- but the method
        is public and takes an ``IO[bytes]`` as well, and a
        :class:`~pcapkit.corekit.fields.misc.SchemaField` hands the live file
        straight down. Reporting the raw stream position then names an offset
        outside the field: the same three-octet area that fails at offset 3 below
        reported offset 5 when the stream was two octets in.

        """
        from pcapkit.utilities.exceptions import FieldValueError

        schema = self._make_wrapped_options_schema()
        field = schema.__fields__['options']

        stream = io.BytesIO(b'\xde\xad' + b'\x01\xff\x00')
        stream.seek(2)

        with self.assertRaisesRegex(FieldValueError, r'at offset 3 of 3\b'):
            with time_limit(5):
                field.unpack(stream, {})

    def test_schema_list_field_unpack_rejects_a_schema_item_consuming_nothing(self) -> None:
        """A list of schema items must be advanced past too, or reported.

        :meth:`ListField.unpack
        <pcapkit.corekit.fields.collections.ListField.unpack>` sizes a schema item
        by ``len(data)`` in the same way, so a budget larger than the octets behind
        it leaves the item schema reading an exhausted stream, recording nothing,
        and subtracting nothing. Reachable from a TCP segment whose ``SACK`` option
        declares more octets than the option area holds, which
        :file:`tests/protocols/transport/test_tcp_udp_unit.py` pins; this covers
        the field on its own, and pins the offset as a count into the field rather
        than into the stream -- the same reading as its ``OptionField`` subclass.

        Two items parse off the two octets below and the third finds the stream
        exhausted, so the diagnostic's ``after 2 item(s)`` is a count of what was
        parsed rather than an ordinal naming the second item.

        """
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final
        from pcapkit.utilities.exceptions import FieldValueError

        @schema_final
        class Marker(Schema):
            type: int = UInt8Field(default=0)

        @schema_final
        class MarkerListSchema(Schema):
            #: Eight octets of budget, however few are really there.
            markers: list[Marker] = ListField(
                length=8,
                item_type=SchemaField(length=2, schema=Marker),
            )

        field = MarkerListSchema.__fields__['markers']

        stream = io.BytesIO(b'\xde\xad' + b'\x01\x02')
        stream.seek(2)

        with self.assertRaisesRegex(FieldValueError, r'after 2 item\(s\), at offset 2 of 8\b'):
            with time_limit(5):
                field.unpack(stream, {})

    def _make_previewed_item_schema(self):
        """A schema whose length is peeked before it is read for real.

        Returns:
            A :class:`~pcapkit.protocols.schema.schema.Schema` subclass with a
            :class:`~pcapkit.corekit.fields.misc.ForwardMatchField` that previews
            the very octet ``length`` then reads again for real -- the shape
            :class:`~pcapkit.protocols.schema.internet.mh.CGAParameter`'s
            ``public_key_test`` has, minimised to one octet. ``length_peek``
            consumes nothing from the stream (:meth:`Schema.unpack
            <pcapkit.protocols.schema.schema.Schema.unpack>` rewinds past it), so
            an instance built from ``b'\\x02AB'`` reads 3 octets off the wire --
            not 4 -- and :meth:`Schema.__len__
            <pcapkit.protocols.schema.schema.Schema.__len__>` is expected to agree.

        """
        from pcapkit.corekit.fields.misc import ForwardMatchField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class PreviewedItem(Schema):
            #: Non-consuming preview of ``length``, read again below.
            length_peek: int = ForwardMatchField(UInt8Field(default=0))
            #: The same octet, read for real this time.
            length: int = UInt8Field(default=0)
            #: Sized from the peeked (and re-read) ``length``.
            data: bytes = BytesField(length=lambda pkt: pkt['length'], default=b'')

        return PreviewedItem

    def test_forward_match_field_does_not_count_toward_length(self) -> None:
        """A ``ForwardMatchField`` reads octets but must not be billed for them.

        Before the fix, :meth:`Schema.unpack
        <pcapkit.protocols.schema.schema.Schema.unpack>` kept the octets a
        :class:`~pcapkit.corekit.fields.misc.ForwardMatchField` read in
        ``__buffer__`` even though it rewinds the stream past them, so
        ``len(schema)`` double-counted them: the same octet is read once by
        ``length_peek`` (kept in the buffer) and again for real by ``length``
        (also kept), so a 3-octet input reported length 4. See #446.

        """
        PreviewedItem = self._make_previewed_item_schema()

        unpacked = PreviewedItem.unpack(b'\x02AB', 3, {})

        self.assertEqual(unpacked.length, 2)
        self.assertEqual(unpacked.data, b'AB')
        # 1 octet for ``length_peek``/``length`` together (not 2, one per
        # field) plus 2 octets of ``data`` -- the input's own 3 octets, not the
        # 4 a double-counted forward match would report.
        self.assertEqual(len(unpacked), 3)
        self.assertEqual(bytes(unpacked), b'\x02AB')

    def test_schema_list_field_rejects_a_declared_area_that_a_forward_match_over_reports(self) -> None:
        """The failure mode #446 is about: a correct declared area, rejected.

        Two ``PreviewedItem``s take two octets each off the wire -- four in
        total -- and :class:`~pcapkit.corekit.fields.collections.ListField`
        is given exactly that as its declared ``length``. Before the fix, each
        item's over-reported ``len(data)`` (3, not 2) drains the budget one
        octet too fast: ``4 - 3 = 1`` after the first item, then ``1 - 3 = -2``
        on the second, and :meth:`ListField.unpack
        <pcapkit.corekit.fields.collections.ListField.unpack>` raises
        ``FieldValueError`` on input that is exactly the right length. This is
        the same mechanism that fails
        :class:`~pcapkit.protocols.schema.internet.mh.CGAParametersOption`'s
        ``parameters`` :class:`~pcapkit.corekit.fields.collections.ListField`
        of :class:`~pcapkit.protocols.schema.internet.mh.CGAParameter` items --
        each carrying its own load-bearing ``public_key_test``
        ``ForwardMatchField`` -- with the identical
        ``FieldValueError: Field parameters has invalid length.``, minimised so
        it needs neither a CGA parameter nor its option registry.

        """
        from pcapkit.corekit.fields.collections import ListField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.protocols.schema.schema import Schema, schema_final

        PreviewedItem = self._make_previewed_item_schema()

        @schema_final
        class PreviewedItemListSchema(Schema):
            #: Four octets of budget, exactly what two ``PreviewedItem``s take.
            markers: list[PreviewedItem] = ListField(  # type: ignore[valid-type]
                length=4,
                item_type=SchemaField(length=2, schema=PreviewedItem),
            )

        field = PreviewedItemListSchema.__fields__['markers']
        unpacked = field.unpack(b'\x01A\x01B', {})

        self.assertEqual(len(unpacked), 2)
        self.assertEqual(unpacked[0].data, b'A')
        self.assertEqual(unpacked[1].data, b'B')

    def _make_wrapped_options_schema(self):
        """A three-octet option area whose first option over-reads by one octet.

        Returns:
            A :class:`~pcapkit.protocols.schema.schema.Schema` subclass carrying a
            single :class:`~pcapkit.corekit.fields.collections.OptionField`.

        ``Wrapper`` is the smallest thing that separates the octets an option takes
        from the stream from the ``len(data)`` it reports, and is the shape every
        wrapper option schema in the package has: it reads two octets and returns a
        nested schema that recorded one.

        """
        from pcapkit.corekit.fields.collections import OptionField
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @schema_final
        class Marker(Schema):
            type: int = UInt8Field(default=0)

        @schema_final
        class Wrapper(Schema):
            #: Two octets of stream, of which ``Marker`` records only the first.
            body: Marker = SchemaField(length=2, schema=Marker)

            def post_process(self, packet: dict) -> Schema:
                return self.body

        @schema_final
        class WrappedOptionsSchema(Schema):
            options: list[Marker] = OptionField(
                length=3,
                base_schema=Marker,
                registry=collections.defaultdict(lambda: Marker, {1: Wrapper}),
            )

        return WrappedOptionsSchema


if __name__ == '__main__':
    unittest.main()
