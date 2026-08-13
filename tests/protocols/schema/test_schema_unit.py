from __future__ import annotations

import builtins
import collections
import enum
import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules

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

    def test_schema_update_unknown_fields_and_builtin_field_mapping(self) -> None:
        _, _, _, _, BuiltinNameSchema = self._make_schema_classes()

        schema = BuiltinNameSchema.__new__(BuiltinNameSchema)
        schema.__update__({'items': 7})

        self.assertEqual(schema['items'], 7)
        self.assertEqual(list(schema), ['items'])
        self.assertEqual(schema.to_dict(), {'items': 7})
        self.assertIn('items=7', str(schema))
        self.assertIn('items=7', repr(schema))

        with mock.patch('pcapkit.protocols.schema.schema.warn') as warn:
            schema.__update__({'missing': 1})
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

        BaseEnumSchema.register(Code.two, OneSchema)
        self.assertIs(BaseEnumSchema.registry[Code.two], OneSchema)
        self.assertIs(BaseEnumSchema.from_dict().registry, BaseEnumSchema.registry)

    def test_schema_final_generated_init_and_legacy_version_branch(self) -> None:
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema.schema import Schema, schema_final

        class GeneratedInitSchema(Schema):
            value: int = UInt8Field(default=1)

        class EmptyGeneratedSchema(Schema):
            pass

        original_hasattr = builtins.hasattr

        def fake_hasattr(obj: object, name: str) -> bool:
            if obj in (GeneratedInitSchema, EmptyGeneratedSchema) and name == '__init__':
                return False
            return original_hasattr(obj, name)

        with mock.patch('builtins.hasattr', side_effect=fake_hasattr):
            GeneratedInitSchema = schema_final(GeneratedInitSchema)
            EmptyGeneratedSchema = schema_final(EmptyGeneratedSchema)

        self.assertEqual(bytes(GeneratedInitSchema(value=2)), b'\x02')
        self.assertEqual(bytes(GeneratedInitSchema()), b'\x01')
        self.assertEqual(bytes(EmptyGeneratedSchema()), b'')

        with mock.patch('pcapkit.protocols.schema.schema.sys.version_info', (3, 10)):
            class LegacyVersionSchema(Schema):
                value: int = UInt8Field(default=3)

        self.assertIn('value', LegacyVersionSchema.__fields__)

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
        schema.__update__({'value': 4})

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


if __name__ == '__main__':
    unittest.main()
