from __future__ import annotations

import collections
import enum
import importlib.util
import io
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ProtocolBaseUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _make_protocol_class(self):
        from pcapkit.corekit.infoclass import info_final
        from pcapkit.corekit.fields.misc import PayloadField
        from pcapkit.corekit.protochain import ProtoChain
        from pcapkit.protocols.data.data import Data
        from pcapkit.protocols.protocol import Protocol
        from pcapkit.protocols.schema.schema import Schema, schema_final

        @info_final
        class DummyData(Data):
            value: int = 0

        @schema_final
        class DummySchema(Schema):
            payload: bytes = PayloadField(length=lambda packet: packet['__length__'], default=b'')

        class DummyProtocol(Protocol[DummyData, DummySchema],
                            schema=DummySchema, data=DummyData):
            __layer__ = 'Internet'
            __proto__ = collections.defaultdict(lambda: None)

            @property
            def name(self) -> str:
                return 'Dummy Protocol'

            @property
            def length(self) -> int:
                return 2

            def read(self, length: int | None = None, **kwargs: object) -> DummyData:
                data = DummyData(value=kwargs.get('value', 0))
                self._next = kwargs.get('next_protocol')
                if self._next is None:
                    from pcapkit.protocols.misc.null import NoPayload
                    self._next = NoPayload()
                self._protos = ProtoChain(self.__class__, self.alias, basis=self._next.protochain)
                return data

            def make(self, packet: bytes = b'ab', **kwargs: object) -> DummySchema:
                return DummySchema(payload=packet)

            @classmethod
            def __index__(cls) -> int:
                return 250

        return DummyProtocol, DummyData, DummySchema

    def test_basic_properties_repr_str_and_packet_cache(self) -> None:
        DummyProtocol, _, _ = self._make_protocol_class()
        from pcapkit.utilities.exceptions import UnsupportedCall

        proto = DummyProtocol(packet=b'abcd', value=7)

        self.assertEqual(proto.name, 'Dummy Protocol')
        self.assertEqual(proto.alias, 'DummyProtocol')
        self.assertEqual(proto.info_name, 'dummyprotocol')
        self.assertEqual(proto.info.to_dict()['value'], 7)
        self.assertEqual(proto.data, b'abcd')
        self.assertEqual(bytes(proto), b'abcd')
        self.assertEqual(len(proto), 4)
        self.assertEqual(proto.protocol, 'DummyProtocol')
        self.assertEqual(proto.schema.to_dict()['payload'], b'abcd')
        self.assertEqual(proto.packet.header, b'ab')
        self.assertEqual(proto.packet.payload, b'cd')
        self.assertIn('DummyProtocol', repr(proto))
        self.assertIn('61 62 63 64', str(proto))
        self.assertEqual(repr(proto), repr(proto))
        self.assertEqual(str(proto), str(proto))
        self.assertEqual(len(proto), len(proto))
        self.assertEqual(proto.__length_hint__(), None)
        self.assertEqual(proto.__hash__(), hash(b'abcd'))
        self.assertEqual(proto.__index__(), 250)
        self.assertEqual(proto.__iter__().read(), b'abcd')

        self.assertEqual(proto._file.tell(), 0)
        self.assertEqual(proto._read_packet(header=1, payload=2, discard=True), b'bc')
        self.assertEqual(proto._file.tell(), 0)
        self.assertEqual(proto._read_packet(3), b'abc')
        self.assertEqual(proto._file.tell(), 0)
        self.assertEqual(proto._get_payload(), b'abcd')

        no_protocol = object.__new__(DummyProtocol)
        no_protocol._protos = []
        self.assertIsNone(no_protocol.protocol)

        fallback_packet = object.__new__(DummyProtocol)
        fallback_packet.__cached__ = {}
        fallback_packet._data = b'fallback'
        fallback_packet._read_packet = mock.Mock(side_effect=[UnsupportedCall('fallback'), b'payload'])
        self.assertEqual(fallback_packet.packet.header, b'')
        self.assertEqual(fallback_packet.packet.payload, b'payload')

    def test_pack_unpack_from_schema_and_from_data(self) -> None:
        DummyProtocol, DummyData, RawSchema = self._make_protocol_class()

        proto = DummyProtocol(packet=b'xy')
        self.assertEqual(proto.pack(packet=b'zz'), b'zz')

        proto_from_schema = DummyProtocol.from_schema({'payload': b'12'})
        self.assertIsInstance(proto_from_schema.schema, RawSchema)
        self.assertEqual(bytes(proto_from_schema), b'12')

        schema_obj = RawSchema(payload=b'34')
        proto_from_schema_obj = DummyProtocol.from_schema(schema_obj)
        self.assertEqual(bytes(proto_from_schema_obj), b'34')

        proto_from_data = DummyProtocol.from_data(DummyData(value=9))
        self.assertEqual(proto_from_data.info.to_dict()['value'], 9)
        self.assertEqual(bytes(proto_from_data), b'ab')

        proto_from_dict = DummyProtocol.from_data({'value': 10})
        self.assertEqual(proto_from_dict.info.to_dict()['value'], 10)

    def test_decode_and_unquote_fallbacks(self) -> None:
        from pcapkit.protocols.protocol import ProtocolBase

        self.assertEqual(ProtocolBase.decode(b'hello', encoding='ascii'), 'hello')
        self.assertEqual(ProtocolBase.decode(bytes([0xff]), encoding='ascii'), '\xff')
        self.assertEqual(ProtocolBase.unquote('hello%20world'), 'hello world')

        with mock.patch('urllib.parse.unquote', side_effect=UnicodeDecodeError('x', b'%', 0, 1, 'bad')):
            self.assertEqual(ProtocolBase.unquote('%41%42'), 'AB')

    def test_expand_comp_eq_contains_and_getitem(self) -> None:
        DummyProtocol, _, _ = self._make_protocol_class()
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import ProtocolNotFound

        payload = Raw(packet=b'body')
        proto = DummyProtocol(packet=b'ab', next_protocol=payload)

        self.assertEqual(DummyProtocol.expand_comp(DummyProtocol),
                         (DummyProtocol, 'DUMMYPROTOCOL'))
        self.assertEqual(DummyProtocol.expand_comp(proto),
                         (DummyProtocol, 'DUMMYPROTOCOL'))
        self.assertIn(Raw, DummyProtocol.expand_comp('Raw'))
        self.assertEqual(DummyProtocol.expand_comp('unknown-proto'), ('UNKNOWN-PROTO',))

        self.assertTrue(DummyProtocol.__eq__(proto))
        self.assertTrue(DummyProtocol.__eq__(DummyProtocol))
        self.assertTrue(DummyProtocol.__eq__('dummyprotocol'))
        self.assertFalse(DummyProtocol.__eq__(object()))
        self.assertIn('dummyprotocol', proto)
        self.assertIn(Raw, proto)
        self.assertIs(proto['dummyprotocol'], proto)
        self.assertIs(proto[Raw], payload)
        self.assertNotIn('missing', proto)
        with self.assertRaises(ProtocolNotFound):
            _ = proto['missing']

    def test_integer_read_pack_and_make_index_variants(self) -> None:
        DummyProtocol, _, _ = self._make_protocol_class()
        from pcapkit.utilities.exceptions import ProtocolNotImplemented, StructError

        class Number(enum.IntEnum):
            one = 1
            two = 2

        proto = DummyProtocol(packet=b'\x01\x02\x03\x04\x05\x06\x07\x08')

        self.assertEqual(proto._read_unpack(1), 1)
        self.assertEqual(proto._read_unpack(2), 0x0203)
        self.assertEqual(proto._read_unpack(4), 0x04050607)
        proto._file = io.BytesIO(b'\x01\x02\x03\x04\x05\x06\x07\x08')
        self.assertEqual(proto._read_unpack(8, signed=True), 0x0102030405060708)

        proto._file = io.BytesIO(b'\x01\x02\x03')
        self.assertEqual(proto._read_unpack(3), 0x010203)
        proto._file = io.BytesIO(b'\x01')
        self.assertEqual(proto._read_unpack(2, quiet=True), 1)
        proto._file = io.BytesIO(b'\x01')
        with self.assertRaises(StructError):
            proto._read_unpack(2)
        proto._file = io.BytesIO(b'\x01\x02\x03')
        self.assertEqual(proto._read_binary(2), '0000000100000010')
        proto._file = io.BytesIO(b'')
        with self.assertRaises(StructError):
            proto._read_unpack()

        self.assertEqual(DummyProtocol._make_pack(0x0102030405060708, size=8),
                         b'\x01\x02\x03\x04\x05\x06\x07\x08')
        self.assertEqual(DummyProtocol._make_pack(-2, size=4, signed=True),
                         b'\xff\xff\xff\xfe')
        self.assertEqual(DummyProtocol._make_pack(0x0102, size=2), b'\x01\x02')
        self.assertEqual(DummyProtocol._make_pack(0x0102, size=2, lilendian=True), b'\x02\x01')
        self.assertEqual(DummyProtocol._make_pack(0x010203, size=3), b'\x01\x02\x03')
        with self.assertRaises(StructError):
            DummyProtocol._make_pack(256, size=1)

        self.assertEqual(DummyProtocol._make_index(Number.one), 1)
        self.assertEqual(DummyProtocol._make_index(7), 7)
        self.assertEqual(DummyProtocol._make_index('one', namespace=Number), 1)
        self.assertEqual(DummyProtocol._make_index('tcp', namespace={6: 'tcp'}), 6)
        self.assertEqual(DummyProtocol._make_index('tcp', namespace={'tcp': 6}, reversed=True), 6)
        self.assertEqual(DummyProtocol._make_index('missing', default=99), 99)
        self.assertEqual(DummyProtocol._make_index('one', namespace=Number, pack=True, size=1), b'\x01')
        with self.assertRaises(ProtocolNotImplemented):
            DummyProtocol._make_index('missing')

    def test_register_analyze_and_next_layer_paths(self) -> None:
        DummyProtocol, DummyData, _ = self._make_protocol_class()
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.exceptions import RegistryError

        with self.assertRaises(RegistryError):
            DummyProtocol.register(1, object)  # type: ignore[arg-type]

        DummyProtocol.register(9, ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'))
        self.assertIs(DummyProtocol.__proto__[9], Raw)

        with mock.patch('pcapkit.protocols.protocol.warn') as warn:
            DummyProtocol.register(1, Raw)
            DummyProtocol.register(1, Raw)
        self.assertGreaterEqual(warn.call_count, 1)

        DummyProtocol.__proto__ = collections.defaultdict(
            lambda: Raw,
            {4: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')},
        )
        analyzed_module = DummyProtocol.analyze(4, b'module-body', alias=4)
        self.assertIsInstance(analyzed_module, Raw)
        self.assertIs(DummyProtocol.__proto__[4], Raw)

        DummyProtocol.__proto__ = collections.defaultdict(lambda: Raw, {1: Raw})
        analyzed = DummyProtocol.analyze(1, b'raw-body', alias=1)
        self.assertIsInstance(analyzed, Raw)
        self.assertEqual(bytes(analyzed), b'raw-body')

        class BrokenRaw(ProtocolBase):
            @property
            def name(self) -> str:
                return 'Broken'

            @property
            def length(self) -> int:
                return 0

            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                raise ValueError('boom')

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

            @classmethod
            def __index__(cls) -> int:
                return 0

        class EOFProtocol(ProtocolBase):
            @property
            def name(self) -> str:
                return 'EOF'

            @property
            def length(self) -> int:
                return 0

            def __init__(self, payload_io: io.BytesIO, length: int, **kwargs: object) -> None:
                from pcapkit.utilities.exceptions import StructError
                raise StructError('eof', eof=True, quiet=True)

            def read(self, length: int | None = None, **kwargs: object) -> object:
                raise NotImplementedError

            def make(self, **kwargs: object) -> object:
                raise NotImplementedError

            @classmethod
            def __index__(cls) -> int:
                return 0

        DummyProtocol.__proto__ = collections.defaultdict(lambda: BrokenRaw, {2: BrokenRaw, 3: EOFProtocol})
        self.assertIsInstance(DummyProtocol.analyze(2, b'bad'), Raw)
        from pcapkit.protocols.misc.null import NoPayload
        self.assertIsInstance(DummyProtocol.analyze(3, b''), NoPayload)

        proto = DummyProtocol(packet=b'abpayload')
        decoded = proto._decode_next_layer(DummyData(value=3), 1, length=3)
        self.assertIs(decoded.__next_type__, Raw)
        self.assertEqual(decoded.__next_name__, 'raw')
        self.assertIsInstance(proto.payload, Raw)
        self.assertIn('Raw', str(proto.protochain))

        proto_zero = DummyProtocol(packet=b'ab')
        self.assertIsInstance(proto_zero._import_next_layer(1, 0), NoPayload)

        proto_module = DummyProtocol(packet=b'abmodule')
        proto_module._sigterm = False
        proto_module.__proto__ = collections.defaultdict(
            lambda: Raw,
            {5: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')},
        )
        self.assertIsInstance(proto_module._import_next_layer(5, None), Raw)
        self.assertIs(proto_module.__proto__[5], Raw)

        proto_stop = DummyProtocol(packet=b'abpayload', _protocol='dummyprotocol')
        self.assertTrue(proto_stop._check_term_threshold())
        self.assertIsInstance(proto_stop._import_next_layer(1, 3), Raw)

        layer_stop = object.__new__(DummyProtocol)
        layer_stop._exlayer = 'internet'
        layer_stop._exproto = None
        self.assertTrue(layer_stop._check_term_threshold())

        no_stop = object.__new__(DummyProtocol)
        no_stop._exlayer = None
        no_stop._exproto = 'raw'
        self.assertFalse(no_stop._check_term_threshold())

    def test_make_payload_branches(self) -> None:
        DummyProtocol, DummyData, _ = self._make_protocol_class()
        from pcapkit.protocols.misc.null import NoPayload

        self.assertIsInstance(DummyProtocol._make_payload({}), NoPayload)  # type: ignore[arg-type]
        self.assertIsInstance(DummyProtocol._make_payload({  # type: ignore[arg-type]
            '__next_type__': object,
        }), NoPayload)
        self.assertIsInstance(DummyProtocol._make_payload({  # type: ignore[arg-type]
            '__next_type__': DummyProtocol,
        }), NoPayload)

        payload = DummyProtocol._make_payload({  # type: ignore[arg-type]
            '__next_type__': DummyProtocol,
            '__next_name__': 'inner',
            'inner': DummyData(value=12),
        })
        self.assertIsInstance(payload, DummyProtocol)
        self.assertEqual(payload.info.to_dict()['value'], 12)


if __name__ == '__main__':
    unittest.main()
