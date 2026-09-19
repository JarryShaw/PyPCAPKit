from __future__ import annotations

import collections
import enum
import importlib.util
import io
import ipaddress
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

        schema_from_dict = RawSchema(payload=b'12')
        with mock.patch.object(RawSchema, 'from_dict', return_value=schema_from_dict) as from_dict:
            proto_from_schema = DummyProtocol.from_schema({'payload': b'12'})
        from_dict.assert_called_once_with({'payload': b'12'})
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

    def test_lookup_registry_reads_the_fallback_without_recording_it(self) -> None:
        """The non-recording lookup is generic over what the registry holds.

        ``__proto__`` maps to protocol classes, but the ``__option__`` /
        ``__chunk__`` / ``__block__`` family maps to *method names* -- a
        :obj:`str`, or a ``(parser, constructor)`` pair. Those have no
        :class:`~pcapkit.corekit.module.ModuleDescriptor` to resolve, so they
        want the lookup on its own, which is why it is a helper of its own rather
        than something buried inside
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._lookup_next_layer`.

        """
        DummyProtocol, _, _ = self._make_protocol_class()

        parser, constructor = object(), object()
        registry = collections.defaultdict(lambda: 'donone', {
            2: 'mss',
            3: (parser, constructor),
        })

        # A hit is returned as it is, whichever shape it has.
        self.assertEqual(DummyProtocol._lookup_registry(registry, 2), 'mss')
        self.assertEqual(DummyProtocol._lookup_registry(registry, 3),
                         (parser, constructor))

        # A miss reads the declared fallback and leaves no trace.
        self.assertEqual(DummyProtocol._lookup_registry(registry, 156), 'donone')
        self.assertNotIn(156, registry)
        self.assertEqual(set(registry), {2, 3})

        # A tuple key -- which is what ``PCAPNG.__option__`` is keyed on, since
        # its option codes collide across block namespaces -- is no different.
        namespaced = collections.defaultdict(lambda: 'unknown', {('if', 2): 'if_name'})
        self.assertEqual(DummyProtocol._lookup_registry(namespaced, ('if', 2)), 'if_name')
        self.assertEqual(DummyProtocol._lookup_registry(namespaced, ('if', 42)), 'unknown')
        self.assertEqual(set(namespaced), {('if', 2)})

    def test_lookup_next_layer_reads_the_fallback_without_recording_it(self) -> None:
        """A missed lookup must not turn into a registration.

        ``__proto__`` is a :class:`collections.defaultdict` on a class
        attribute, so ``__proto__[code]`` inserts every code it is handed. The
        insertion is worth nothing -- the value is the fallback the factory
        would have produced anyway -- and it costs a spurious "already
        registered" warning on the next real
        :meth:`~pcapkit.protocols.protocol.ProtocolBase.register` call.

        Resolving a :class:`~pcapkit.corekit.module.ModuleDescriptor` for a code
        that *is* registered still writes back, since that is memoisation of an
        import rather than a new entry.

        """
        DummyProtocol, _, _ = self._make_protocol_class()
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.protocols.misc.raw import Raw

        DummyProtocol.__proto__ = collections.defaultdict(
            lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
            {7: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw')},
        )

        registry = DummyProtocol.__proto__

        # A miss resolves to the declared fallback and leaves no trace.
        self.assertIs(DummyProtocol._lookup_next_layer(registry, 99), Raw)
        self.assertNotIn(99, registry)
        self.assertEqual(set(registry), {7})

        # A hit resolves the descriptor once and keeps the resolved class.
        self.assertIs(DummyProtocol._lookup_next_layer(registry, 7), Raw)
        self.assertIs(registry[7], Raw)

        # A class registered directly is returned as it is.
        registry[8] = Raw
        self.assertIs(DummyProtocol._lookup_next_layer(registry, 8), Raw)

        # ``analyze`` and ``_import_next_layer`` both go through the lookup, so
        # neither of them records an unregistered code either.
        self.assertIsInstance(DummyProtocol.analyze(99, b'body'), Raw)
        proto = DummyProtocol(packet=b'abpayload')
        proto._sigterm = False
        self.assertIsInstance(proto._import_next_layer(99, 3), Raw)
        self.assertEqual(set(DummyProtocol.__proto__), {7, 8})

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

    def test_parse_limits_accept_the_spelling_every_producer_uses(self) -> None:
        """``layer=``/``protocol=`` are honoured while parsing, ignored while making.

        The limits are documented on ``ProtocolBase.__init__`` as ``_layer`` and
        ``_protocol``, but nothing in the tree spells them that way: the engines
        and every ``_import_next_layer`` pass them without the underscore, so
        both were silently dropped (GH-356). Both spellings therefore have to
        work, and the prefixed one has to win when the two disagree.

        The un-prefixed pair may only be consumed while *parsing*, though.
        ``protocol`` is a real ``make()`` argument -- ``IPv4.make`` takes one, and
        ``Data_IPv6.to_dict`` carries one straight into ``from_data`` -- so
        swallowing it on the construction path would silently drop the value
        being constructed.

        """
        DummyProtocol, _, _ = self._make_protocol_class()

        for keywords, layer, proto in (
            ({'_layer': 'Internet'}, 'Internet', None),
            ({'layer': 'Internet'}, 'Internet', None),
            ({'_protocol': 'dummyprotocol'}, None, 'dummyprotocol'),
            ({'protocol': 'dummyprotocol'}, None, 'dummyprotocol'),
            # the prefixed spelling wins over the un-prefixed one
            ({'_layer': 'Internet', 'layer': 'Transport'}, 'Internet', None),
        ):
            with self.subTest(**keywords):
                parsed = DummyProtocol(io.BytesIO(b'abpayload'), 9, **keywords)

                self.assertEqual(parsed._exlayer, layer)
                self.assertEqual(parsed._exproto, proto)
                self.assertTrue(parsed._sigterm)

        # ... and the un-prefixed pair reaches ``make()`` untouched when there is
        # no source stream, i.e. nothing is being parsed.
        made = DummyProtocol(packet=b'abpayload', protocol='dummyprotocol', layer='Internet')
        self.assertIsNone(made._exlayer)
        self.assertIsNone(made._exproto)
        self.assertFalse(made._sigterm)

    def test_no_limit_sentinels_are_not_treated_as_a_limit(self) -> None:
        """``layer='none'`` and ``protocol='null'`` mean "no limit", not a name.

        They are what ``Extractor.__init__`` substitutes for an omitted argument,
        so they reach every protocol of every packet and must not be compared
        against real protocol names.

        """
        DummyProtocol, _, _ = self._make_protocol_class()

        for keywords in ({'layer': 'none'}, {'layer': 'NONE'}, {'protocol': 'null'},
                         {'_layer': 'none'}, {'_protocol': 'null'},
                         {'layer': 'none', 'protocol': 'null'}):
            with self.subTest(**keywords):
                parsed = DummyProtocol(io.BytesIO(b'abpayload'), 9, **keywords)

                self.assertIsNone(parsed._exlayer)
                self.assertIsNone(parsed._exproto)
                self.assertFalse(parsed._sigterm)

    def test_packet_context_is_republished_as_dunder_packet(self) -> None:
        """The enclosing layer's ``packet=`` reaches ``unpack`` as ``__packet__``.

        ``_import_next_layer`` hands the next protocol its packet context as
        ``packet=``, but the schema layer reads it from ``__packet__``
        (``Protocol.unpack``, and the ``pack``/``unpack`` overrides of ``Frame``
        and ``PCAPNG``). Nothing bridged the two, so a schema always saw an empty
        dict (GH-382).

        The republished dict is a *copy*: ``Schema.unpack`` writes every field it
        reads into the context it is handed, and the IPv6 extension header walk
        gives one dict to each header in turn, so sharing it would leak one
        header's fields into the next one's context.

        """
        DummyProtocol, _, _ = self._make_protocol_class()

        seen = {}  # type: dict[str, object]
        original = DummyProtocol.unpack

        def capture(self, length=None, **kwargs):
            # Snapshot before delegating: ``Schema.unpack`` writes its own
            # ``__length__`` and every field it reads into the context, so what
            # arrived is only observable ahead of the call.
            seen['snapshot'] = dict(kwargs.get('__packet__') or {})
            seen['identity'] = kwargs.get('__packet__')
            seen['packet'] = kwargs.get('packet')
            return original(self, length, **kwargs)

        DummyProtocol.unpack = capture  # type: ignore[method-assign]
        try:
            outer = {'src': 'the-source', 'dst': 'the-destination'}
            DummyProtocol(io.BytesIO(b'abpayload'), 9, packet=outer)
        finally:
            DummyProtocol.unpack = original  # type: ignore[method-assign]

        self.assertEqual(seen['snapshot'], {'src': 'the-source', 'dst': 'the-destination'})
        # A copy, and the enclosing layer's own dict is left exactly as it was.
        self.assertIsNot(seen['identity'], outer)
        self.assertEqual(outer, {'src': 'the-source', 'dst': 'the-destination'})
        # ``packet=`` is left in place as well, since it is the documented
        # ``_import_next_layer`` spelling and some callers still read it.
        self.assertIs(seen['packet'], outer)

    def test_explicit_dunder_packet_is_not_overridden(self) -> None:
        """A caller that already supplies ``__packet__`` keeps its own dict.

        The PCAP-NG engine does exactly that -- it passes the section's snapshot
        length as ``__packet__`` -- so the bridge must only fill the keyword in
        when it is absent.

        """
        DummyProtocol, _, _ = self._make_protocol_class()

        seen = {}  # type: dict[str, object]
        original = DummyProtocol.unpack

        def capture(self, length=None, **kwargs):
            seen['identity'] = kwargs.get('__packet__')
            return original(self, length, **kwargs)

        DummyProtocol.unpack = capture  # type: ignore[method-assign]
        try:
            chosen = {'snaplen': 262144}
            DummyProtocol(io.BytesIO(b'abpayload'), 9,
                          packet={'src': 'ignored'}, __packet__=chosen)
        finally:
            DummyProtocol.unpack = original  # type: ignore[method-assign]

        self.assertIs(seen['identity'], chosen)

    def test_outer_address_reaches_a_schema_that_needs_it(self) -> None:
        """A real consumer of the packet context gets its value (GH-382).

        RFC 7731 lets an MPL option elide its Seed-ID from the wire when the
        Seed-ID type is ``IPV6_SOURCE_ADDRESS``, in which case the seed *is* the
        enclosing IPv6 source address.
        ``pcapkit.protocols.schema.internet.hopopt.MPLOption.post_process``
        implements that by reading ``packet['src']`` -- a value only the outer
        layer knows -- and ``IPv6.read`` does put it in the dict it hands down.
        The dict never arrived as ``__packet__``, so the seed silently came back
        as :data:`None` for every such option.

        The capture is built here rather than read from
        :file:`examples/captures/`: this is a unit-tier module, and none of the
        committed captures carries an MPL option.

        """
        from pcapkit.const.ipv6.seed_id import SeedID
        from pcapkit.protocols.internet.ipv6 import IPv6

        source = ipaddress.IPv6Address('2001:db8::1')
        destination = ipaddress.IPv6Address('ff02::1')

        #: One HOPOPT extension header, eight octets: an MPL option whose
        #: Seed-ID is elided, then two ``Pad1`` octets to fill the header out.
        hopopt = bytes([
            59,     # next header: IPv6-NoNxt
            0,      # hdr ext len: 0, i.e. 8 octets in total
            0x6D,   # option type: MPL_Option
            0x02,   # opt data len: 2 -- flags and sequence only, seed elided
            0x00,   # flags: S=0b00 (IPV6_SOURCE_ADDRESS), M=0, V=0
            0x2A,   # sequence
            0x00,   # option type: Pad1
            0x00,   # option type: Pad1
        ])
        packet = (bytes([0x60, 0x00, 0x00, 0x00])            # version, traffic class, flow label
                  + len(hopopt).to_bytes(2, 'big')           # payload length
                  + bytes([0, 64])                           # next header: HOPOPT; hop limit
                  + source.packed + destination.packed
                  + hopopt)

        parsed = IPv6(io.BytesIO(packet), len(packet))
        option = list(parsed.info.hopopt.options.values())[0]

        self.assertEqual(str(parsed.protochain), 'IPv6:HOPOPT')
        self.assertEqual(parsed.info.src, source)
        self.assertEqual(option.seed_type, SeedID.IPV6_SOURCE_ADDRESS)
        self.assertEqual(option.seed_id, source)


if __name__ == '__main__':
    unittest.main()
