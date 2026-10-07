# -*- coding: utf-8 -*-
"""Construction through ``make()`` in :class:`~pcapkit.protocols.protocol.Protocol`.

GitHub issue #1312: :meth:`~pcapkit.protocols.protocol.ProtocolBase.unpack`
reused the schema :meth:`~pcapkit.protocols.protocol.ProtocolBase.pack` had
made instead of parsing the packed octets, so ``read`` met the raw
:obj:`bytes` (or :class:`~pcapkit.protocols.schema.schema.Schema`) items
the option makers accept, and construction crashed with
:exc:`AttributeError`. A bare ``MH()`` crashed the same way on its default
``data=b'\\x00\\x00'``. A made schema holding raw octets where parsing its
packed form yields a schema is now replaced by the parsed one.

GitHub issue #1308: a :obj:`str` member name given to two enum arguments
of one ``make()`` raised ``ambiguous member name`` when only one of the
enumerations had it. Each ``_make_index`` call now resolves against the
argument it was passed.

Every case builds its own packet in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they belong to the live
:mod:`pcapkit` import.

"""

import importlib
import unittest
import unittest.mock
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


def _attr(path: 'str') -> 'Any':
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


#: One raw item per protocol whose ``make()`` accepts raw octets in a list:
#: (protocol class, construction keywords, packed octets).
RAW_ITEMS = {
    'HIP parameters': ('pcapkit.protocols.internet.hip.HIP',
                       {'extension': True, 'parameters': [b'\x00\x41\x00\x0c' + bytes(12)]},
                       '1106206100000000' + '00' * 32 + '0041000c' + '00' * 12),
    'IPv4 options': ('pcapkit.protocols.internet.ipv4.IPv4',
                     {'options': [b'\x94\x04\x00\x00'], 'protocol': 253},
                     '460000180000000000fd00007f0000010000000094040000'),
    'TCP options': ('pcapkit.protocols.transport.tcp.TCP',
                    {'options': [b'\x02\x04\x05\xb4']},
                    '0000000000000000000000006000ffff00000000020405b4'),
    'HOPOPT options': ('pcapkit.protocols.internet.hopopt.HOPOPT',
                       {'extension': True, 'options': [b'\x05\x02\x00\x00']},
                       '1100050200000000'),
    'IPv6_Opts options': ('pcapkit.protocols.internet.ipv6_opts.IPv6_Opts',
                          {'extension': True, 'options': [b'\x05\x02\x00\x00']},
                          '1100050200000000'),
    'MH options': ('pcapkit.protocols.internet.mh.MH',
                   {'data': {'options': [b'\x01\x02\x00\x00']}},
                   '11010000000000000102000001020000'),
    'SCTP chunks': ('pcapkit.protocols.transport.sctp.SCTP',
                    {'chunks': [b'\x0e\x00\x00\x04']},
                    '0000000000000000617cebb70e000004'),
    'IPv6_Route data': ('pcapkit.protocols.internet.ipv6_route.IPv6_Route',
                        {'extension': True, 'data': bytes(4)},
                        '1100000000000000'),
}


class TestMakeRawItems(unittest.TestCase):
    """Raw and :class:`Schema` items given to ``make()`` build a packet (#1312)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_raw_item_builds_and_parses(self) -> None:
        for case, (klass, kwargs, packed) in RAW_ITEMS.items():
            with self.subTest(case=case):
                cls = _attr(klass)
                proto = cls(**kwargs)
                self.assertEqual(proto.data.hex(), packed)
                # the made packet reads as the same octets parsed afresh
                extra = {'extension': True} if kwargs.get('extension') else {}
                self.assertEqual(proto.info, cls(proto.data, **extra).info)

    def test_schema_item_builds_as_raw_item(self) -> None:
        for case in ('HIP parameters', 'IPv4 options', 'TCP options'):
            with self.subTest(case=case):
                klass, kwargs, packed = RAW_ITEMS[case]
                cls = _attr(klass)
                key = next(key for key in ('parameters', 'options') if key in kwargs)
                extra = {'extension': True} if kwargs.get('extension') else {}
                header = cls(bytes.fromhex(packed), **extra).__header__
                item = getattr(header, 'param' if key == 'parameters' else 'options')[0]
                self.assertNotIsInstance(item, bytes)
                proto = cls(**{**kwargs, key: [item]})
                self.assertEqual(proto.data.hex(), packed)

    def test_bare_mh_constructs(self) -> None:
        mh = _attr('pcapkit.protocols.internet.mh.MH')
        proto = mh()
        self.assertEqual(proto.data.hex(), '1100000000000000')
        self.assertEqual(proto.info, mh(proto.data).info)

    def test_made_schema_without_raw_items_is_kept(self) -> None:
        module = importlib.import_module('pcapkit.protocols.protocol')
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        option = _attr('pcapkit.const.ipv4.option_number.OptionNumber')

        # an option given as a tuple is made into a schema, so nothing is re-parsed
        made = ipv4.make(ipv4.__new__(ipv4), options=[(option.RTRALT, {'alert': 0})], protocol=253)
        self.assertFalse(module._holds_raw(made))
        raw = ipv4.make(ipv4.__new__(ipv4), options=[b'\x94\x04\x00\x00'], protocol=253)
        self.assertTrue(module._holds_raw(raw))

        parsed = ipv4(raw.pack()).__header__
        self.assertTrue(module._raw_where_parsed(raw, parsed))
        self.assertFalse(module._raw_where_parsed(parsed, parsed))
        # raw octets matched by raw octets are not a stand-in for a schema
        self.assertFalse(module._raw_where_parsed([b'\x01'], [b'\x01']))

    def test_unparsable_raw_item_raises_protocol_error(self) -> None:
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        # a lone length-less option makes the packed octets unparsable
        with self.assertRaisesRegex(exc, r'malformed raw item given to make\(\)') as caught:
            ipv4(options=[b'\x02', b'\x94\x04\x00\x00'], protocol=253)
        self.assertIsInstance(caught.exception.__cause__, exc)

    def test_random_raw_items_raise_library_errors_only(self) -> None:
        random = importlib.import_module('random')
        base = _attr('pcapkit.utilities.exceptions.BaseError')
        rng = random.Random(1352)

        def items() -> 'list[bytes]':
            return [bytes(rng.randrange(256) for _ in range(rng.randrange(1, 13)))
                    for _ in range(rng.randrange(1, 3))]

        for case, (klass, kwargs, _) in RAW_ITEMS.items():
            key = next(iter(kw for kw in ('parameters', 'options', 'chunks', 'data') if kw in kwargs))
            cls = _attr(klass)
            with self.subTest(case=case):
                for _ in range(200):
                    value = items()  # type: Any
                    if case == 'MH options':
                        value = {'options': value}
                    elif case == 'IPv6_Route data':
                        value = b''.join(value)
                    try:
                        with importlib.import_module('warnings').catch_warnings():
                            importlib.import_module('warnings').simplefilter('ignore')
                            cls(**{**kwargs, key: value})
                    except base:
                        pass

    def test_malformed_raw_item_raises_protocol_error(self) -> None:
        # ESP_INFO needs a 12-octet body; an 8-octet one is a parse error,
        # reported as such rather than as an AttributeError on raw bytes
        hip = _attr('pcapkit.protocols.internet.hip.HIP')
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        with self.assertRaisesRegex(exc, r'\[ParamNo 65\] invalid format'):
            hip(extension=True, parameters=[b'\x00\x41\x00\x08' + bytes(8)])


class TestMakeIndexPerArgument(unittest.TestCase):
    """A member name resolves against its own ``make()`` argument (#1308)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _pair(self) -> 'tuple[Any, Any, Any]':
        enum = importlib.import_module('enum')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')

        left = enum.IntEnum('Left', {'Shared': 1})
        right = enum.IntEnum('Right', {'Shared': 2, 'Only': 3})

        class Pair(protocol):  # type: ignore[misc,valid-type]
            def make_pair(self, a: 'Any' = left.Shared, a_namespace: 'Any' = None,
                          b: 'Any' = right.Shared, b_namespace: 'Any' = None) -> 'tuple[int, int]':
                return (self._make_index(a, namespace=a_namespace),
                        self._make_index(b, 0, namespace=b_namespace))

        return Pair, left, right

    def test_shared_name_resolves_per_argument(self) -> None:
        pair, _, _ = self._pair()
        self.assertEqual(pair.make_pair(pair, a='Shared', b='Shared'), (1, 2))
        # a name only one argument holds resolves as it did before
        self.assertEqual(pair.make_pair(pair, a='Shared', b='Only'), (1, 3))

    def test_ipv4_shared_name_falls_back_per_argument(self) -> None:
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.IPv4')
        tos_del = _attr('pcapkit.const.ipv4.tos_del.ToSDelay')

        expected = ipv4(tos_del=tos_del.LOW, tos_thr=1).data
        # ``LOW`` is a ToSDelay member but not a ToSThroughput one
        self.assertEqual(ipv4(tos_del='LOW', tos_thr='LOW', tos_thr_default=1).data, expected)
        self.assertEqual(ipv4(tos_thr='LOW', tos_thr_default=1).data,
                         ipv4(tos_thr=1).data)

    def test_non_parameter_first_argument_matches_every_argument(self) -> None:
        enum = importlib.import_module('enum')
        protocol = _attr('pcapkit.protocols.protocol.ProtocolBase')
        level = enum.IntEnum('Level', {'HIGH': 7})

        class Alias(protocol):  # type: ignore[misc,valid-type]
            def make_alias(self, b: 'Any' = level.HIGH, b_namespace: 'Any' = None) -> 'int':
                value = b
                return self._make_index(value)

        # ``value`` is a local, so ``b`` is found by its value as before
        self.assertEqual(Alias.make_alias(Alias, b='HIGH'), 7)

    def test_unlocated_call_matches_every_argument(self) -> None:
        # without the caller's source the call cannot be located, so every
        # argument holding the name is a candidate and they must agree
        module = importlib.import_module('pcapkit.protocols.protocol')
        exc = _attr('pcapkit.utilities.exceptions.ProtocolNotImplemented')
        pair, _, right = self._pair()

        with unittest.mock.patch.object(module, '_make_index_calls', lambda func: ()):
            with self.assertRaisesRegex(exc, r"ambiguous member name 'Shared'.*"
                                             r"pass a_namespace= or b_namespace= explicitly"):
                pair.make_pair(pair, a='Shared', b='Shared')
            self.assertEqual(pair.make_pair(pair, a='Shared', b='Shared', b_namespace=right), (1, 2))

    def test_source_unavailable_locates_nothing(self) -> None:
        module = importlib.import_module('pcapkit.protocols.protocol')
        # a builtin has no Python source
        self.assertEqual(module._make_index_calls(len), ())


if __name__ == '__main__':
    unittest.main()
