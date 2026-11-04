# -*- coding: utf-8 -*-
"""Construction through ``make()`` in :class:`~pcapkit.protocols.protocol.Protocol`.

This guards against GitHub issue #1312, where
:meth:`~pcapkit.protocols.protocol.ProtocolBase.unpack` reused the schema
:meth:`~pcapkit.protocols.protocol.ProtocolBase.pack` had made instead of
parsing the packed octets, so ``read`` met the raw :obj:`bytes` (or
:class:`~pcapkit.protocols.schema.Schema`) items the option makers
accept, and construction crashed with :exc:`AttributeError`. A bare ``MH()``
crashed the same way on its default ``data=b'\\x00\\x00'``. A made schema
holding raw octets where parsing its packed form yields a schema is replaced by
the parsed one.

Every case builds its own packet in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, so they belong to the live
:mod:`pcapkit` import.

"""

import importlib
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): branches on the running interpreter's version or implementation.
__tier__ = 'ALL'


def _attr(path: 'str') -> 'Any':
    module, _, name = path.rpartition('.')
    return getattr(importlib.import_module(module), name)


#: One raw item per protocol whose ``make()`` accepts raw octets in a list:
#: (protocol class, construction keywords, packed octets).
RAW_ITEMS = {
    'HIP parameters': ('pcapkit.protocols.internet.hip.protocol.HIP',
                       {'extension': True, 'parameters': [b'\x00\x41\x00\x0c' + bytes(12)]},
                       '1106202100000000' + '00' * 32 + '0041000c' + '00' * 12),
    'IPv4 options': ('pcapkit.protocols.internet.ipv4.protocol.IPv4',
                     {'options': [b'\x94\x04\x00\x00'], 'protocol': 253},
                     '460000180000000000fda5e47f0000010000000094040000'),
    'TCP options': ('pcapkit.protocols.transport.tcp.protocol.TCP',
                    {'options': [b'\x02\x04\x05\xb4']},
                    '0000000000000000000000006000ffff00000000020405b4'),
    # two octets of padding follow the option, as one zero-length PadN (#1793)
    'HOPOPT options': ('pcapkit.protocols.internet.hopopt.protocol.HOPOPT',
                       {'extension': True, 'options': [b'\x05\x02\x00\x00']},
                       '1100050200000100'),
    'IPv6_Opts options': ('pcapkit.protocols.internet.ipv6_opts.protocol.IPv6_Opts',
                          {'extension': True, 'options': [b'\x05\x02\x00\x00']},
                          '1100050200000100'),
    'MH options': ('pcapkit.protocols.internet.mh.protocol.MH',
                   {'data': {'options': [b'\x01\x02\x00\x00']}},
                   '11010000000000000102000001020000'),
    'SCTP chunks': ('pcapkit.protocols.transport.sctp.protocol.SCTP',
                    {'chunks': [b'\x0e\x00\x00\x04']},
                    '0000000000000000617cebb70e000004'),
    'IPv6_Route data': ('pcapkit.protocols.internet.ipv6_route.protocol.IPv6_Route',
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
        mh = _attr('pcapkit.protocols.internet.mh.protocol.MH')
        proto = mh()
        self.assertEqual(proto.data.hex(), '1100000000000000')
        self.assertEqual(proto.info, mh(proto.data).info)

    def test_made_schema_without_raw_items_is_kept(self) -> None:
        module = importlib.import_module('pcapkit.protocols.protocol')
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.protocol.IPv4')
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
        ipv4 = _attr('pcapkit.protocols.internet.ipv4.protocol.IPv4')
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
        # reported as such rather than as an AttributeError on raw bytes. Its
        # fields read past the octets given, which the option field refuses
        # (#1325) before the reader sees them.
        hip = _attr('pcapkit.protocols.internet.hip.protocol.HIP')
        exc = _attr('pcapkit.utilities.exceptions.ProtocolError')
        with self.assertRaisesRegex(exc, r'runs past the end of the data'):
            hip(extension=True, parameters=[b'\x00\x41\x00\x08' + bytes(8)])


if __name__ == '__main__':
    unittest.main()
