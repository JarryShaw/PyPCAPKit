from __future__ import annotations

import importlib.util
import unittest
from types import SimpleNamespace

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyData(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class RawNullUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_raw_properties_make_data_and_index_error(self) -> None:
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import UnsupportedCall

        raw = object.__new__(Raw)
        schema = raw.make(packet=b'raw-packet')
        data = DummyData(packet=b'raw-packet')

        self.assertEqual(raw.name, 'Unknown')
        self.assertEqual(raw.length, 0)
        self.assertEqual(schema.packet, b'raw-packet')
        self.assertEqual(Raw._make_data(data), {'packet': b'raw-packet'})
        with self.assertRaises(UnsupportedCall):
            _ = raw.protocol
        with self.assertRaises(UnsupportedCall):
            Raw.__index__()

        Raw.__post_init__(raw, packet=b'raw-packet', alias=SimpleNamespace(name='CUSTOM'))
        self.assertEqual(raw._data, b'raw-packet')
        self.assertEqual(raw._info.protocol.name, 'CUSTOM')

        Raw.__post_init__(raw, file=b'file-data', length=4)
        self.assertEqual(raw._data, b'file-data')
        self.assertIsNone(raw._info.protocol)

    def test_no_payload_properties_read_make_and_index_error(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.utilities.exceptions import UnsupportedCall

        null = object.__new__(NoPayload)
        schema = null.make()
        data = null.read()

        self.assertEqual(null.name, 'Null')
        self.assertEqual(null.length, 0)
        self.assertEqual(type(schema).__name__, 'NoPayload')
        self.assertEqual(type(data).__name__, 'NoPayload')
        with self.assertRaises(UnsupportedCall):
            _ = null.protocol
        with self.assertRaises(UnsupportedCall):
            NoPayload.__index__()


if __name__ == '__main__':
    unittest.main()
