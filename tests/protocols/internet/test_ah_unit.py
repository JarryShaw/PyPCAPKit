from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class DummyDict(dict):
    __getattr__ = dict.__getitem__


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class AHUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ah_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah import AH

        data = DummyDict(
            next=TransType.TCP,
            spi=0x12345678,
            seq=7,
            icv=b'auth',
            __next_type__=None,
        )
        proto = object.__new__(AH)

        self.assertEqual(AH.__index__(), TransType.AH)
        self.assertEqual(proto.__length_hint__(), 20)
        values = AH._make_data(data)
        self.assertEqual(values['next'], TransType.TCP)
        self.assertEqual(values['spi'], 0x12345678)
        self.assertEqual(values['seq'], 7)
        self.assertEqual(values['icv'], b'auth')
        self.assertIn('payload', values)

    def test_ah_make_builds_schema_with_payload_length(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah import AH

        proto = object.__new__(AH)
        schema = proto.make(
            next=TransType.UDP,
            spi=1,
            seq=2,
            icv=b'12345678',
            payload=b'data',
        )

        self.assertEqual(schema.next, TransType.UDP)
        self.assertEqual(schema.spi, 1)
        self.assertEqual(schema.seq, 2)
        self.assertEqual(schema.icv, b'12345678')
        self.assertEqual(schema.len, 3)

    def test_ah_read_properties_and_ipsec_id(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ah import AH
        from pcapkit.protocols.internet.ipsec import IPsec
        from pcapkit.protocols.schema.internet.ah import AH as Schema_AH
        from pcapkit.utilities.exceptions import UnsupportedCall

        proto = object.__new__(AH)
        proto.__header__ = Schema_AH(
            next=TransType.TCP,
            len=3,
            spi=0x12345678,
            seq=9,
            icv=b'12345678',
            payload=b'data',
        )
        proto._data = b'\x00' * 24
        proto.__cached__ = {}
        proto._extf = False
        proto._info = DummyDict(length=20)

        self.assertEqual(IPsec.id(), ('AH', 'ESP'))
        self.assertEqual(AH.id(), ('AH',))
        self.assertEqual(proto.name, 'Authentication Header')
        self.assertEqual(proto.length, 20)
        proto._next = 'payload'
        proto._protos = ['TCP']
        self.assertEqual(proto.payload, 'payload')
        self.assertEqual(proto.protocol, 'TCP')
        self.assertEqual(proto.protochain, ['TCP'])

        ext_data = proto.read(extension=True)
        self.assertEqual(ext_data.next, TransType.TCP)
        self.assertEqual(ext_data.length, 20)
        self.assertEqual(ext_data.spi, 0x12345678)

        with mock.patch.object(AH, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=24), 'decoded')
        decode.assert_called_once()

        proto._extf = True
        with self.assertRaises(UnsupportedCall):
            _ = proto.payload
        with self.assertRaises(UnsupportedCall):
            _ = proto.protocol
        with self.assertRaises(UnsupportedCall):
            _ = proto.protochain

        with mock.patch.object(IPsec, '__post_init__', return_value=None) as post_init:
            post_proto = object.__new__(AH)
            post_proto.__post_init__(extension=True, version=6, custom=True)
        self.assertTrue(post_proto._extf)
        post_init.assert_called_once()


if __name__ == '__main__':
    unittest.main()
