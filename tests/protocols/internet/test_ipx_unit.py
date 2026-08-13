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
class IPXUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ipx_index_length_and_make_data(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipx import IPX

        data = DummyDict(
            chksum=b'\xff\xff',
            count=42,
            type=4,
            dst='dst-node',
            src='src-node',
            __next_type__=None,
        )
        proto = object.__new__(IPX)

        self.assertEqual(IPX.__index__(), TransType.IPX_in_IP)
        self.assertEqual(proto.__length_hint__(), 30)
        values = IPX._make_data(data)
        self.assertEqual(values['chksum'], b'\xff\xff')
        self.assertEqual(values['count'], 42)
        self.assertEqual(values['type'], 4)
        self.assertEqual(values['dst'], 'dst-node')
        self.assertEqual(values['src'], 'src-node')
        self.assertIn('payload', values)

    def test_ipx_make_builds_schema_with_addresses(self) -> None:
        from pcapkit.protocols.internet.ipx import IPX

        proto = object.__new__(IPX)
        dst = b'\x00\x00\x00\x01\x00\x01\x02\x03\x04\x05\x04\x56'
        src = b'\x00\x00\x00\x02\x06\x07\x08\x09\x0a\x0b\x07\x89'
        schema = proto.make(
            chksum=b'\xaa\xbb',
            count=9,
            type=4,
            dst=dst,
            src=src,
            payload=b'ipx',
        )

        self.assertEqual(schema.chksum, b'\xaa\xbb')
        self.assertEqual(schema.len, 33)
        self.assertEqual(schema.count, 9)
        self.assertEqual(schema.type, 4)
        self.assertEqual(schema.dst, dst)
        self.assertEqual(schema.src, src)

    def test_ipx_read_properties_and_address_decoding(self) -> None:
        from pcapkit.const.ipx.packet import Packet
        from pcapkit.const.ipx.socket import Socket
        from pcapkit.protocols.internet.ipx import IPX
        from pcapkit.protocols.schema.internet.ipx import IPX as Schema_IPX

        proto = object.__new__(IPX)
        dst = b'\x00\x00\x00\x01\x00\x01\x02\x03\x04\x05\x04\x56'
        src = b'\x00\x00\x00\x02\x06\x07\x08\x09\x0a\x0b\x07\x89'
        proto.__header__ = Schema_IPX(
            chksum=b'\xff\xff',
            len=33,
            count=3,
            type=Packet.PEP,
            dst=dst,
            src=src,
            payload=b'abc',
        )
        proto._data = bytes(proto.__header__)
        proto.__cached__ = {}

        with mock.patch.object(proto, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(), 'decoded')

        parsed = decode.call_args.args[0]
        self.assertEqual(parsed.chksum, b'\xff\xff')
        self.assertEqual(parsed.len, 33)
        self.assertEqual(parsed.count, 3)
        self.assertEqual(parsed.type, Packet.PEP)
        self.assertEqual(parsed.dst.network, '00:00:00:01')
        self.assertEqual(parsed.dst.node, '00-01-02-03-04-05')
        self.assertEqual(parsed.dst.socket, Socket.Diagnostic_Packet)
        self.assertEqual(parsed.dst.addr, '00:00:00:01:00:01:02:03:04:05:04:56')
        self.assertEqual(parsed.src.network, '00:00:00:02')
        self.assertEqual(parsed.src.node, '06-07-08-09-0a-0b')
        self.assertEqual(parsed.src.addr, '00:00:00:02:06:07:08:09:0a:0b:07:89')
        self.assertEqual(decode.call_args.args[1], Packet.PEP)
        self.assertEqual(decode.call_args.args[2], 3)

        proto._info = parsed
        self.assertEqual(proto.name, 'Internetwork Packet Exchange')
        self.assertEqual(proto.length, 30)
        self.assertEqual(proto.protocol, Packet.PEP)
        self.assertEqual(proto.dst, parsed.dst.addr)
        self.assertEqual(proto.src, parsed.src.addr)

        with mock.patch.object(proto, '_decode_next_layer', return_value='decoded') as decode:
            self.assertEqual(proto.read(length=33), 'decoded')
        decode.assert_called_once()


if __name__ == '__main__':
    unittest.main()
