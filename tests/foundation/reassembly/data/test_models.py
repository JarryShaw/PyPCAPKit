from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReassemblyDataModelTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ip_data_models_and_package_aliases(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.foundation.reassembly.data import (IP_Buffer, IP_Datagram, IP_DatagramID,
                                                        IP_Packet, ReassemblyData)
        from pcapkit.foundation.reassembly.data.ip import Buffer, Datagram, DatagramID, Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        bufid = (src, dst, 123, TransType.UDP)

        packet = Packet(bufid, 7, 8, 20, True, 28, b'ip-header', bytearray(b'payload'))
        self.assertIsInstance(packet, IP_Packet)
        self.assertEqual(packet.bufid, bufid)
        self.assertEqual(packet.payload, bytearray(b'payload'))

        datagram_id = DatagramID(src, dst, 123, TransType.UDP)
        datagram = Datagram(False, datagram_id, (7,), b'ip-header', (b'payload',), None)
        self.assertIsInstance(datagram.id, IP_DatagramID)
        self.assertIsInstance(datagram, IP_Datagram)
        self.assertFalse(datagram.completed)
        self.assertEqual(datagram.to_dict()['payload'], (b'payload',))

        buffer = Buffer(-1, bytearray(b'\x01'), [7], b'ip-header', bytearray(b'payload'))
        self.assertIsInstance(buffer, IP_Buffer)
        self.assertEqual(buffer.index, [7])

        storage = ReassemblyData((datagram,), (), ())
        self.assertEqual(storage.ipv4, (datagram,))
        self.assertEqual(storage.ipv6, ())
        self.assertEqual(storage.tcp, ())

    def test_tcp_data_models_and_package_aliases(self) -> None:
        from pcapkit.foundation.reassembly.data import (TCP_Buffer, TCP_Datagram, TCP_DatagramID,
                                                        TCP_Fragment, TCP_HoleDiscriptor,
                                                        TCP_Packet)
        from pcapkit.foundation.reassembly.data.tcp import (Buffer, Datagram, DatagramID,
                                                            Fragment, HoleDiscriptor, Packet)

        src = ip_address('192.0.2.10')
        dst = ip_address('198.51.100.20')
        bufid = (src, 12345, dst, 443)

        packet = Packet(bufid, 100, 200, 3, True, False, False, 5, 0, 4,
                        b'tcp-header', bytearray(b'hello'))
        self.assertIsInstance(packet, TCP_Packet)
        self.assertEqual(packet.first, 0)
        self.assertTrue(packet.syn)

        datagram_id = DatagramID((src, 12345), (dst, 443), 200)
        datagram = Datagram(True, datagram_id, (3,), b'tcp-header', b'hello', {'parsed': True})
        self.assertIsInstance(datagram.id, TCP_DatagramID)
        self.assertIsInstance(datagram, TCP_Datagram)
        self.assertTrue(datagram.completed)

        hole = HoleDiscriptor(5, 10)
        fragment = Fragment([3], 100, 5, bytearray(b'hello'))
        buffer = Buffer([hole], b'tcp-header', {200: fragment})
        self.assertIsInstance(hole, TCP_HoleDiscriptor)
        self.assertIsInstance(fragment, TCP_Fragment)
        self.assertIsInstance(buffer, TCP_Buffer)
        self.assertEqual(buffer.ack[200].raw, bytearray(b'hello'))


if __name__ == '__main__':
    unittest.main()
