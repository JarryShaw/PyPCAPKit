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
        from pcapkit.foundation.reassembly.data import (Completion, IP_Buffer, IP_Datagram,
                                                        IP_DatagramID, IP_Packet, ReassemblyData)
        from pcapkit.foundation.reassembly.data.ip import Buffer, Datagram, DatagramID, Packet

        src = ip_address('192.0.2.1')
        dst = ip_address('198.51.100.2')
        bufid = (src, dst, 123, TransType.UDP)

        packet = Packet(bufid, 7, 8, 20, True, 28, b'ip-header', bytearray(b'payload'), 1000.0)
        self.assertIsInstance(packet, IP_Packet)
        self.assertEqual(packet.bufid, bufid)
        self.assertEqual(packet.payload, bytearray(b'payload'))
        self.assertEqual(packet.timestamp, 1000.0)

        datagram_id = DatagramID(src, dst, 123, TransType.UDP)
        datagram = Datagram(Completion.PARTIAL, datagram_id, (7,), b'ip-header', (b'payload',), None, ())
        self.assertIsInstance(datagram.id, IP_DatagramID)
        self.assertIsInstance(datagram, IP_Datagram)
        self.assertFalse(datagram.completed)
        self.assertIs(datagram.completed, Completion.PARTIAL)
        self.assertEqual(datagram.to_dict()['payload'], (b'payload',))
        self.assertEqual(datagram.conflict, ())

        buffer = Buffer(-1, bytearray(b'\x01'), [7], b'ip-header', bytearray(b'payload'), 1000.0, [])
        self.assertIsInstance(buffer, IP_Buffer)
        self.assertEqual(buffer.index, [7])
        self.assertEqual(buffer.timestamp, 1000.0)
        self.assertEqual(buffer.conflict, [])

        storage = ReassemblyData((datagram,), (), ())
        self.assertEqual(storage.ipv4, (datagram,))
        self.assertEqual(storage.ipv6, ())
        self.assertEqual(storage.tcp, ())

    def test_completion_is_a_string_that_still_reads_as_the_old_bool(self) -> None:
        """The contract ``Datagram.completed`` has to keep, now it is a StrEnum.

        Deriving from :class:`~pcapkit.utilities.compat.StrEnum` -- as
        :class:`~pcapkit.protocols.application.httpv1.Type` does -- buys
        serialisability and comparison against a plain string. What it must not
        cost is the truthiness callers of the former :obj:`bool` field rely on,
        which needs ``__bool__`` overridden because every non-empty string is
        otherwise truthy.

        """
        import json

        from pcapkit.foundation.reassembly.data.data import Completion

        # only COMPLETE is truthy, so ``if datagram.completed:`` reads as it did
        self.assertTrue(Completion.COMPLETE)
        self.assertFalse(Completion.PARTIAL)
        self.assertFalse(Completion.TIMEOUT)

        # ... while equality against a bool stays broken, as documented
        self.assertNotEqual(Completion.COMPLETE, True)
        self.assertNotEqual(Completion.PARTIAL, False)

        # what the str base adds
        self.assertIsInstance(Completion.TIMEOUT, str)
        self.assertEqual(Completion.TIMEOUT, 'timeout')
        self.assertEqual(str(Completion.PARTIAL), 'partial')
        self.assertEqual(json.dumps(Completion.PARTIAL), '"partial"')

        # and identity still works, which is what the assertions elsewhere use
        self.assertIs(Completion('complete'), Completion.COMPLETE)

    def test_tcp_data_models_and_package_aliases(self) -> None:
        from pcapkit.foundation.reassembly.data import (Completion, TCP_Buffer, TCP_Datagram,
                                                        TCP_DatagramID, TCP_Fragment,
                                                        TCP_HoleDescriptor, TCP_Packet)
        from pcapkit.foundation.reassembly.data.tcp import (Buffer, Datagram, DatagramID,
                                                            Fragment, HoleDescriptor, Packet)

        src = ip_address('192.0.2.10')
        dst = ip_address('198.51.100.20')
        bufid = (src, 12345, dst, 443)

        packet = Packet(bufid, 100, 200, 3, True, False, False, 5, 0, 4,
                        b'tcp-header', bytearray(b'hello'), 1000.0)
        self.assertIsInstance(packet, TCP_Packet)
        self.assertEqual(packet.first, 0)
        self.assertTrue(packet.syn)
        self.assertEqual(packet.timestamp, 1000.0)

        datagram_id = DatagramID((src, 12345), (dst, 443), 200)
        datagram = Datagram(Completion.COMPLETE, datagram_id, (3,), b'tcp-header', b'hello',
                            {'parsed': True})
        self.assertIsInstance(datagram.id, TCP_DatagramID)
        self.assertIsInstance(datagram, TCP_Datagram)
        self.assertTrue(datagram.completed)
        self.assertIs(datagram.completed, Completion.COMPLETE)

        hole = HoleDescriptor(5, 10)
        fragment = Fragment([3], 100, 5, bytearray(b'hello'))
        buffer = Buffer([hole], b'tcp-header', {200: fragment}, 1000.0)
        self.assertIsInstance(hole, TCP_HoleDescriptor)
        self.assertIsInstance(fragment, TCP_Fragment)
        self.assertIsInstance(buffer, TCP_Buffer)
        self.assertEqual(buffer.ack[200].raw, bytearray(b'hello'))
        self.assertEqual(buffer.timestamp, 1000.0)


if __name__ == '__main__':
    unittest.main()
