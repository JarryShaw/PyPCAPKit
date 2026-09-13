from __future__ import annotations

import importlib.util
from ipaddress import ip_address
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TraceFlowDataModelTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_tcp_traceflow_data_models_and_package_aliases(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.data import (TCP_Buffer, TCP_Index, TCP_Packet,
                                                       TraceFlowData)
        from pcapkit.foundation.traceflow.data.tcp import Buffer, Index, Packet

        src = ip_address('2001:db8::1')
        dst = ip_address('2001:db8::2')
        frame = {'frame': 1}
        packet = Packet(LinkType.ETHERNET, 1, frame, True, False, src, dst, 12345, 443, 1.5)
        self.assertIsInstance(packet, TCP_Packet)
        self.assertEqual(packet.src, src)
        self.assertEqual(packet.frame, frame)

        dumper = object()
        buffer = Buffer(dumper, [1, 2], '2001_db8_1-12345_2001_db8_2-443')
        self.assertIsInstance(buffer, TCP_Buffer)
        self.assertEqual(buffer.fpout, dumper)

        index = Index('/tmp/flow.json', (1, 2), buffer.label)
        self.assertIsInstance(index, TCP_Index)
        self.assertEqual(index.index, (1, 2))

        storage = TraceFlowData((index,))
        self.assertEqual(storage.tcp, (index,))


if __name__ == '__main__':
    unittest.main()
