# -*- coding: utf-8 -*-
"""TCP flow labels are unique, so no flow truncates another's output file.

GitHub issue #1360: the label is built from the packet that opens a flow, and the
output file is named after it and opened -- truncating it -- when the flow starts.
Two flows opened on the same endpoints at the same capture timestamp got one label
and one file, and the later flow erased the earlier one's frames. That happens
unidirectionally when a direction resumes after its FIN, and bidirectionally when a
new connection reuses a torn-down conversation's endpoints.

Every case builds its packets in memory and writes to a temporary directory.

"""

import importlib.util
from ipaddress import ip_address
import os
import tempfile
import unittest

from tests._support import reimport_once_per_class

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: The label both colliding flows used to share.
LABEL = '192.0.2.1_12345-198.51.100.2_443-300.0'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestTraceFlowLabelUnique(unittest.TestCase):
    """Pin one label, and one file, per traced flow."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _packet(index: int, *, syn: bool = False, fin: bool = False, reverse: bool = False,
                timestamp: float = 300.0) -> 'object':
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.traceflow.data.tcp import Packet

        near, far = (ip_address('192.0.2.1'), 12345), (ip_address('198.51.100.2'), 443)
        (src, srcport), (dst, dstport) = (far, near) if reverse else (near, far)
        return Packet(LinkType.ETHERNET, index, {'frame': index}, syn, fin, False, src, dst,
                      srcport, dstport, timestamp, 0, 0, b'h', bytearray(b''))

    def _trace(self, bidirectional: bool, packets: 'list[object]') -> 'tuple[list, dict]':
        from pcapkit.foundation.traceflow.tcp import TCP

        with tempfile.TemporaryDirectory() as tempdir:
            trace = TCP(tempdir, 'json', bidirectional=bidirectional)
            for packet in packets:
                trace.dump(packet)
            trace.finish()
            flows = [(flow.label, flow.index, flow.fpout) for flow in trace.index]
            files = {}
            for name in sorted(os.listdir(tempdir)):
                with open(os.path.join(tempdir, name), encoding='utf-8') as file:
                    text = file.read()
                files[name] = tuple(i for i in range(1, 5) if f'Frame {i}' in text)
            flows = [(label, index, os.path.basename(fpout)) for label, index, fpout in flows]
        return flows, files

    def test_unidirectional_flow_resumed_at_the_same_timestamp(self) -> None:
        flows, files = self._trace(False, [self._packet(1, fin=True), self._packet(2)])

        self.assertEqual(flows, [(LABEL, (1,), f'{LABEL}.json'),
                                 (f'{LABEL}-1', (2,), f'{LABEL}-1.json')])
        self.assertEqual(files, {f'{LABEL}-1.json': (2,), f'{LABEL}.json': (1,)})

    def test_bidirectional_connection_reusing_endpoints_at_the_same_timestamp(self) -> None:
        flows, files = self._trace(True, [
            self._packet(1, syn=True),
            self._packet(2, fin=True),
            self._packet(3, fin=True, reverse=True),
            self._packet(4, syn=True),  # a new connection on the torn-down endpoints
        ])

        self.assertEqual(flows, [(LABEL, (1, 2, 3), f'{LABEL}.json'),
                                 (f'{LABEL}-1', (4,), f'{LABEL}-1.json')])
        self.assertEqual(files, {f'{LABEL}-1.json': (4,), f'{LABEL}.json': (1, 2, 3)})

    def test_every_repeat_gets_the_next_free_suffix(self) -> None:
        flows, files = self._trace(False, [self._packet(i, fin=True) for i in range(1, 5)])

        labels = [LABEL, f'{LABEL}-1', f'{LABEL}-2', f'{LABEL}-3']
        self.assertEqual([flow[0] for flow in flows], labels)
        self.assertEqual(files, {f'{label}.json': (i,) for i, label in enumerate(labels, 1)})

    def test_non_colliding_labels_are_unchanged(self) -> None:
        flows, _ = self._trace(False, [self._packet(1, fin=True), self._packet(2, timestamp=301.0),
                                       self._packet(3, reverse=True)])

        self.assertEqual([flow[0] for flow in flows], [
            LABEL,
            '192.0.2.1_12345-198.51.100.2_443-301.0',
            '198.51.100.2_443-192.0.2.1_12345-300.0',
        ])


if __name__ == '__main__':
    unittest.main()
