from __future__ import annotations

import pathlib
import sys
import types
import unittest
from unittest import mock

from tests._support import ROOT, ensure_package, load_module, purge_modules


class InterfaceMiscTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def _load_module(self, *, extractor_engine: str = 'default',
                     stream_indexes: tuple[int, ...] = (2, 1)):
        ensure_package('pcapkit', ROOT / 'pcapkit')
        ensure_package('pcapkit.foundation', ROOT / 'pcapkit' / 'foundation')
        ensure_package('pcapkit.foundation.reassembly',
                       ROOT / 'pcapkit' / 'foundation' / 'reassembly')
        ensure_package('pcapkit.toolkit', ROOT / 'pcapkit' / 'toolkit')

        calls = {
            'pcap': [],
            'dpkt': [],
            'scapy': [],
            'extractor': [],
        }
        frames = [
            types.SimpleNamespace(index=1, payload=b'one'),
            types.SimpleNamespace(index=2, payload=b'two'),
        ]

        extraction_module = types.ModuleType('pcapkit.foundation.extraction')

        class Extractor:
            def __init__(self, **kwargs):
                calls['extractor'].append(kwargs)
                self.engine = extractor_engine
                self.frame = frames
                self.trace = types.SimpleNamespace(tcp=[
                    types.SimpleNamespace(index=stream_indexes, fpout='stream.bin'),
                ])

        extraction_module.Extractor = Extractor
        sys.modules['pcapkit.foundation.extraction'] = extraction_module

        tcp_module = types.ModuleType('pcapkit.foundation.reassembly.tcp')

        class TCP:
            def __init__(self, strict=False):
                self.strict = strict
                self.datagram = []

            def __call__(self, packet):
                self.datagram.append(types.SimpleNamespace(index=packet.index,
                                                           payload=packet.payload))

        tcp_module.TCP = TCP
        sys.modules['pcapkit.foundation.reassembly.tcp'] = tcp_module

        def install_toolkit(name: str, *, uses_count: bool) -> None:
            toolkit_module = types.ModuleType(f'pcapkit.toolkit.{name}')

            def tcp_reassembly(frame, *, count=None):
                calls[name].append((frame, count))
                if frame.payload == b'two' and count == 2:
                    return None
                index = count if uses_count else frame.index
                return types.SimpleNamespace(index=index, payload=frame.payload)

            toolkit_module.tcp_reassembly = tcp_reassembly
            sys.modules[f'pcapkit.toolkit.{name}'] = toolkit_module

        install_toolkit('pcap', uses_count=False)
        install_toolkit('dpkt', uses_count=True)
        install_toolkit('scapy', uses_count=True)

        module = load_module('pcapkit.interface.misc', 'pcapkit/interface/misc.py')
        return module, calls

    def test_follow_tcp_stream_falls_back_for_pyshark_and_uses_pcap_helper(self) -> None:
        module, calls = self._load_module(extractor_engine='default')

        with mock.patch.object(module, 'warn') as warn:
            streams = module.follow_tcp_stream(
                fin='in.pcap',
                verbose=True,
                extension=False,
                engine='pyshark',
                fout='trace.pcap',
                format='pcap',
                byteorder='little',
                nanosecond=True,
            )

        warn.assert_called_once()
        self.assertEqual(calls['extractor'][0]['engine'], None)
        self.assertTrue(calls['extractor'][0]['trace'])
        self.assertTrue(calls['extractor'][0]['tcp'])
        self.assertEqual(calls['extractor'][0]['trace_fout'], 'trace.pcap')
        self.assertEqual(calls['extractor'][0]['trace_format'], 'pcap')
        self.assertEqual(len(calls['pcap']), 2)
        self.assertEqual(calls['pcap'][0][1], None)
        self.assertEqual(streams[0].filename, 'stream.bin')
        self.assertEqual(streams[0].packets[0].payload, b'two')
        self.assertEqual(streams[0].conversations, (b'one', b'two'))

    def test_follow_tcp_stream_uses_dpkt_and_scapy_counted_helpers(self) -> None:
        module, calls = self._load_module(extractor_engine='dpkt')
        streams = module.follow_tcp_stream(engine='dpkt')
        self.assertEqual(calls['extractor'][0]['engine'], 'dpkt')
        self.assertEqual(calls['dpkt'], [
            (streams[0].packets[0], 2),
            (streams[0].packets[1], 1),
        ])
        self.assertEqual(streams[0].conversations, (b'one',))

        purge_modules(['pcapkit'])
        module, calls = self._load_module(extractor_engine='scapy')
        streams = module.follow_tcp_stream(engine='scapy')
        self.assertEqual(calls['extractor'][0]['engine'], 'scapy')
        self.assertEqual(calls['scapy'], [
            (streams[0].packets[0], 2),
            (streams[0].packets[1], 1),
        ])
        self.assertEqual(streams[0].conversations, (b'one',))


if __name__ == '__main__':
    unittest.main()
