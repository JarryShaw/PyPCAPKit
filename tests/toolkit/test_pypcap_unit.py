"""Unit tests for :mod:`pcapkit.toolkit.pypcap`.

`pypcap`_ hands back raw bytes, so this toolkit has only the two auxiliary
functions; the reassembly and flow tracing adapters exist purely to refuse
loudly, and that refusal is asserted here so it cannot regress into a silent
:data:`None`.

.. _pypcap: https://github.com/pynetwork/pypcap

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPToolkitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_packet2chain_reports_the_link_layer_and_raw(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcap import packet2chain

        self.assertEqual(packet2chain(b'\x00' * 20, data_link=LinkType.ETHERNET),
                         'ETHERNET:Raw')
        self.assertEqual(packet2chain(b'', data_link=LinkType.RAW), 'RAW:Raw')

    def test_packet2dict_carries_the_bytes_verbatim(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcap import packet2dict

        info = packet2dict(b'abcd', 1.25, data_link=LinkType.ETHERNET)
        self.assertEqual(info, {
            'timestamp': 1.25,
            'packet': b'abcd',
            'ETHERNET': {'raw_len': 4, 'raw': b'abcd'},
        })

    def test_unsupported_adapters_refuse_loudly(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.toolkit.pypcap import (ipv4_reassembly, ipv6_reassembly, tcp_reassembly,
                                            tcp_traceflow)
        from pcapkit.utilities.exceptions import UnsupportedCall

        for name, call in (
            ('ipv4_reassembly', lambda: ipv4_reassembly(b'raw', count=1)),
            ('ipv6_reassembly', lambda: ipv6_reassembly(b'raw', count=1)),
            ('tcp_reassembly', lambda: tcp_reassembly(b'raw', count=1)),
            ('tcp_traceflow', lambda: tcp_traceflow(b'raw', 1.0,
                                                    data_link=LinkType.ETHERNET, count=1)),
        ):
            with self.subTest(function=name):
                with self.assertRaises(UnsupportedCall) as caught:
                    call()
                self.assertIn('no protocol dissection', str(caught.exception))

    def test_module_exports_the_documented_surface(self) -> None:
        from pcapkit.toolkit import pypcap

        self.assertEqual(sorted(pypcap.__all__), [
            'ipv4_reassembly', 'ipv6_reassembly', 'packet2chain', 'packet2dict',
            'tcp_reassembly', 'tcp_traceflow',
        ])
        for name in pypcap.__all__:
            self.assertTrue(callable(getattr(pypcap, name)), name)


if __name__ == '__main__':
    unittest.main()
