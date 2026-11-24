# -*- coding: utf-8 -*-
"""Every built-in output dumper has a format macro, exported beside the others. C.f. #3047.

A format macro is a name in ``pcapkit.interface.core.__all__`` bound to a key of
``Extractor.__output__``, so the dumpers the macros reach are read off that table
rather than listed here. The PCAP-NG macro is ``PCAP_NG``: ``pcapkit`` and
``pcapkit.all`` already bind ``PCAPNG`` to the protocol class, which a macro of
that name would shadow in one and be shadowed by in the other.

"""

from __future__ import annotations

import importlib
import importlib.util
import unittest

from tests._support import reimport_once_per_class

#: Test tier (#1958): export lists and a lookup table, the same on every interpreter.
__tier__ = 'LATEST'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Every namespace exporting the format macros.
EXPORTERS = ('pcapkit.interface.core', 'pcapkit.interface', 'pcapkit', 'pcapkit.all')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FormatMacroTests(unittest.TestCase):
    """The format macros cover ``Extractor.__output__``, and ``PCAPNG`` keeps its meaning."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_every_dumper_has_a_macro(self) -> None:
        import pcapkit.interface.core as core
        from pcapkit.foundation.extraction import Extractor

        table = Extractor.__output__
        values = [getattr(core, name) for name in core.__all__]
        reached = {table[value][0] for value in values if isinstance(value, str) and value in table}
        missing = {dumper for dumper, _ in table.values()} - reached
        self.assertEqual(sorted(map(str, missing)), [])

    def test_pcap_ng_selects_the_pcapng_dumper(self) -> None:
        from pcapkit.corekit.module import ModuleDescriptor
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.interface.core import PCAP_NG

        self.assertEqual(PCAP_NG, 'pcapng')
        self.assertEqual(Extractor.__output__[PCAP_NG],
                         (ModuleDescriptor('pcapkit.dumpkit', 'PCAPNGIO'), '.pcapng'))

    def test_exported_beside_the_other_format_macros(self) -> None:
        from pcapkit.interface.core import PCAP_NG

        for name in EXPORTERS:
            with self.subTest(module=name):
                module = importlib.import_module(name)
                self.assertIn('PCAP_NG', module.__all__)
                self.assertIs(getattr(module, 'PCAP_NG'), PCAP_NG)

    def test_pcapng_stays_the_protocol_class(self) -> None:
        from pcapkit.protocols.misc.pcapng.protocol import PCAPNG

        for name in ('pcapkit', 'pcapkit.all'):
            with self.subTest(module=name):
                self.assertIs(getattr(importlib.import_module(name), 'PCAPNG'), PCAPNG)


if __name__ == '__main__':
    unittest.main()
