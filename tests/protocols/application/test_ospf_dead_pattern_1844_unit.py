# -*- coding: utf-8 -*-
"""The unused Ethernet-address pattern in the OSPF, Ethernet and PCAP-NG modules.

GitHub issue #1844. Guards against
:mod:`pcapkit.protocols.application.ospf.protocol` defining a ``PAT_MAC_ADDR`` that
nothing reads, and importing :mod:`re` only to compile it. These tests pin
that the constant is absent and that the module does not import :mod:`re`
without using it.

The Ethernet and PCAP-NG copies lost their readers when the MAC address maker
moved to ``ProtocolBase`` (#2614), so they are pinned absent too, as is the
Ethernet module's :mod:`re` import. The ARP copy, which matches an address of
any number of octets, has a reader and stays.

"""
from __future__ import annotations

import ast
import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class OSPFDeadPatternUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_pat_mac_addr_is_gone(self) -> None:
        from pcapkit.protocols.application.ospf import protocol as ospf
        from pcapkit.protocols.link.ethernet import protocol as ethernet
        from pcapkit.protocols.misc.pcapng import protocol as pcapng

        for module in (ospf, ethernet, pcapng):
            with self.subTest(module=module.__name__):
                self.assertFalse(hasattr(module, 'PAT_MAC_ADDR'))

    def test_re_is_not_imported_unused(self) -> None:
        # Read the source of the module actually imported, so the check runs
        # against the tree under test. ``re`` may come back if something uses
        # it; what must not return is the import with no reader.
        from pcapkit.protocols.application.ospf import protocol as ospf
        from pcapkit.protocols.link.ethernet import protocol as ethernet

        for module in (ospf, ethernet):
            with open(module.__file__, encoding='utf-8') as file:
                tree = ast.parse(file.read())

            imports_re = any(
                alias.name == 're' and alias.asname is None
                for node in tree.body if isinstance(node, ast.Import)
                for alias in node.names
            )
            reads_re = any(
                isinstance(node, ast.Name) and node.id == 're'
                for node in ast.walk(tree)
            )
            with self.subTest(module=module.__name__):
                self.assertFalse(imports_re and not reads_re,
                                 f'{module.__file__} imports re but never uses it')


if __name__ == '__main__':
    unittest.main()
