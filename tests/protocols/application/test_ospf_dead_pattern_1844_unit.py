# -*- coding: utf-8 -*-
"""The unused Ethernet-address pattern in the OSPF module.

GitHub issue #1844. :mod:`pcapkit.protocols.application.ospf` defined a
``PAT_MAC_ADDR`` that nothing read, a leftover that came along when OSPF moved
to the application layer in #1031, and it imported :mod:`re` only to compile
it. The constant and the import are gone. This pins that the constant stays
gone and that the module does not import :mod:`re` without using it. The
copies of the pattern in the Ethernet, ARP and PCAP-NG modules have readers
and are untouched.

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
        from pcapkit.protocols.application import ospf

        self.assertFalse(hasattr(ospf, 'PAT_MAC_ADDR'))

    def test_re_is_not_imported_unused(self) -> None:
        # Read the source of the module actually imported, so the check runs
        # against the tree under test. ``re`` may come back if something uses
        # it; what must not return is the import with no reader.
        from pcapkit.protocols.application import ospf

        with open(ospf.__file__, encoding='utf-8') as file:
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
        self.assertFalse(imports_re and not reads_re,
                         f'{ospf.__file__} imports re but never uses it')


if __name__ == '__main__':
    unittest.main()
