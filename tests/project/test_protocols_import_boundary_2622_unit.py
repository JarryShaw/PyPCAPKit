# -*- coding: utf-8 -*-
"""Protocol code imports nothing from :mod:`pcapkit.foundation` to do its own work (#2622).

The owner ruled on #2622 that the protocol class owns the parse of a reassembled
outcome, and :mod:`pcapkit.foundation.analysis` only calls it: the dependency runs
from ``foundation`` to the protocols. So no module under :file:`pcapkit/protocols/`
imports :mod:`pcapkit.foundation`, except where the import does no protocol work:

* :mod:`pcapkit.foundation.registry.protocols` and any module under it, which the
  protocol base's registration hooks reach to register a class -- the rest of
  :mod:`pcapkit.foundation.registry` is not exempt;
* an import inside an ``if TYPE_CHECKING:`` block, which only an annotation reads.

Imports are found by
:func:`tests.project.test_utilities_import_boundary_1735_unit.imported_names`, so a
lazy, relative or literal dynamic import counts as well. The rule is written down on
:file:`docs/source/contributing/conventions/reassembly-integration.rst`.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import ast
import unittest

from tests.project.test_utilities_import_boundary_1735_unit import ROOT, _module_name, imported_names

#: The protocol package the rule governs.
PROTOCOLS = ROOT / 'pcapkit' / 'protocols'

#: The package protocol code may not import from.
FOUNDATION = 'pcapkit.foundation'

#: The part of it the protocol base's registration hooks reach, which the rule
#: allows, with any module under it.
REGISTRATION = 'pcapkit.foundation.registry.protocols'


def _within(name: 'str', package: 'str') -> 'bool':
    """Whether ``name`` is ``package`` or a module under it."""
    return name == package or name.startswith(f'{package}.')


def _type_checking_lines(source: 'str') -> 'set[int]':
    """Every line inside the body of an ``if TYPE_CHECKING:`` block of ``source``."""
    lines = set()  # type: set[int]
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        name = test.attr if isinstance(test, ast.Attribute) else getattr(test, 'id', None)
        if name != 'TYPE_CHECKING':
            continue
        for stmt in node.body:
            lines.update(range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1))
    return lines


def violations(source: 'str', module: 'str', is_package: 'bool' = False) -> 'list[tuple[int, str]]':
    """Every import of :data:`FOUNDATION` in ``source`` that the rule does not allow."""
    typing_only = _type_checking_lines(source)
    return [(line, name) for line, name in imported_names(source, module, is_package)
            if _within(name, FOUNDATION) and not _within(name, REGISTRATION)
            and line not in typing_only]


class ProtocolsImportBoundaryTests(unittest.TestCase):
    """:mod:`pcapkit.protocols` does no work through :mod:`pcapkit.foundation`."""

    def test_the_walk_found_the_package(self) -> None:
        names = {path.relative_to(PROTOCOLS).as_posix() for path in PROTOCOLS.rglob('*.py')}
        self.assertIn('protocol.py', names)
        self.assertIn('application/dtls.py', names)

    def test_no_protocol_module_imports_foundation_to_do_its_work(self) -> None:
        found = []  # type: list[str]
        for path in sorted(PROTOCOLS.rglob('*.py')):
            source = path.read_text(encoding='utf-8')
            for line, name in violations(source, _module_name(path), path.name == '__init__.py'):
                found.append(f'{path.relative_to(ROOT).as_posix()}:{line}: {name}')
        self.assertEqual(found, [],
                         'these modules under pcapkit/protocols/ import pcapkit.foundation, '
                         'which #2622 rules out: the protocol class owns the parse, and '
                         'pcapkit.foundation only calls it:\n' + '\n'.join(found))

    def test_the_scanner_tells_the_allowed_imports_apart(self) -> None:
        source = '\n'.join([
            'from typing import TYPE_CHECKING',                           # 1
            'from pcapkit.foundation.analysis.dtls import dtls_handshake',  # 2
            'from ...foundation.reassembly import dtls',                  # 3
            'from pcapkit import foundation',                             # 4
            'from pcapkit.foundation.registry.protocols import register',  # 5
            'if TYPE_CHECKING:',                                          # 6
            '    from pcapkit.foundation.engines.pcapng import Context',  # 7
            'else:',                                                      # 8
            '    import pcapkit.foundation.extraction',                   # 9
            'def f():',                                                   # 10
            '    from pcapkit.foundation.registry.protocols.tcp import r',  # 11
            '    importlib.import_module("pcapkit.foundation.traceflow")',  # 12
            '    from pcapkit.corekit import fields',                     # 13
            '    from pcapkit.foundation.registry.foundation import e',   # 14
            '    from pcapkit.foundation.registry import protocols',      # 15
            '    from pcapkit.foundation.registry.protocolsx import x',   # 16
        ])
        self.assertEqual(violations(source, 'pcapkit.protocols.application.dtls'), [
            (2, 'pcapkit.foundation.analysis.dtls'),
            (3, 'pcapkit.foundation.reassembly'),
            (4, 'pcapkit.foundation'),
            (9, 'pcapkit.foundation.extraction'),
            (12, 'pcapkit.foundation.traceflow'),
            (14, 'pcapkit.foundation.registry.foundation'),
            (15, 'pcapkit.foundation.registry'),
            (16, 'pcapkit.foundation.registry.protocolsx'),
        ])


if __name__ == '__main__':
    unittest.main()
