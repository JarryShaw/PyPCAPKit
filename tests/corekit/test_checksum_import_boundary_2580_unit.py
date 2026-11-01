# -*- coding: utf-8 -*-
"""Nothing under :mod:`pcapkit.corekit.checksum` imports :mod:`pcapkit.protocols`.

GitHub issue #2580 moved the Internet checksum out of :mod:`pcapkit.protocols`
into :mod:`pcapkit.corekit.checksum.internet`, so that the protocols build on it
rather than it on them; the IP pseudo-header, which needs IPv4 and IPv6, stayed
in :mod:`pcapkit.protocols.misc.checksum`. A checksum family added beside it
keeps to the same rule, so the whole package is checked: it imports
:mod:`pcapkit` only from ``corekit`` and ``utilities``.

The scan is the one :mod:`tests.project.test_utilities_import_boundary_1735_unit`
runs over :mod:`pcapkit.utilities`: every import, at top level, inside a function
and under ``TYPE_CHECKING`` alike, read with :mod:`ast`.

This module is unit-tier and reads no capture.

"""
from __future__ import annotations

import unittest

from tests.project.test_utilities_import_boundary_1735_unit import (ROOT, _module_name,
                                                                    imported_names)

#: The package the rule governs.
CHECKSUM = ROOT / 'pcapkit' / 'corekit' / 'checksum'

#: The :mod:`pcapkit` packages it may import.
ALLOWED = ('pcapkit.corekit', 'pcapkit.utilities')


def crosses_the_boundary(name: 'str') -> 'bool':
    """Whether importing ``name`` reaches :mod:`pcapkit` outside :data:`ALLOWED`."""
    if any(name == allowed or name.startswith(f'{allowed}.') for allowed in ALLOWED):
        return False
    return name == 'pcapkit' or name.startswith('pcapkit.')


def violations() -> 'list[str]':
    """Every import under :data:`CHECKSUM` that crosses the boundary, as ``path:line: name``."""
    found = []  # type: list[str]
    for path in sorted(CHECKSUM.rglob('*.py')):
        source = path.read_text(encoding='utf-8')
        for line, name in imported_names(source, _module_name(path),
                                         is_package=path.name == '__init__.py'):
            if crosses_the_boundary(name):
                found.append(f'{path.relative_to(ROOT).as_posix()}:{line}: {name}')
    return found


class ChecksumImportBoundaryTests(unittest.TestCase):
    """:mod:`pcapkit.corekit.checksum` stays below :mod:`pcapkit.protocols`."""

    def test_the_walk_found_the_package(self) -> None:
        names = {path.name for path in CHECKSUM.rglob('*.py')}
        self.assertIn('__init__.py', names)
        self.assertIn('internet.py', names)

    def test_no_module_imports_pcapkit_outside_corekit_and_utilities(self) -> None:
        found = violations()
        self.assertEqual(found, [],
                         'these modules under pcapkit/corekit/checksum/ import pcapkit from '
                         'outside corekit and utilities, which #2580 rules out; what needs '
                         'the protocols belongs beside IP_Pseudo in '
                         'pcapkit.protocols.misc.checksum:\n' + '\n'.join(found))

    def test_what_the_move_took_out_would_cross(self) -> None:
        source = '\n'.join([
            'from typing import TYPE_CHECKING',                                  # 1
            'from pcapkit.corekit.enum import EnumLookup',                       # 2
            'from pcapkit.utilities.warnings import ChecksumWarning, warn',      # 3
            'from pcapkit.protocols.protocol import _rebuilding',                # 4
            'if TYPE_CHECKING:',                                                 # 5
            '    from pcapkit.protocols.misc.checksum.ip_pseudo import IP_Pseudo',  # 6
            'def verify_upper(ip):',                                             # 7
            '    from pcapkit.protocols.internet.ah import AH',                  # 8
            '    from pcapkit import foundation',                                # 9
        ])
        crossing = [(line, name)
                    for line, name in imported_names(source, 'pcapkit.corekit.checksum.demo')
                    if crosses_the_boundary(name)]
        self.assertEqual(crossing, [
            (4, 'pcapkit.protocols.protocol'),
            (6, 'pcapkit.protocols.misc.checksum.ip_pseudo'),
            (8, 'pcapkit.protocols.internet.ah'),
            (9, 'pcapkit.foundation'),
        ])


if __name__ == '__main__':
    unittest.main()
