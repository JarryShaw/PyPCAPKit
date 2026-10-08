# -*- coding: utf-8 -*-
"""Every :class:`~pcapkit.corekit.fields.strings.BitField` names all of its bits.

GitHub issue #1288: :meth:`BitField.pre_process
<pcapkit.corekit.fields.strings.BitField.pre_process>` starts from an all-zero
buffer and writes only the subfields its ``namespace`` names, so a bit no
subfield covers is packed as zero whatever was parsed. The per-protocol fixes
(#1226, #1253, #1254, #1307, #1310) named a ``reserved`` subfield site by site.
This module is the invariant behind them: it walks every schema under
:mod:`pcapkit.protocols.schema` and checks that each bit field's namespace
covers its full width exactly once -- no gap and no overlap.

A bit field wrapped in :class:`~pcapkit.corekit.fields.misc.ForwardMatchField`
is exempt by construction, not by allowlist: such a field only peeks ahead,
packs to no octets, and the bits it reads are packed again by the fields that
follow it.

Discovery is cross-checked against the source: the number of ``BitField(...)``
calls in each schema module must equal the number of bit fields found in it, so
one constructed where the walk cannot see it -- inside a selector, say -- fails
here rather than escaping the check.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""
from __future__ import annotations

import ast
import importlib
import os
import pkgutil
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Iterator

#: Bit fields allowed to leave bits unnamed, as ``schema.field`` (relative to
#: :mod:`pcapkit.protocols.schema`) -> the ``(start, length)`` bit ranges left
#: uncovered. Every known site has been fixed, so this is empty, and it must
#: stay empty unless a new gap is filed as a GitHub issue. An entry must match
#: exactly: once its site is fixed the entry has to go, and a site that changes
#: shape has to be looked at again.
#:
#: A gap packs its unnamed bits as zero, so a parsed packet with any of them
#: set does not rebuild byte-exactly.
KNOWN_GAPS: 'dict[str, tuple[tuple[int, int], ...]]' = {}


def _gaps(width: 'int', namespace: 'dict[str, tuple[int, int]]') -> 'tuple[tuple[int, int], ...]':
    """Return the ``(start, length)`` runs of bits no subfield covers."""
    covered = [False] * width
    for start, size in namespace.values():
        covered[start:start + size] = [True] * size
    runs = []  # type: list[tuple[int, int]]
    bit = 0
    while bit < width:
        if covered[bit]:
            bit += 1
            continue
        end = bit
        while end < width and not covered[end]:
            end += 1
        runs.append((bit, end - bit))
        bit = end
    return tuple(runs)


def _overlaps(namespace: 'dict[str, tuple[int, int]]') -> 'list[int]':
    """Return the bits more than one subfield claims."""
    seen = set()  # type: set[int]
    shared = set()  # type: set[int]
    for start, size in namespace.values():
        for bit in range(start, start + size):
            (shared if bit in seen else seen).add(bit)
    return sorted(shared)


class TestBitFieldCoverage(unittest.TestCase):
    """Pin that no schema bit field packs an unnamed bit."""

    maxDiff = None

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _discover(self) -> 'dict[str, tuple[Any, bool, str]]':
        """Map ``schema.field`` to each bit field found, whether it sits under a
        :class:`ForwardMatchField`, and the module declaring it."""
        import pcapkit.protocols.schema as package
        from pcapkit.corekit.fields.misc import ForwardMatchField
        from pcapkit.corekit.fields.strings import BitField
        from pcapkit.protocols.schema.schema import Schema

        repo = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
        self.assertTrue(os.path.abspath(package.__file__).startswith(repo + os.sep), package.__file__)
        for info in pkgutil.walk_packages(package.__path__, f'{package.__name__}.'):
            importlib.import_module(info.name)

        def subclasses(cls: 'type') -> 'Iterator[type]':
            for sub in cls.__subclasses__():
                yield sub
                yield from subclasses(sub)

        found = {}  # type: dict[int, tuple[str, Any, bool, str]]

        def walk(obj: 'Any', where: 'tuple[str, str]', forward: 'bool', seen: 'set[int]') -> 'None':
            if id(obj) in seen:
                return
            seen.add(id(obj))
            if isinstance(obj, BitField):
                found.setdefault(id(obj), (where[0], obj, forward, where[1]))
            elif isinstance(obj, (list, tuple, set, frozenset)):
                for item in obj:
                    walk(item, where, forward, seen)
            elif isinstance(obj, dict):
                for item in obj.values():
                    walk(item, where, forward, seen)
            elif type(obj).__module__.startswith('pcapkit.corekit.fields') and hasattr(obj, '__dict__'):
                inner = forward or isinstance(obj, ForwardMatchField)
                for item in vars(obj).values():
                    walk(item, where, inner, seen)

        prefix = f'{package.__name__}.'
        for cls in set(subclasses(Schema)):
            if not cls.__module__.startswith(prefix):
                continue
            module = cls.__module__[len(prefix):]
            for name, field in cls.__dict__.get('__fields__', {}).items():
                walk(field, (f'{module}.{cls.__qualname__}.{name}', module), False, set())
        return {where: (field, forward, module) for where, field, forward, module in found.values()}

    def test_discovery_matches_source(self) -> None:
        import pcapkit.protocols.schema as package

        found = self._discover()
        per_module = {}  # type: dict[str, int]
        for _, _, module in found.values():
            per_module[module] = per_module.get(module, 0) + 1

        root = os.path.dirname(package.__file__)
        for info in pkgutil.walk_packages(package.__path__, ''):
            if info.ispkg:
                continue
            path = os.path.join(root, *info.name.split('.')) + '.py'
            with open(path, encoding='utf-8') as file:
                tree = ast.parse(file.read(), path)
            calls = sum(1 for node in ast.walk(tree)
                        if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == 'BitField')
            with self.subTest(module=info.name):
                self.assertEqual(per_module.get(info.name, 0), calls)
        self.assertGreater(len(found), 0)

    def test_every_bitfield_names_all_its_bits(self) -> None:
        found = self._discover()
        gaps = {}  # type: dict[str, tuple[tuple[int, int], ...]]
        for where, (field, forward, _) in sorted(found.items()):
            namespace = field._namespace  # pylint: disable=protected-access
            with self.subTest(field=where):
                self.assertEqual(_overlaps(namespace), [])
            if forward:
                continue
            run = _gaps(field.length * 8, namespace)
            if run:
                gaps[where] = run
        self.assertEqual(gaps, KNOWN_GAPS)

    def test_gap_finder_catches_an_unnamed_bit(self) -> None:
        from pcapkit.corekit.fields.strings import BitField

        field = BitField(length=1, namespace={'x': (0, 1), 'y': (7, 1)})
        namespace = field._namespace  # pylint: disable=protected-access
        self.assertEqual(_gaps(field.length * 8, namespace), ((1, 6),))
        self.assertEqual(_gaps(8, {'x': (0, 8)}), ())
        self.assertEqual(_overlaps({'x': (0, 4), 'y': (3, 5)}), [3])


if __name__ == '__main__':
    unittest.main()
