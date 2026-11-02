# -*- coding: utf-8 -*-
"""The registries :mod:`pcapkit.const` defines, and the kind of each. C.f. #2615.

The const sweeps -- :mod:`tests.const.test_const_enum_builtin_parity`,
:mod:`tests.const.test_const_enum_get`, :mod:`tests.const.test_const_enum_lookup`
and :mod:`tests.const.test_const_registry_protocol` -- each discover the
registries by walking the tree, and each holds what it found to this census by
name, through :func:`compare`. So a registry added, dropped or changed in kind
fails every sweep that covers it, and the failure names the registry, where a
pinned count fails on the same changes without naming anything.

The census is one module per package of :mod:`pcapkit.const`, named after the
package and found by :func:`pkgutil.iter_modules`. Each holds a ``REGISTRIES``
mapping of ``module:QualName`` to a kind, sorted, one registry per line. A
registry added to a package is one line in that package's module, and an added
package is one added module, so changes to unrelated packages touch disjoint
files rather than the same pins in every sweep.
:mod:`tests.const.test_const_census_2615_unit` holds the modules to that layout.

The kinds partition the registries as the sweeps split them: ``'flag'`` is an
:class:`aenum.Flag`, ``'str'`` a :class:`str` enumeration that is no flag, and
``'int'`` an :class:`int` one that is no flag.

Nothing here imports :mod:`pcapkit`, so loading the census leaves nothing behind
for a sweep that purges and re-imports it.

"""
from __future__ import annotations

import collections
import importlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from types import ModuleType
    from typing import Iterable

__all__ = ['KINDS', 'MANIFESTS', 'REGISTRIES', 'AGREES', 'ADVICE',
           'names', 'modules', 'paths', 'compare']

#: The kinds a registry is recorded as.
KINDS = ('int', 'flag', 'str')


def _manifests() -> 'dict[str, ModuleType]':
    """Every census module, keyed by the package of :mod:`pcapkit.const` it covers."""
    found = sorted(info.name for info in pkgutil.iter_modules(__path__))
    return {name: importlib.import_module(f'{__name__}.{name}') for name in found}


#: Each census module, keyed by the package of :mod:`pcapkit.const` it covers.
MANIFESTS = _manifests()

#: Every registry in the census, as ``module:QualName``, and its kind.
REGISTRIES = {name: kind for manifest in MANIFESTS.values()
              for name, kind in manifest.REGISTRIES.items()}

#: What :func:`compare` returns when a sweep and the census agree.
AGREES = {'found twice': [], 'not in the census': [], 'not found': []}  # type: dict[str, list[str]]

#: What a sweep that disagrees with the census asks for.
ADVICE = ('the registries under pcapkit.const differ from tests/const/census: record an '
          "added, removed or re-kinded registry in its package's census module, then check "
          "that the sweep's exception sets still hold for it")


def names(*kinds: 'str') -> 'frozenset[str]':
    """Every registry of ``kinds``, as the dotted ``module.QualName`` the sweeps key on.

    Args:
        kinds: Any of :data:`KINDS`.

    Returns:
        The registries' dotted names.

    """
    return frozenset(name.replace(':', '.') for name, kind in REGISTRIES.items() if kind in kinds)


def modules() -> 'frozenset[str]':
    """Every module the census places a registry in."""
    return frozenset(name.split(':', 1)[0] for name in REGISTRIES)


def paths() -> 'list[str]':
    """:func:`modules`, as sorted repository-relative file paths."""
    return sorted(module.replace('.', '/') + '.py' for module in modules())


def compare(found: 'Iterable[str]', expected: 'Iterable[str]') -> 'dict[str, list[str]]':
    """How what a sweep found differs from what the census expects.

    Args:
        found: What the sweep discovered, one entry per discovery.
        expected: What the census holds for that sweep.

    Returns:
        A mapping equal to :data:`AGREES` exactly when ``found`` holds each of
        ``expected`` once and nothing else; otherwise its lists name the
        entries found more than once, found but not expected, and expected but
        not found.

    """
    seen = collections.Counter(found)
    wanted = set(expected)
    return {'found twice': sorted(name for name, count in seen.items() if count > 1),
            'not in the census': sorted(set(seen) - wanted),
            'not found': sorted(wanted - set(seen))}
