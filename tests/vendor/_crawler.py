# -*- coding: utf-8 -*-
"""Shared scaffolding for the crawler tests. C.f. #3148.

The modules under :file:`tests/vendor/`, and :mod:`tests.const.test_const_enum_lookup`,
render constant modules from recorded data and compare them with the committed files,
which takes the same few steps in each:

* :func:`import_from_checkout` -- import the crawler and constant modules, and skip
  unless they come from this checkout. Compared against this repository's files, a
  module imported from an installed copy elsewhere would be comparing two trees,
  which is an environment mismatch rather than a defect.
* :func:`make_crawler` -- a crawler with the attributes
  :meth:`Vendor.__init__ <pcapkit.vendor.default.Vendor.__init__>` sets, without its
  fetch and the constant file it writes.
* :func:`normalize` -- the whitespace normalisation that write goes through.
* :func:`defined_crawlers` -- every crawler defined under :file:`pcapkit/vendor/`.

It is deliberately not named ``test_*``, and it imports :mod:`pcapkit` only when a
test calls it, after :func:`tests._support.reimport_once_per_class`.

"""
from __future__ import annotations

import importlib
import pathlib
import pkgutil
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import unittest
    from types import ModuleType
    from typing import Any

__all__ = ['ROOT', 'import_from_checkout', 'make_crawler', 'normalize', 'is_crawler', 'defined_crawlers']

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]


def import_from_checkout(test: 'unittest.TestCase', *names: 'str') -> 'tuple[ModuleType, ...]':
    """Import ``names``, skipping ``test`` unless each comes from this checkout.

    Args:
        test: The test case to skip.
        *names: Dotted names of the modules to import.

    Returns:
        The modules, in the order named.

    """
    modules = tuple(importlib.import_module(name) for name in names)
    for module in modules:
        resolved = pathlib.Path(module.__file__).resolve()  # type: ignore[arg-type]
        if ROOT not in resolved.parents:
            test.skipTest(f'{module.__name__} was imported from {resolved}, which is outside '
                          f'{ROOT}; install this checkout with `pip install -e .`, or set '
                          f'PYTHONPATH to it, to run this suite against it')
    return modules


def make_crawler(klass: 'type[Any]', *args: 'Any') -> 'tuple[Any, Any]':
    """A ``klass`` crawler as :meth:`Vendor.__init__` would set it up.

    ``Vendor.__init__`` fetches over the network and *writes* the constant file
    as a side effect of construction, neither of which a test has any business
    doing, so the attributes it sets -- ``NAME``, ``DOCS`` and ``record`` -- are
    set here instead.

    Args:
        klass: The crawler class.
        *args: What to hand :meth:`~pcapkit.vendor.default.Vendor.request` in
            place of a fetched page; nothing for a crawler with no ``LINK``.

    Returns:
        The crawler, and the data its ``request`` returned.

    """
    vendor = klass.__new__(klass)
    vendor.NAME = klass.__name__
    vendor.DOCS = klass.__doc__
    data = vendor.request(*args)
    vendor.record = vendor.count(data)
    return vendor, data


def normalize(context: 'str') -> 'str':
    """Apply the whitespace normalisation the generator writes files through.

    :meth:`pcapkit.vendor.default.Vendor.__init__` does not write what
    :meth:`~pcapkit.vendor.default.Vendor.context` returns verbatim: it strips
    trailing whitespace from every non-blank line, drops whitespace-only lines
    outright, and ends the file with a newline courtesy of :func:`print`. Byte
    comparison against the committed file has to do the same, or it reports a
    difference that regeneration would not produce.

    Args:
        context: Return value of :meth:`~pcapkit.vendor.default.Vendor.context`,
            or any template rendered for a constant module.

    Returns:
        The text as the generator would have written it to disk.

    """
    lines = []  # type: list[str]
    for line in context.splitlines():
        if line:
            if line.strip():
                lines.append(line.rstrip())
        else:
            lines.append(line)
    return '\n'.join(lines) + '\n'


def is_crawler(obj: 'Any', base: 'type[Any]') -> 'bool':
    """Whether ``obj`` is a concrete crawler class.

    :class:`~pcapkit.vendor.default.Vendor` itself is excluded: it is the
    abstract base, it is exported from :mod:`pcapkit.vendor` for subclassing
    rather than for running, and it is not in :attr:`__all__`.

    Args:
        obj: Anything a module exports.
        base: :class:`~pcapkit.vendor.default.Vendor`, from the current import.

    """
    return isinstance(obj, type) and issubclass(obj, base) and obj is not base


def defined_crawlers(vendor: 'ModuleType', base: 'type[Any]') -> 'dict[str, Any]':
    """Every crawler defined under :file:`pcapkit/vendor/`, by qualified name.

    Discovered from the filesystem with :func:`pkgutil.walk_packages`, which
    is the half of a comparison :attr:`__all__` cannot influence -- so a
    crawler that exists and is not listed is still found.

    A class is attributed to the module that *defines* it, i.e. where
    ``__module__`` points, so the re-exports every subpackage performs do not
    each count as another crawler.

    Args:
        vendor: The :mod:`pcapkit.vendor` package, from the current import.
        base: :class:`~pcapkit.vendor.default.Vendor`, from the current import.

    """
    found = {}  # type: dict[str, Any]
    for info in pkgutil.walk_packages(vendor.__path__, prefix='pcapkit.vendor.'):
        if any(part.startswith('_') for part in info.name.split('.')):
            continue
        module = importlib.import_module(info.name)
        for name in getattr(module, '__all__', ()):
            obj = getattr(module, name, None)
            if is_crawler(obj, base) and obj.__module__ == info.name:
                found[f'{info.name}.{name}'] = obj
    return found
