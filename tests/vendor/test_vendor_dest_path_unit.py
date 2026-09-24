# -*- coding: utf-8 -*-
"""Regression tests for :meth:`pcapkit.vendor.default.Vendor._dest_path`.

Prerequisite for GitHub issue #732, which turns
:file:`pcapkit/const/reg/apptype.py` into a package with per-transport modules
(``tcp.py``, ``udp.py``, ``dccp.py``, ``sctp.py``) mirrored under
:file:`pcapkit/vendor/reg/apptype/`. Before that split can be generated, the
path derivation :meth:`~pcapkit.vendor.default.Vendor.__init__` uses to decide
where to write a crawler's constant file has to handle a module nested *two*
levels under :mod:`pcapkit.vendor`, not just one.

The pre-fix code derived that path by splitting the module's absolute
filesystem path into exactly two levels:

.. code-block:: python

   temp, FILE = os.path.split(os.path.abspath(inspect.getfile(type(self))))
   ROOT, STEM = os.path.split(temp)
   os.makedirs(os.path.join(ROOT, '..', 'const', STEM), exist_ok=True)
   with open(os.path.join(ROOT, '..', 'const', STEM, FILE), 'w') as file:

That is correct only because every crawler today sits exactly one level under
``vendor/``, e.g. :mod:`pcapkit.vendor.reg.apptype` writes
:file:`pcapkit/const/reg/apptype.py`. Traced by hand for a module one level
deeper -- :file:`pcapkit/vendor/reg/apptype/tcp.py`, the shape #732 needs --
``temp`` is :file:`.../vendor/reg/apptype`, so ``ROOT`` becomes
:file:`.../vendor/reg` and ``STEM`` becomes ``apptype``. The write then lands at
:file:`.../vendor/reg/../const/apptype/tcp.py`, i.e.
:file:`pcapkit/vendor/const/apptype/tcp.py` -- *inside* ``vendor/`` itself,
never reaching :mod:`pcapkit.const` at all.

The fix, :meth:`~pcapkit.vendor.default.Vendor._dest_path`, anchors on the
``vendor`` package's own ``__file__`` instead of counting a fixed number of
path components, and mirrors whatever path a module sits at *relative to*
``vendor/`` under ``const/``.

That relative-path mirroring has its own failure mode, caught in review
rather than by any test written for the first version of this change:
``const/`` and ``vendor/`` are siblings at equal depth, so for a module that
is *not* under the resolved ``vendor_root`` -- a second checkout, or any
module whose file simply is not under ``vendor/`` -- the leading ``..``
segments of ``os.path.relpath(module, vendor_root)`` cancel out exactly
against ``const_root``, reproducing the module's own path. Unguarded,
:meth:`Vendor.__init__` then opens that with ``'w'``, silently truncating the
crawler's own source. The fix rejects that case outright, raising
:exc:`~pcapkit.utilities.exceptions.VendorPathNotFound` instead of returning
a path that happens to equal its input.

Three things are pinned:

* :class:`ExistingCrawlerDestPathTests` -- the regression guard. Every crawler
  discovered under :mod:`pcapkit.vendor` today is depth-one, and each must still
  resolve to exactly the :file:`const/` file it writes today; this is the "did
  not move" half of the contract, checked by enumerating the real crawlers on
  disk rather than sampling a couple by name.
* :class:`NestedCrawlerDestPathTests`\\ 's
  :meth:`~NestedCrawlerDestPathTests.test_nested_module_resolves_under_const`
  -- the case that motivated the fix. A stub crawler is built two levels
  under a *synthetic* ``vendor/`` tree in a temporary directory (never inside
  the checkout, since :meth:`Vendor.__init__` -- not exercised here -- would
  otherwise write into it), and :meth:`_dest_path` is asserted to mirror it
  under a sibling ``const/`` at the same relative depth. Run against the
  pre-fix code (with the ``_dest_path`` hunk reverted by hand), this raises
  ``AttributeError: 'TCP' object has no attribute '_dest_path'`` -- the method
  the fix introduces does not exist yet, which is itself evidence the old
  inline code could not have passed this case either: :func:`_old_algorithm`
  below reproduces the reverted logic directly against the same synthetic
  paths and lands it at ``vendor/const/apptype/tcp.py``, confirming the trace
  above without needing the checkout's real crawlers.
* :class:`NestedCrawlerDestPathTests`\\ 's
  :meth:`~NestedCrawlerDestPathTests.test_module_outside_vendor_root_raises_instead_of_self_truncating`
  -- the destructive escape case above, pinned directly: a stub crawler's
  module file stays where it is, but ``vendor_root`` is patched to an
  unrelated temporary tree that shares no ancestry with it beyond the
  filesystem root, and :meth:`_dest_path` is asserted to raise rather than to
  return the module's own path.

Neither class calls :meth:`Vendor.__init__`: it fetches from IANA/Wikipedia and
writes the constant file as a side effect of construction, so every instance
here is built with ``cls.__new__(cls)`` -- the same bypass
:file:`tests/vendor/test_crawler_reachability_unit.py` and
:file:`tests/vendor/test_user_agent_unit.py` already use for the same reason.

The suite is unit-tier (see :mod:`tests._tiers`): it reads no capture and makes
no network call. Both classes are gated on :data:`HAS_VENDOR_DEPS`, the same
two-dependency gate :file:`tests/vendor/test_crawler_reachability_unit.py`
uses, because importing :mod:`pcapkit.vendor.default` first imports the
:mod:`pcapkit.vendor` package, whose :file:`__init__.py` pulls in every
crawler subpackage unconditionally -- seven of which ``import bs4`` at module
scope. ``html5lib`` is deliberately *not* in the gate: it appears nowhere at
module scope, only as the string parser name in six crawlers'
``bs4.BeautifulSoup(text, 'html5lib')`` calls at actual crawl time, which
nothing here reaches -- no test in this file calls :meth:`Vendor.__init__` or
:meth:`~Vendor.context`. ``requests`` and ``beautifulsoup4`` both ship in the
``test`` extra precisely so vendor tests can run (:file:`pyproject.toml`,
around line 243), so both classes below run in CI as things stand, unlike
:file:`tests/vendor/test_user_agent_unit.py`, whose own gate also lists
``html5lib`` and skips there because of it.

"""
from __future__ import annotations

import importlib
import importlib.util
import inspect
import os
import pathlib
import pkgutil
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import purge_modules

if TYPE_CHECKING:
    from typing import Any

#: Repository root, i.e. the grandparent of the directory holding this file.
ROOT = pathlib.Path(__file__).resolve().parents[2]

#: Every distribution importing :mod:`pcapkit.vendor` needs, for the reason the
#: module docstring above gives. Deliberately just the two
#: :file:`tests/vendor/test_crawler_reachability_unit.py` uses -- not the
#: three :file:`tests/vendor/test_user_agent_unit.py` gates on, since
#: ``html5lib`` is not needed to reach anything either of the classes below
#: exercises.
VENDOR_DEPS = ('requests', 'bs4')

#: Whether the crawlers are importable at all. Both packages ship in the
#: ``test`` extra (:file:`pyproject.toml`), so this is ``True`` under a plain
#: ``pip install -e '.[test]'`` and both classes below run in CI as things
#: stand -- kept as belt-and-braces for an environment that lacks them, the
#: same way :file:`tests/vendor/test_crawler_reachability_unit.py` guards it.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)


def _old_algorithm(module_file: 'str') -> 'str':
    """Reproduce the reverted, pre-fix path derivation directly.

    Verbatim translation of the hunk this change replaces -- two
    :func:`os.path.split` calls and a pair of ``os.path.join(ROOT, '..', ...)``
    -- kept here rather than imported, since the whole point is a copy that
    survives the fix being applied. Used only by
    :meth:`NestedCrawlerDestPathTests.test_old_algorithm_would_have_written_inside_vendor`
    to show *what* the old code got wrong, independent of whether
    ``Vendor._dest_path`` currently exists to be reverted and re-run by hand.

    Args:
        module_file: Absolute path of the crawler's own module file.

    Returns:
        The path the pre-fix code would have opened for writing.

    """
    temp, file_name = os.path.split(os.path.abspath(module_file))
    root, stem = os.path.split(temp)
    return os.path.join(root, os.pardir, 'const', stem, file_name)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class ExistingCrawlerDestPathTests(unittest.TestCase):
    """Every crawler on disk resolves to the constant file it actually owns.

    The regression guard: :meth:`Vendor._dest_path` must not move a single
    existing crawler's output, enumerated from the filesystem rather than
    sampled by name so that adding a crawler without adding it here cannot
    silently go unchecked.

    A depth-one crawler is held to the pre-fix formula, which is what "must not
    move" means for the 116 that predate the fix. The five nested ones GitHub
    issue #732 added -- :mod:`pcapkit.vendor.reg.apptype` and its four
    per-transport modules -- are held to the mirrored path instead, since the
    pre-fix formula is precisely what cannot express them: it would put
    ``vendor/reg/apptype/tcp.py`` at ``vendor/const/apptype/tcp.py``, inside
    ``vendor/`` itself. Both arms end at the same assertion, that the file is
    really there, which is the half of this test the formula cannot fake.

    """

    if TYPE_CHECKING:
        vendor: 'Any'
        Vendor: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import pcapkit
        import pcapkit.vendor as vendor
        from pcapkit.vendor.default import Vendor

        # Comparing this checkout's crawlers against this checkout's __file__
        # only means something if pcapkit was actually imported from here --
        # see test_crawler_reachability_unit.py's setUp for the same guard.
        resolved = pathlib.Path(pcapkit.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'pcapkit was imported from {resolved}, which is outside {ROOT}; '
                          f'install this checkout with `pip install -e .`, or set PYTHONPATH to '
                          f'it, to run this suite against it')

        self.vendor = vendor
        self.Vendor = Vendor

    def _is_crawler(self, obj: 'Any') -> 'bool':
        return isinstance(obj, type) and issubclass(obj, self.Vendor) and obj is not self.Vendor

    def _defined_crawlers(self) -> 'dict[str, Any]':
        """Every crawler class defined under :file:`pcapkit/vendor/`.

        Discovered from the filesystem with :func:`pkgutil.walk_packages`, the
        same approach :file:`tests/vendor/test_crawler_reachability_unit.py`
        uses -- this file is not about ``__all__`` reachability, but the
        discovery itself is identical, and reusing it means the enumeration
        here covers exactly what that suite calls "defined".

        """
        found = {}  # type: dict[str, Any]
        for info in pkgutil.walk_packages(self.vendor.__path__, prefix='pcapkit.vendor.'):
            if any(part.startswith('_') for part in info.name.split('.')):
                continue
            module = importlib.import_module(info.name)
            for name in getattr(module, '__all__', ()):
                obj = getattr(module, name, None)
                if self._is_crawler(obj) and obj.__module__ == info.name:
                    found[f'{info.name}.{name}'] = obj
        return found

    def test_every_crawler_resolves_to_its_existing_const_file(self) -> None:
        crawlers = self._defined_crawlers()
        # A suite that silently discovered zero crawlers would report success
        # having checked nothing -- fail loudly instead if discovery itself broke.
        self.assertGreater(len(crawlers), 0, 'no crawlers were discovered under pcapkit.vendor')

        for qualname, cls in sorted(crawlers.items()):
            with self.subTest(crawler=qualname):
                instance = cls.__new__(cls)
                dest = instance._dest_path()  # pylint: disable=protected-access

                module_file = os.path.abspath(inspect.getfile(cls))
                vendor_root = os.path.dirname(os.path.abspath(self.vendor.__file__))
                rel_path = os.path.relpath(module_file, vendor_root)

                if len(rel_path.split(os.sep)) == 2:
                    # The pre-fix formula. Every crawler that predates #732 sits
                    # at this depth and must still land exactly where it did.
                    expected = os.path.normpath(_old_algorithm(module_file))
                else:
                    # #732's nested crawlers, which the pre-fix formula cannot
                    # express -- mirrored under const/ at whatever depth they sit.
                    expected = os.path.normpath(os.path.join(
                        os.path.dirname(vendor_root), 'const', rel_path))

                self.assertEqual(dest, expected,
                                 f'{qualname} would move from its current const/ path')
                self.assertTrue(os.path.isfile(dest),
                                f'{qualname} const file does not exist at {dest}')


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class NestedCrawlerDestPathTests(unittest.TestCase):
    """A module nested two levels under ``vendor/`` (#732's ``tcp.py`` shape).

    Built entirely inside a temporary directory -- a synthetic ``vendor/`` tree
    with its own ``reg/apptype/tcp.py`` -- so nothing here touches the
    checkout's real :file:`pcapkit/vendor/` or :file:`pcapkit/const/`.

    """

    if TYPE_CHECKING:
        vendor: 'Any'
        Vendor: 'Any'

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

        import pcapkit
        import pcapkit.vendor as vendor
        import pcapkit.vendor.default as default
        from pcapkit.utilities.exceptions import VendorPathNotFound

        resolved = pathlib.Path(pcapkit.__file__).resolve()
        if ROOT not in resolved.parents:
            self.skipTest(f'pcapkit was imported from {resolved}, which is outside {ROOT}; '
                          f'install this checkout with `pip install -e .`, or set PYTHONPATH to '
                          f'it, to run this suite against it')

        self.vendor = vendor
        self.Vendor = default.Vendor
        self.default = default
        self.VendorPathNotFound = VendorPathNotFound

        self._tempdir = tempfile.TemporaryDirectory(prefix='pcapkit-vendor-nested-test-')
        self.addCleanup(self._tempdir.cleanup)

    def _build_nested_crawler(self) -> 'tuple[Any, str, str, str]':
        """Build a ``Vendor`` subclass whose file sits two levels under a
        synthetic ``vendor/`` root, mirroring #732's
        ``vendor/reg/apptype/tcp.py`` layout.

        Returns:
            A 4-tuple of ``(instance, module_file, expected_dest,
            fake_vendor_file)``.

        """
        tmp_path = pathlib.Path(self._tempdir.name)
        vendor_dir = tmp_path / 'vendor'
        module_dir = vendor_dir / 'reg' / 'apptype'
        module_dir.mkdir(parents=True)
        module_file = module_dir / 'tcp.py'
        module_file.write_text(textwrap.dedent('''\
            from pcapkit.vendor.default import Vendor


            class TCP(Vendor):
                """Stub nested crawler, for #732 path-derivation tests only."""
        '''), encoding='utf-8')

        module_name = f'_pcapkit_vendor_nested_test_tcp_{id(self)}'
        spec = importlib.util.spec_from_file_location(module_name, module_file)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        # inspect.getfile(cls) looks the defining module up in sys.modules, so
        # it has to be registered there before (or while) it executes.
        sys.modules[module_name] = module
        self.addCleanup(sys.modules.pop, module_name, None)
        spec.loader.exec_module(module)

        instance = module.TCP.__new__(module.TCP)
        expected_dest = str(tmp_path / 'const' / 'reg' / 'apptype' / 'tcp.py')
        fake_vendor_file = str(vendor_dir / '__init__.py')
        return instance, str(module_file), expected_dest, fake_vendor_file

    def test_nested_module_resolves_under_const(self) -> None:
        instance, _module_file, expected_dest, fake_vendor_file = self._build_nested_crawler()

        with mock.patch.object(self.vendor, '__file__', fake_vendor_file):
            dest = instance._dest_path()  # pylint: disable=protected-access

        self.assertEqual(dest, expected_dest,
                         'a module nested under vendor/reg/apptype/ must land at the mirrored '
                         'const/reg/apptype/ path, not be flattened into const/apptype/ and not '
                         'dropped inside vendor/const/apptype/')

    def test_module_outside_vendor_root_raises_instead_of_self_truncating(self) -> None:
        # The destructive case a reviewer caught: const/ and vendor/ are
        # siblings at equal depth, so for a module that is NOT under
        # vendor_root, os.path.relpath(module, vendor_root)'s leading '..'
        # segments cancel out exactly against const_root -- reproducing
        # module_file itself. Vendor.__init__ then opens that with 'w',
        # silently truncating the crawler's own source instead of raising.
        # Reachable in practice because every crawler ends
        # sys.exit(SomeCrawler()), so running one from a second checkout
        # resolves pcapkit.vendor from a different tree than sys.argv[0].
        instance, module_file, _expected_dest, _fake_vendor_file = self._build_nested_crawler()

        # vendor_root is patched to a tree that shares no ancestry with
        # module_file beyond the filesystem root, so the escape is genuine
        # rather than an accidental partial overlap.
        unrelated = tempfile.TemporaryDirectory(prefix='pcapkit-vendor-unrelated-root-')
        self.addCleanup(unrelated.cleanup)
        fake_vendor_file = os.path.join(unrelated.name, 'vendor', '__init__.py')

        with mock.patch.object(self.vendor, '__file__', fake_vendor_file):
            with self.assertRaises(self.VendorPathNotFound) as ctx:
                instance._dest_path()  # pylint: disable=protected-access

        # And the destructive half, pinned directly: the exception carries the
        # module's own path rather than the method having quietly returned it
        # as a "destination" to open with 'w'.
        self.assertIn(module_file, str(ctx.exception))

    def test_old_algorithm_would_have_written_inside_vendor(self) -> None:
        # Independent evidence that the reverted hunk is genuinely wrong here,
        # not only that Vendor._dest_path does not exist yet on the pre-fix
        # code (see the AttributeError captured in the PR description). This
        # runs the pre-fix formula itself, copied verbatim into
        # _old_algorithm, against the very same synthetic paths this class
        # uses -- and it lands inside vendor/, exactly as the hand trace in
        # the issue predicts.
        _instance, module_file, expected_dest, _fake_vendor_file = self._build_nested_crawler()

        old_result = os.path.normpath(_old_algorithm(module_file))
        expected_dest = os.path.normpath(expected_dest)

        self.assertNotEqual(old_result, expected_dest,
                            'the old algorithm was expected to disagree with the fixed one for '
                            'a nested module -- if it now agrees, the trace this test pins is '
                            'stale and needs re-deriving')
        self.assertIn(os.path.join('vendor', 'const'), old_result,
                     f'expected the old algorithm to land inside vendor/const/, got {old_result}')


if __name__ == '__main__':
    unittest.main()
