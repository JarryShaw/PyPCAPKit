# -*- coding: utf-8 -*-
"""The compatibility shims in :mod:`pcapkit.utilities.compat`.

Every name that module exports has two implementations: the one the running
interpreter provides, and a fallback for the oldest interpreter the package
supports. Only one of the two can run on any given interpreter, so the only way
to test the other is to lie to the module about which interpreter it is on --
:meth:`CompatTests.load_compat_as_python35` executes the file a second time with
:data:`sys.version_info` faked to ``(3, 5)``.

That lie is not free, and containing its cost is most of what this module is
about. A fake version is process-global for as long as it is installed, so *any*
module first imported while it is in place memoises the false value -- and
restoring :data:`sys.version_info` afterwards does not undo a memoisation that
has already happened. Issue #687 is the bill: ``aenum/_common.py`` caches
``pyver = sys.version_info[:2]`` at import time, the ``< 3.11`` branch of
:file:`pcapkit/utilities/compat.py` does ``from aenum import StrEnum``, and on
Python 3.11 and later nothing this file imports has pulled :mod:`aenum` in already
-- the branch the *real* interpreter takes is ``from enum import StrEnum`` -- so the
faked load performs the first ``import aenum`` of the process. Every
:mod:`aenum` enumeration built afterwards -- including
``pcapkit/const/reg/apptype.py:26``'s ``TransportProtocol`` -- then took the
``pyver < PY3_6`` path in ``aenum/_enum.py`` and died with ``AttributeError:
'TransportProtocol' object has no attribute '__set_name__'``, so a later
``import pcapkit`` failed outright.

Hence the two guards here, neither of which is about the shims themselves:

#. :data:`WARM_BEFORE_FAKING` is imported *before* the fake goes in, so the
   memoised value is the true one, and
   :meth:`CompatTests.load_compat_as_python35` **asserts** that nothing at all
   was first-imported under the fake -- the ordering is checked rather than
   assumed.
#. :meth:`CompatTests.assert_aenum_is_not_poisoned` runs as a cleanup on every
   test in this file, so the invariant is re-checked after each one rather than
   only where it is broken.

One honest limitation, because it decides where the regression is actually caught.
Both guards are **vacuous under a normal** :program:`pytest` **run**, and not by
accident: :func:`tests.conftest.pytest_sessionstart` imports :mod:`pcapkit` before
the first test, which imports :mod:`aenum` under the true version, so there is no
cold cache left for the fake to poison. Measured -- with
:data:`WARM_BEFORE_FAKING` emptied, ``pytest -q tests/utilities/test_compat.py``
still reports ``5 passed``, while ``python -m unittest tests.utilities.test_compat``
reports ``FAILED (failures=5)``. So the route that regresses is the stdlib
:mod:`unittest` runner, ``pytest --noconftest``, or a bare script, and
:class:`tests.project.test_module_isolation.UnmaskedOrderTests` is what runs one of
those in CI on this file's behalf.

"""
from __future__ import annotations

import decimal
import enum
import importlib
import sys
import unittest
from unittest import mock

from tests._support import load_module, purge_modules

# NOTE: :mod:`aenum` is deliberately *not* imported at module scope, however
# convenient that would be for the assertions below. A module-level import would
# warm the cache issue #687 is about as a side effect of this file being
# collected, which is the fix -- so it would also make the fix impossible to
# switch off and the regression test impossible to fail. The warming is done by
# :data:`WARM_BEFORE_FAKING` alone, where it is visible and named, and the
# assertions reach :mod:`aenum` through :data:`sys.modules` instead.

#: Modules to import before :data:`sys.version_info` is faked, so that whatever
#: they memoise about the interpreter at import time is the *real* answer.
#:
#: :mod:`aenum` is the one that bit, and it bit hard enough to be worth spelling
#: out. ``aenum/_common.py`` caches ``pyver = sys.version_info[:2]`` at import
#: time; every other module of the package then takes a **copy** of that value
#: through ``from ._common import *``. With the copy reading ``(3, 5)``,
#: ``aenum/_enum.py`` believes the interpreter predates
#: :meth:`~object.__set_name__` and calls it on every member of every enumeration
#: built from then on. See issue #687, and note that this is also why *reloading*
#: ``aenum._common`` is not a fix: it repairs ``aenum._common.pyver`` and leaves
#: ``aenum._enum.pyver``, the copy that decides the branch, still reading
#: ``(3, 5)``. Measured on CPython 3.14.7 with ``aenum`` 3.1.17, and structural
#: rather than version-specific: the copy is made by ``from ._common import *`` at
#: the top of every one of :mod:`aenum`'s own modules.
#:
#: The rest are here because the faked branches import them too. Whether each one
#: memoises anything version-dependent is deliberately *not* the question: the
#: invariant :meth:`CompatTests.load_compat_as_python35` asserts is that nothing
#: whatever is first-imported under the fake, which needs no judgement about
#: which third-party caches are dangerous. A future interpreter or :mod:`aenum`
#: release that pulls in one more module fails that assertion here, at the line
#: that caused it, instead of poisoning something three directories away.
WARM_BEFORE_FAKING = ('aenum', 'decimal', 'threading', 'typing', 'typing_extensions')

#: Prefix of the names the loaders themselves write, which are excluded from the
#: "nothing was imported under the fake" check. :func:`tests._support.load_module`
#: binds the module it executes and a stub package per parent of its name, and
#: those writes are the loader's own -- :func:`tests._support.restore_modules_after`
#: already owes them (issue #674).
#:
#: Excluding them is safe for a reason that does not extend to the third-party
#: modules this file *does* check, and the distinction is the point. Four
#: :mod:`pcapkit` modules do memoise the interpreter version at import time in the
#: same shape :mod:`aenum` does -- ``py37``/``py38`` in
#: :mod:`pcapkit.protocols.misc.pcap.frame`, :mod:`pcapkit.protocols.misc.pcapng`,
#: :mod:`pcapkit.protocols.link.ethernet` and :mod:`pcapkit.protocols.link.arp`.
#: None of them is reachable from the branches faked here, and if one became
#: reachable it would still be harmless: the region is purged and restored around
#: every test, so the next import recomputes the value from source. A third-party
#: module is never purged, which is exactly why its cache is permanent and why the
#: assertion is aimed there.
OWN_MODULE_PREFIX = 'pcapkit'


def aenum_pyver_readings() -> 'dict[str, tuple[int, ...]]':
    """``pyver`` as every imported :mod:`aenum` module currently sees it.

    Swept out of :data:`sys.modules` rather than named module by module, because
    ``pyver`` is not one value: ``aenum/_common.py`` computes it, and every other
    module of the package takes a **copy** through ``from ._common import *``.
    The copies can disagree with the original -- reloading ``aenum._common``
    repairs it and leaves all of them -- and it is ``aenum._enum``'s copy that
    ``aenum/_enum.py:1640`` branches on when it decides whether to call
    :meth:`~object.__set_name__` by hand. Sweeping covers ``_py3``, ``_tuple``
    and ``_constant`` too, without this file having to keep a list of which of
    :mod:`aenum`'s private modules hold one.

    Returns:
        Each :mod:`aenum` module that has a tuple ``pyver``, mapped to its value.
        Empty when :mod:`aenum` has not been imported at all, which is a real
        state under the stdlib :mod:`unittest` runner: nothing has cached
        anything yet, so there is nothing to be wrong.

    """
    return {name: module.pyver
            for name, module in sorted(sys.modules.items())
            if (name == 'aenum' or name.startswith('aenum.'))
            and isinstance(getattr(module, 'pyver', None), tuple)}


class CompatTests(unittest.TestCase):
    def setUp(self) -> None:
        # Registered before anything else, and deliberately first: cleanups run
        # last-in-first-out, so this one runs *after* the module-table restore
        # that ``load_module`` arranges below and after the test body however it
        # ended -- including when it ended by raising. It is a sweep of a handful
        # of module attributes, so paying it on the tests that fake nothing costs
        # nothing and covers the case where a future test in this file learns to
        # fake a version without going through ``load_compat_as_python35``.
        self.addCleanup(self.assert_aenum_is_not_poisoned)

        purge_modules(['pcapkit'])
        self.compat = load_module('pcapkit.utilities.compat', 'pcapkit/utilities/compat.py')

    def assert_aenum_is_not_poisoned(self) -> None:
        """:mod:`aenum` still believes it is on the interpreter it is on.

        The invariant issue #687 broke, checked across every reading
        :func:`aenum_pyver_readings` can find rather than in one place, for the
        reason that function gives: the value is copied into each of
        :mod:`aenum`'s modules at import time and they can disagree.

        Checked here, immediately, rather than left to show up as the symptom,
        because the symptom is unrecoverable and lands somewhere else. Nothing
        this file can do afterwards puts a memoised value back, so the useful
        moment to notice is the test that caused it -- not the ten tests of
        :mod:`tests.project.test_public_api` that failed on it three directories
        away.

        """
        real = sys.version_info[:2]
        wrong = {name: value for name, value in aenum_pyver_readings().items()
                 if value != real}
        self.assertEqual(
            wrong, {},
            f'{sorted(wrong)} read pyver as {sorted(set(wrong.values()))} rather than '
            f'{real!r} -- aenum was first imported while this file had sys.version_info '
            f'faked, so its import-time version cache is now permanently wrong and every '
            f'aenum enumeration built from here on takes the pre-3.6 __set_name__ path '
            f'and raises AttributeError. Nothing undoes this: restoring sys.version_info '
            f'does not un-memoise a value. See issue #687 and WARM_BEFORE_FAKING.')

    def load_compat_as_python35(self, module_name: str) -> 'object':
        """Execute :file:`pcapkit/utilities/compat.py` as if on Python 3.5.

        Two things have to hold for that to be safe, and the second is the whole
        of issue #687.

        The interpreter has to *look* like 3.5 while the module body runs, which
        is what the :func:`~unittest.mock.patch.object` here does. And nothing may
        be imported for the first time while it looks that way, because an
        import-time cache of the faked value is not something restoring
        :data:`sys.version_info` can undo -- the value is already memoised inside
        a module this suite does not own.

        So the imports the faked branches need are done first, under the true
        version, and then the window is *measured*: any name that appears in
        :data:`sys.modules` while the fake is installed is a name whose
        import-time view of the interpreter is now wrong, and the assertion below
        says so. That is what turns "import :mod:`aenum` early and hope the
        ordering holds" into an ordering that is checked. Names under
        :data:`OWN_MODULE_PREFIX` are excluded: those are the loader's own writes,
        already owed back by :func:`tests._support.restore_modules_after`.

        Args:
            module_name: Dotted name to execute the file under. Must not be the
                name the real module holds, or the 3.5-flavoured module would be
                bound over it.

        Returns:
            The executed module, with every ``< 3.6`` fallback in place of the
            implementation this interpreter would otherwise have supplied.

        """
        for name in WARM_BEFORE_FAKING:
            importlib.import_module(name)

        before = frozenset(sys.modules)
        with mock.patch.object(sys, 'version_info', (3, 5)):
            compat = load_module(module_name, 'pcapkit/utilities/compat.py')

        leaked = sorted(
            name for name in set(sys.modules) - before
            if not (name == OWN_MODULE_PREFIX or name.startswith(OWN_MODULE_PREFIX + '.'))
        )
        self.assertEqual(
            leaked, [],
            f'{leaked} were imported for the first time while sys.version_info was '
            f'faked to (3, 5), so whatever any of them memoised about the interpreter '
            f'at import time is now wrong for the rest of the process -- and restoring '
            f'sys.version_info does not undo it. Add them to WARM_BEFORE_FAKING so '
            f'they are imported under the real version first. See issue #687.')
        return compat

    def test_cached_property_only_computes_once(self) -> None:
        class Demo:
            def __init__(self) -> None:
                self.calls = 0

            @self.compat.cached_property
            def value(self) -> int:
                self.calls += 1
                return 42

        demo = Demo()
        self.assertEqual(demo.value, 42)
        self.assertEqual(demo.value, 42)
        self.assertEqual(demo.calls, 1)

    def test_localcontext_applies_keyword_overrides(self) -> None:
        original_prec = decimal.getcontext().prec
        with self.compat.localcontext(prec=7) as ctx:
            self.assertEqual(ctx.prec, 7)
            self.assertEqual(decimal.getcontext().prec, 7)
        self.assertEqual(decimal.getcontext().prec, original_prec)

    def test_show_flag_values_returns_individual_bits(self) -> None:
        class DemoFlag(enum.IntFlag):
            READ = 1
            WRITE = 2
            EXEC = 4

        self.assertEqual(self.compat.show_flag_values(DemoFlag.READ | DemoFlag.EXEC), [1, 4])

    def test_faking_the_version_leaves_aenum_reading_the_real_one(self) -> None:
        """The regression test for issue #687.

        Named rather than folded into
        :meth:`test_python35_fallback_implementations`, because the invariant it
        pins has nothing to do with the shims: it is about what faking a version
        around a real ``import`` costs whatever else is in the process.

        Self-contained on purpose: it installs the fake itself rather than relying
        on :meth:`test_python35_fallback_implementations` having run first. Under
        :mod:`unittest` a class's methods run in alphabetical order and under
        :program:`pytest` in definition order, so which of the two goes first is a
        property of their names and their position in this file -- neither of
        which is a thing a regression test should rest on. A check that only fails
        when it happens to run second is a check that a rename switches off.

        The closing lines are the symptom rather than a proxy for it. Building
        an :class:`aenum.IntFlag` subclass is exactly what
        ``pcapkit/const/reg/apptype.py:26`` does, and it is the statement that
        raised ``AttributeError: 'TransportProtocol' object has no attribute
        '__set_name__'`` for ten tests of :mod:`tests.project.test_public_api`
        when this file ran before them under :mod:`unittest`. Asserting on it
        here costs two lines and no ``import pcapkit``, which keeps this module in
        the unit tier (see :mod:`tests._tiers`).

        """
        purge_modules(['pcapkit.utilities.compat_py35_probe'])
        self.load_compat_as_python35('pcapkit.utilities.compat_py35_probe')

        # Not vacuous: the branch just executed did ``from aenum import StrEnum``,
        # so aenum is in sys.modules by now whether or not the warm-up put it
        # there. An empty sweep would mean this test had stopped checking
        # anything, which is worth failing on rather than passing quietly.
        readings = aenum_pyver_readings()
        self.assertNotEqual(
            readings, {},
            'no aenum module reported a pyver, so this test checked nothing -- the '
            '< 3.11 branch of compat.py is supposed to have imported aenum (#687)')
        self.assertEqual(sorted(set(readings.values())), [sys.version_info[:2]])

        aenum = importlib.import_module('aenum')

        class TransportProtocolLike(aenum.IntFlag):
            TCP = 6

        self.assertEqual(TransportProtocolLike.TCP.value, 6)

    def test_python35_fallback_implementations(self) -> None:
        purge_modules(['pcapkit.utilities.compat_py35'])
        compat = self.load_compat_as_python35('pcapkit.utilities.compat_py35')

        self.assertTrue(issubclass(compat.ModuleNotFoundError, ImportError))

        class CollectionLike:
            def __len__(self): return 0
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class BrokenCollection:
            __len__ = None
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class BaseCollection:
            def __len__(self): return 0
            def __iter__(self): return iter(())
            def __contains__(self, item): return False

        class DerivedCollection(BaseCollection):
            pass

        class MissingCollection:
            def __len__(self): return 0
            def __iter__(self): return iter(())

        self.assertTrue(compat.Collection.__subclasshook__(CollectionLike))
        self.assertTrue(compat.Collection.__subclasshook__(DerivedCollection))
        self.assertEqual(compat.Collection.__subclasshook__(BrokenCollection), NotImplemented)
        self.assertEqual(compat.Collection.__subclasshook__(MissingCollection), NotImplemented)

        class Demo:
            def __init__(self) -> None:
                self.calls = 0

            @compat.cached_property
            def value(self) -> int:
                self.calls += 1
                return 10

        demo = Demo()
        self.assertEqual(demo.value, 10)
        self.assertEqual(demo.value, 10)
        self.assertEqual(demo.calls, 1)
        self.assertIs(Demo.__dict__['value'].__get__(None, Demo), Demo.__dict__['value'])
        self.assertEqual(Demo.__dict__['value'].__get__(demo, Demo), 10)

        prop = compat.cached_property(lambda self: 1)
        prop.__set_name__(Demo, 'first')
        prop.__set_name__(Demo, 'first')
        with self.assertRaises(TypeError):
            prop.__set_name__(Demo, 'second')

        class SlotDemo:
            __slots__ = ()

        prop = compat.cached_property(lambda self: 1)
        prop.__set_name__(SlotDemo, 'value')
        with self.assertRaises(TypeError):
            prop.__get__(SlotDemo(), SlotDemo)

        original_prec = decimal.getcontext().prec
        with compat.localcontext(prec=9) as ctx:
            self.assertEqual(ctx.prec, 9)
        self.assertEqual(decimal.getcontext().prec, original_prec)

        class OldFlag(enum.IntFlag):
            READ = 1
            EXEC = 4

        self.assertEqual(compat.show_flag_values(OldFlag.READ | OldFlag.EXEC), [1, 4])
        self.assertEqual(list(compat._iter_bits_lsb(0)), [])
        with self.assertRaises(ValueError):
            compat.show_flag_values(-1)


if __name__ == '__main__':
    unittest.main()
