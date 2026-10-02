# -*- coding: utf-8 -*-
"""``run()`` must restore a target's const file when the target's run fails.

GitHub issue #872. Rounds 4-8 made
:meth:`~pcapkit.vendor.default.Vendor.__init__`'s own write atomic -- a
temp-file-then-:func:`os.replace` at the point of the write, with permission
matching for the replacement. The owner's ruling on that, verbatim: *"I
prefer we use contextlib over manually manage the temp file deletion based
on pure best intent (try-finally) and for atomic writing, an easier path is
simply keep a copy before running the sub-vendor and revert if anything
failed."*

That supersedes the atomic write entirely rather than adjusting it.
:meth:`~pcapkit.vendor.default.Vendor._write_atomic` no longer exists;
:meth:`Vendor.__init__`'s last line is once again a plain::

    with open(const_file, 'w') as file:
        print(context, file=file)

The protection moved up a level, to
:func:`pcapkit.vendor.__main__._snapshot_and_restore`, a
:func:`contextlib.contextmanager` that :func:`~pcapkit.vendor.__main__.run`
wraps every ``vendor()`` call in. It copies the target's existing const file
aside *before* the crawler is instantiated at all -- resolving the
destination via :meth:`~pcapkit.vendor.default.Vendor._dest_path`, a
classmethod for exactly this reason, called on the crawler *class* rather
than an instance -- and restores that copy if the crawler raises for any
reason. This is a **wider** guarantee than an atomic write at one call site:
it covers any way a crawler's own code could end up touching its const
file, not only the single ``open``/``print`` pair the base class happens to
use, and it puts the discarding exactly at the per-target boundary the
owner's earlier ruling (b) asked for.

Because the protection now lives in ``run()`` rather than inside
:meth:`Vendor.__init__`, this suite calls
:func:`pcapkit.vendor.__main__.run` -- not the crawler class directly, the
way rounds 4-8's version of this file did -- exactly as
:file:`tests/vendor/test_vendor_exit_code_unit.py` already does. Calling the
crawler class directly would exercise :meth:`Vendor.__init__` in isolation,
which is no longer where the guarantee lives.

This suite makes no network call: :class:`~pcapkit.vendor.default.Vendor`'s
``_request``, ``count``, ``context`` and ``_dest_path`` are all overridden by
a stub subclass built per test, with the destination pointed at a temporary
directory rather than the real :file:`pcapkit/const/`. ``_dest_path`` is
overridden as a ``@classmethod``, matching the base class, so
``_snapshot_and_restore`` can call it on the stub class itself before
instantiating it -- overriding it as a plain instance method would raise
``TypeError`` when called that way, which ``_snapshot_and_restore`` would
(correctly, for a crawler it genuinely cannot resolve a path for) treat as
"skip the snapshot", silently exercising the unprotected fallback instead of
what these tests are actually about.

The three permission-matching methods rounds 6-8 added
(``test_existing_permissions_survive_a_successful_write``,
``test_a_read_only_destination_is_regenerated_and_stays_read_only``,
``test_a_new_destination_gets_umask_masked_permissions``) are gone with the
code they pinned: :meth:`_write_atomic`'s mode-matching had three genuinely
different branches (existing mode preserved via :func:`os.stat`, the
``0o444``-succeeds-anyway case, and a fresh-file umask fallback), each
worth its own test. Snapshot-and-restore has no equivalent branching to
pin -- a restored file is simply the exact bytes and mode
:func:`shutil.copy2` copied out, once, for every case alike -- so keeping
three separate permutations would pin nothing that one does not already
cover, and I chose to delete them rather than repoint them at a property
that no longer varies by case.

:meth:`SnapshotRestoreTests.test_successful_run_replaces_the_previous_file_content`
is the happy-path round trip. Run against ``origin/main`` (pre-#872, no
exit-code accounting at all), it fails too --
``self.assertTrue(self.vendor_main.run(...))`` sees :data:`None`, since
pre-fix ``run()`` never returns anything -- so this is a second method the
fix changes, not only the one below.

What survives, in the new shape, is the invariant the original pin actually
encoded: a failure during or around a target's regeneration leaves the
previous const file byte-for-byte intact. That is
:meth:`SnapshotRestoreTests.test_a_failure_leaves_the_previous_file_byte_for_byte_intact`
below, still simulated by making :func:`print` raise once the destination is
open for writing -- :meth:`Vendor.__init__` still opens ``const_file``
directly (there is no temp file to redirect the write onto any more), so
this again truncates the previous content before the injected failure
fires; :func:`~pcapkit.vendor.__main__._snapshot_and_restore` is what
restores it afterwards. It asserts on the *reported* error
(:meth:`~unittest.TestCase.assertWarnsRegex` against the crawler's own
``RuntimeError`` text) rather than merely on ``run()`` returning falsy,
deliberately: a mutant that deletes the ``raise`` from
``_snapshot_and_restore``'s ``except BaseException:`` clause does not
merely misreport the failure, it makes it disappear. Because
:func:`contextlib.contextmanager`'s generated ``__exit__`` suppresses an
exception its generator catches and does not re-raise,
:meth:`Vendor.__init__`'s ``RuntimeError`` never reaches ``run()``'s own
``except Exception as error:`` at all under that mutant -- no warning, no
stderr line, and ``run()`` returns :data:`True`. A bare
``assertFalse(run(...))`` cannot catch a return value that flips to *true*;
only asserting that the crawler's own error was actually reported can. It
also asserts the destination's mode (``0o640`` in, ``0o640`` out) alongside
its content, which is the measurement that actually justifies collapsing
rounds 6-8's three separate mode-permutation tests into one: restore
preserves mode as a side effect of :func:`shutil.copy2` plus a rename, for
every case alike, rather than needing a case-by-case check. Run against
both of :mod:`pcapkit.vendor.__main__` and :mod:`pcapkit.vendor.default`
taken from ``origin/main`` (swapping only one of the two leaves the other's
fix in place and proves nothing -- see GitHub issue #872's own round 8),
this fails on the content assertion with ``'' != 'GOOD CONTENT\\n'``: the
previous content is destroyed before ``run()`` (pre-#872) ever gets a
chance to report anything.

:meth:`SnapshotRestoreTests.test_a_keyboard_interrupt_still_restores_and_propagates`
pins ``except BaseException:`` itself, rather than the narrower
``except Exception:`` a reasonable-looking edit might reach for.
:exc:`KeyboardInterrupt` is a :exc:`BaseException` but not an
:exc:`Exception`, so it is what actually exercises the difference: under an
``except Exception:`` mutant it falls straight through
``_snapshot_and_restore``'s generator uncaught, skipping both the restore
and the backup's cleanup -- the previous content stays truncated and a
``.const.py.*.bak`` is left behind in the directory, measured directly as
``['.const.py.<random>.bak', 'const.py']``. The interrupt itself still
propagates out of ``run()`` either way, since ``run()``'s own
``except Exception:`` never caught it either; what the mutant changes is
only whether anything got restored on the way out. This is why the method
asserts three things rather than two: the exception's propagation, the
content, and the directory listing -- the first alone is silent about
exactly the defect this pins.

:meth:`SnapshotRestoreTests.test_a_read_only_destination_is_left_exactly_as_it_was`
re-measures the ``0o444`` case under the new design rather than assuming it
still behaves as rounds 6-8 documented. It does not: ``os.replace()``
(round 4-8's last step) needed write permission on the *directory*, not the
target file, so a ``0o444`` destination was still successfully regenerated.
A plain ``open(const_file, 'w')`` (this round's design) needs write
permission on the file itself, so a ``0o444`` destination now fails to
regenerate exactly as it did on `main`, before #872 -- a capability the
atomic-write approach had and this one has deliberately traded away for
simplicity, per the owner's ruling. What the new design still guarantees is
that the failure leaves the file exactly as it was, mode included, which is
what this method actually pins.

Run against ``origin/main``, this method passes -- it is a measurement, not
a regression pin. `main`'s plain ``open(const_file, 'w')`` already raised
:exc:`PermissionError` on a ``0o444`` destination *before* truncating
anything (the permission check happens before the write, not after), so the
file was already left untouched on the pre-#872 tree for this one specific
scenario; there is nothing here for the fix to have changed.

The ``0o444`` file is one traded capability; there is a second, in the
opposite direction, not covered by any method here. A writable file inside
a *non-writable directory* also regenerated on `main` -- opening an
*existing* file for writing needs write permission on the file, not on its
parent directory -- but fails under this design, because
:func:`~pcapkit.vendor.__main__._snapshot_and_restore`'s
:func:`tempfile.mkstemp` call needs write permission on the directory to
create the backup, and :meth:`Vendor.__init__`'s own ``open(const_file,
'w')`` never needed that. Measured: ``run()`` returns :data:`False` with a
:exc:`PermissionError`, and the previous content survives untouched because
``vendor()`` is never even called. This is not new relative to rounds 4-8
(``os.replace()`` needed directory write too), only relative to `main`, so
the PR now discloses two traded capabilities rather than one. See
:func:`~pcapkit.vendor.__main__._snapshot_and_restore`'s own docstring for
the asymmetry between this and the ``0o444`` case: a ``_dest_path``
resolution failure *skips* the snapshot and lets the target proceed
unprotected, while a ``mkstemp`` failure *fails* the target before
``vendor()`` is ever attempted.

"""
from __future__ import annotations

import collections
import importlib.util
import os
import stat
import tempfile
import unittest
from unittest import mock

#: Same two-dependency gate the rest of :file:`tests/vendor/` uses. Importing
#: :mod:`pcapkit.vendor.__main__` imports :mod:`pcapkit.vendor` (for its
#: ``vendor_module`` default-target-list fallback), which pulls in every
#: crawler subpackage unconditionally -- :mod:`pcapkit.vendor.default`
#: itself imports :mod:`requests` at module scope and seven crawlers import
#: :mod:`bs4` at module scope.
VENDOR_DEPS = ('requests', 'bs4')

#: Whether the crawler machinery is importable at all. Both ship in the
#: ``test`` extra (:file:`pyproject.toml`), so this should not skip in CI;
#: kept as belt-and-braces for an environment that lacks them.
HAS_VENDOR_DEPS = all(importlib.util.find_spec(name) is not None for name in VENDOR_DEPS)


@unittest.skipUnless(HAS_VENDOR_DEPS, f'vendor extra not installed ({", ".join(VENDOR_DEPS)})')
class SnapshotRestoreTests(unittest.TestCase):
    """``run()``'s snapshot-and-restore, isolated from fetch/render/discovery."""

    def setUp(self) -> None:
        """Re-resolve ``vendor_main``, ``Vendor`` and ``VendorRuntimeWarning``, fresh.

        GitHub issue #985, the same generation skew #981 pins in
        :class:`tests.test_base_class_contract.RegistrationGateTests`: a sibling
        module under :file:`tests/vendor/` (several call
        :func:`tests._support.purge_modules` on ``pcapkit``, e.g.
        :mod:`tests.vendor.test_vendor_dest_path_unit`) mints a fresh generation
        of every :mod:`pcapkit` class, and :func:`tests.conftest.restore_module_table`
        only reconciles that back under :program:`pytest` -- plain :mod:`unittest`
        loads no ``conftest`` at all. A module-level ``from pcapkit.utilities.warnings
        import VendorRuntimeWarning`` would bind whatever generation was live when
        *this module* was first imported, which under ``python -m unittest
        discover`` is before any sibling has purged anything; the crawler under
        test, instantiated through ``self.vendor_main``/``self.Vendor`` below,
        raises whatever generation is current *when the test runs*. The two can
        disagree, and :meth:`unittest.TestCase.assertWarnsRegex` tests each
        captured warning with ``isinstance(warning_instance, expected_class)``
        against the class object it was handed -- not by name, and not by identity
        either, so a genuine *subclass* of the expected class does match. That is
        no rescue here, because the two generations are not related classes at
        all: re-importing re-mints ``VendorRuntimeWarning`` *and* its
        ``BaseWarning`` base, so ``issubclass`` is false in *both* directions and
        the two MROs first converge on the builtin :exc:`UserWarning`.
        ``isinstance`` against a stale binding therefore rejects an instance of
        the fresh generation, and the assertion fails with
        "VendorRuntimeWarning not triggered" even though the warning was actually
        raised, one line earlier, on stderr -- both classes carry the same
        ``__module__`` and ``__name__``, so the message names exactly the class
        that *was* raised.

        ``vendor_main`` and ``Vendor`` were already immune to this, because they
        were resolved here in ``setUp`` rather than at module level.
        ``VendorRuntimeWarning`` was not; it joins them, resolved through
        :func:`importlib.import_module` so this always compares against the
        same generation the crawler actually raises.

        """
        import pcapkit.vendor.__main__ as vendor_main
        from pcapkit.vendor.default import Vendor

        self.vendor_main = vendor_main
        self.Vendor = Vendor
        self.VendorRuntimeWarning = importlib.import_module(
            'pcapkit.utilities.warnings').VendorRuntimeWarning
        self._tempdir = tempfile.TemporaryDirectory(prefix='pcapkit-vendor-snapshot-restore-test-')
        self.addCleanup(self._tempdir.cleanup)

    def _make_crawler(self, const_file: 'str', rendered: 'str') -> 'type':
        """A ``Vendor`` subclass with fetch, render and destination all stubbed.

        No network call and no real CSV parsing: ``_request``/``count``/
        ``context`` return canned values and ``_dest_path`` is pinned to
        ``const_file`` -- overridden as a ``@classmethod``, matching the base
        class, so :func:`~pcapkit.vendor.__main__._snapshot_and_restore` can
        call it on the class itself before this crawler is ever instantiated.

        Args:
            const_file: Where ``_dest_path`` should report the constant file
                lives.
            rendered: The fixed content ``context`` should return.

        """
        Vendor = self.Vendor

        class StubCrawler(Vendor):
            """Stub crawler for GitHub issue #872 -- no network, fixed destination."""

            def _request(self) -> 'list[str]':
                return []

            def count(self, data: 'list[str]') -> 'collections.Counter[str]':
                return collections.Counter()

            def context(self, data: 'list[str]') -> 'str':
                return rendered

            @classmethod
            def _dest_path(cls) -> 'str':
                return const_file

        return StubCrawler

    def test_successful_run_replaces_the_previous_file_content(self) -> None:
        const_file = os.path.join(self._tempdir.name, 'const.py')
        with open(const_file, 'w', encoding='utf-8') as file:
            file.write('OLD CONTENT\n')

        stub_crawler = self._make_crawler(const_file, 'NEW CONTENT')
        self.assertTrue(self.vendor_main.run(stub_crawler))

        with open(const_file, encoding='utf-8') as file:
            self.assertEqual(file.read(), 'NEW CONTENT\n')
        self.assertEqual(os.listdir(self._tempdir.name), ['const.py'],
                         'no backup file should be left behind after a successful run')

    def test_a_failure_leaves_the_previous_file_byte_for_byte_intact(self) -> None:
        const_file = os.path.join(self._tempdir.name, 'const.py')
        with open(const_file, 'w', encoding='utf-8') as file:
            file.write('GOOD CONTENT\n')
        os.chmod(const_file, 0o640)

        stub_crawler = self._make_crawler(const_file, 'NEW CONTENT')

        # side_effect is a callable, not a bare exception, deliberately:
        # run() itself calls print() -- unconditionally, to report the
        # failure on stderr -- and a bare `side_effect=RuntimeError(...)`
        # would raise there too, breaking run()'s own error reporting
        # instead of simulating a failure inside the crawler's write. Only
        # the crawler's own print(context, file=file) call -- recognisable
        # by its first argument being the rendered content -- is made to
        # raise; every other print() call (run()'s own included) passes
        # through to the real builtin.
        real_print = print

        def _raise_on_render(*args: object, **kwargs: object) -> None:
            if args and args[0] == 'NEW CONTENT':
                raise RuntimeError('simulated failure (GitHub issue #872)')
            real_print(*args, **kwargs)

        # assertWarnsRegex against the crawler's OWN error text, not merely
        # assertFalse(run(...)): a mutant that deletes the `raise` from
        # _snapshot_and_restore's `except BaseException:` still returns a
        # falsy run() -- the unguarded os.remove(backup) that then runs
        # raises FileNotFoundError instead (the backup was just renamed away
        # by os.replace), and run() reports THAT, not this test's injected
        # RuntimeError. A bare falsy check cannot tell "failed for the right
        # reason" from "failed for the wrong one"; this can.
        with mock.patch('builtins.print', side_effect=_raise_on_render):
            with self.assertWarnsRegex(self.VendorRuntimeWarning, 'simulated failure'):
                result = self.vendor_main.run(stub_crawler)
        self.assertFalse(result)

        with open(const_file, encoding='utf-8') as file:
            self.assertEqual(file.read(), 'GOOD CONTENT\n',
                             'a failure during a target\'s run must leave the previous const '
                             'file byte-for-byte untouched, not truncated or partially '
                             'overwritten')
        # The mode check, not just content: this is what actually justifies
        # collapsing rounds 6-8's three separate mode-permutation tests into
        # one -- restore preserves mode as a side effect of shutil.copy2
        # plus a rename, uniformly, rather than needing a case-by-case check.
        mode = stat.S_IMODE(os.stat(const_file).st_mode)
        self.assertEqual(mode, 0o640,
                         f'a destination that existed at 0o640 must still be 0o640 after a '
                         f'failed run, not {oct(mode)}')
        self.assertEqual(os.listdir(self._tempdir.name), ['const.py'],
                         'a failed run must not leave a backup file behind')

    def test_a_keyboard_interrupt_still_restores_and_propagates(self) -> None:
        const_file = os.path.join(self._tempdir.name, 'const.py')
        with open(const_file, 'w', encoding='utf-8') as file:
            file.write('GOOD CONTENT\n')

        stub_crawler = self._make_crawler(const_file, 'NEW CONTENT')

        real_print = print

        def _interrupt_on_render(*args: object, **kwargs: object) -> None:
            if args and args[0] == 'NEW CONTENT':
                raise KeyboardInterrupt
            real_print(*args, **kwargs)

        # except BaseException:, not except Exception:, is what this pins.
        # KeyboardInterrupt is a BaseException but not an Exception, so an
        # `except Exception:` mutant would let it fall straight through
        # _snapshot_and_restore's generator uncaught -- no os.replace(),
        # no cleanup, the truncated file and the orphaned backup both left
        # behind. run()'s own `except Exception as error:` does not catch
        # KeyboardInterrupt either (deliberately -- a signal to stop is not
        # a target failure to report and swallow), so it must still
        # propagate all the way out of run() rather than being converted
        # into a plain False return.
        with mock.patch('builtins.print', side_effect=_interrupt_on_render):
            with self.assertRaises(KeyboardInterrupt):
                self.vendor_main.run(stub_crawler)

        with open(const_file, encoding='utf-8') as file:
            self.assertEqual(file.read(), 'GOOD CONTENT\n',
                             'a KeyboardInterrupt mid-write must still leave the previous '
                             'const file byte-for-byte untouched, not truncated or '
                             'partially overwritten')
        self.assertEqual(os.listdir(self._tempdir.name), ['const.py'],
                         'a KeyboardInterrupt must not leave an orphaned backup file behind')

    def test_a_read_only_destination_is_left_exactly_as_it_was(self) -> None:
        const_file = os.path.join(self._tempdir.name, 'const.py')
        with open(const_file, 'w', encoding='utf-8') as file:
            file.write('GOOD CONTENT\n')
        os.chmod(const_file, 0o444)

        stub_crawler = self._make_crawler(const_file, 'NEW CONTENT')

        # Measured, not assumed (see the module docstring): unlike round
        # 4-8's os.replace()-based design, a plain open(const_file, 'w')
        # needs write permission on the file itself, so this still fails --
        # run() must still report that failure.
        self.assertFalse(self.vendor_main.run(stub_crawler))

        # What the new design does guarantee: the failure leaves the file
        # exactly as it was, content and mode both, even though nothing was
        # ever actually rewritten (open() raised before truncating anything).
        with open(const_file, encoding='utf-8') as file:
            self.assertEqual(file.read(), 'GOOD CONTENT\n',
                             'a 0o444 destination must survive a failed run with its '
                             'previous content untouched')
        mode = stat.S_IMODE(os.stat(const_file).st_mode)
        self.assertEqual(mode, 0o444,
                         f'a 0o444 destination must still be 0o444 after a failed run, '
                         f'not {oct(mode)}')


if __name__ == '__main__':
    unittest.main()
