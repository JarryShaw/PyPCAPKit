"""Unit tests for :meth:`pcapkit.foundation.engines.pyshark.PyShark.unsupported_reason`.

The rest of the engine is exercised end to end in
:mod:`tests.foundation.engines.test_runtime_engines`, which needs `PyShark`_ and the
generated captures. This module covers only the preflight check, which is the part
that has to give the right answer on a machine where `PyShark`_ cannot run at all --
including this one.

`PyShark`_ is refused for two independent reasons, and both are measured:

* **the interpreter** -- ``pyshark`` 0.6 builds its event loop with
  ``asyncio.get_event_loop_policy().get_event_loop()``. Run in a fresh interpreter
  with no loop, that returns a loop on 3.10 and 3.11, returns one with a
  :exc:`DeprecationWarning` on 3.12, and raises ``RuntimeError: There is no
  current event loop in thread 'MainThread'`` on 3.14. So the ceiling is
  ``(3, 14)``. Python 3.13 was not available to measure; it is expected to work,
  being on the deprecated-but-functional side of that change, and that is the only
  inferred claim here.
* **the** :program:`tshark` **binary** -- ``pyshark`` shells out to it and parses
  nothing itself.

What this host could and could not provide, stated plainly rather than left to a
silent skip: :program:`tshark` is **not** installed here, so the "missing binary"
path is exercised for real. The "binary present" path is exercised by patching
``pyshark``'s own resolver, since installing Wireshark was not an option; and the
interpreter is 3.14, so every version below the ceiling is reached by patching
:data:`sys.version_info`, which is the same technique
:mod:`tests.foundation.engines.test_pypcapfile_engine` uses.

.. _PyShark: https://kiminewt.github.io/pyshark

"""
from __future__ import annotations

import importlib.util
import sys
import unittest
from unittest import mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

HAS_PYSHARK = importlib.util.find_spec('pyshark') is not None

#: A version below the ceiling, used to reach the :program:`tshark` branch, which
#: is otherwise unreachable on the 3.14 interpreter these tests run on.
SUPPORTED_VERSION = (3, 11, 0, 'final', 0)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PySharkUnsupportedReasonTests(unittest.TestCase):
    def resolver(self, *, found: bool):
        """Install a stand-in ``pyshark.tshark.tshark`` for the duration of a block.

        A stand-in rather than :func:`unittest.mock.patch` on the real module, so
        that these tests do not need `PyShark`_ installed. That matters for the
        version cases in particular: the whole point of deciding the ceiling from
        :data:`sys.version_info` is that the answer is the same on a machine that
        has never installed ``pyshark``, and a test that could only run where it
        *is* installed would not be checking that.

        """
        import types

        message = ("TShark not found. Try adding its location to the configuration "
                   "file. Searched these paths: ['/usr/bin/tshark', '/usr/sbin/tshark']")

        def get_process_path(*args, **kwargs):
            if found:
                return '/usr/bin/tshark'
            raise Exception(message)

        module = types.ModuleType('pyshark.tshark.tshark')
        module.get_process_path = get_process_path  # type: ignore[attr-defined]
        return mock.patch.dict('sys.modules', {
            'pyshark': types.ModuleType('pyshark'),
            'pyshark.tshark': types.ModuleType('pyshark.tshark'),
            'pyshark.tshark.tshark': module,
        })

    def found_tshark(self):
        """A resolver that reports a binary it found."""
        return self.resolver(found=True)

    def missing_tshark(self):
        """A resolver that raises the way ``pyshark``'s does when it finds nothing."""
        return self.resolver(found=False)

    ##########################################################################
    # The Python ceiling.
    ##########################################################################

    def test_the_ceiling_is_the_measured_one(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        self.assertEqual(PyShark.PYTHON_CEILING, (3, 14))

    @unittest.skipUnless(HAS_PYSHARK, 'pyshark not installed')
    def test_the_reason_tracks_the_running_interpreter(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        reason = PyShark.unsupported_reason()
        if sys.version_info[:2] >= PyShark.PYTHON_CEILING:
            self.assertIsNotNone(reason)
            # the message has to name the cause; "unsupported" sends the reader
            # looking in the wrong place
            self.assertIn('asyncio', reason)  # type: ignore[arg-type]
            self.assertIn(f'{sys.version_info[0]}.{sys.version_info[1]}',
                          reason)  # type: ignore[arg-type]
        else:
            # below the ceiling the verdict is about tshark, which this host does
            # not have -- so still a reason, but a different one
            self.assertIsNotNone(reason)
            self.assertIn('tshark', reason)  # type: ignore[arg-type]

    def test_the_ceiling_is_decided_by_version_not_by_an_import(self) -> None:
        """The verdict must not depend on whether ``pyshark`` is installed.

        Otherwise the answer differs between a machine that has the package and
        one that does not, and the engine would call itself usable on 3.14 purely
        because the failing ``asyncio`` call had not been reached yet.

        """
        from pcapkit.foundation.engines.pyshark import PyShark

        for version, refused in (((3, 10), False), ((3, 11), False), ((3, 12), False),
                                 ((3, 13), False), ((3, 14), True), ((3, 15), True)):
            with self.subTest(python=version):
                with mock.patch.object(sys, 'version_info', (*version, 0, 'final', 0)):
                    with self.found_tshark():
                        reason = PyShark.unsupported_reason()
                self.assertEqual(reason is not None, refused, reason)
                if refused:
                    self.assertIn('asyncio', reason)  # type: ignore[arg-type]

    def test_the_version_reason_is_checked_before_the_binary(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        # On 3.14 the engine cannot run whatever the binary situation is, so the
        # interpreter is the reason worth reporting -- and it costs no filesystem
        # probe to decide.
        with mock.patch.object(sys, 'version_info', (3, 14, 0, 'final', 0)):
            with self.found_tshark():
                reason = PyShark.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('asyncio', reason)  # type: ignore[arg-type]
        self.assertNotIn('tshark', reason)  # type: ignore[arg-type]

    ##########################################################################
    # The tshark binary.
    ##########################################################################

    def test_a_missing_binary_is_reported_with_what_was_searched(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        with mock.patch.object(sys, 'version_info', SUPPORTED_VERSION):
            with self.missing_tshark():
                reason = PyShark.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('tshark', reason)  # type: ignore[arg-type]
        # upstream's own message lists every candidate path, which is exactly what
        # the user needs, so it is quoted rather than summarised away
        self.assertIn('Searched these paths', reason)  # type: ignore[arg-type]

    def test_a_present_binary_is_no_reason_at_all(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        with mock.patch.object(sys, 'version_info', SUPPORTED_VERSION):
            with self.found_tshark():
                self.assertIsNone(PyShark.unsupported_reason())

    @unittest.skipUnless(HAS_PYSHARK, 'pyshark not installed')
    def test_this_host_really_has_no_tshark_so_the_check_is_not_vacuous(self) -> None:
        """Exercise the failing path through ``pyshark``'s resolver, unpatched.

        The other tests patch ``get_process_path``, which proves the branch is
        wired up but not that the real resolver ever says no. This one calls it,
        and is skipped only if :program:`tshark` turns out to be installed after
        all -- in which case the complementary
        :meth:`test_a_present_binary_is_no_reason_at_all` is the real check.

        """
        import shutil

        from pcapkit.foundation.engines.pyshark import PyShark

        if shutil.which('tshark') is not None:
            self.skipTest('tshark is installed on this host')

        with mock.patch.object(sys, 'version_info', SUPPORTED_VERSION):
            reason = PyShark.unsupported_reason()

        self.assertIsNotNone(reason)
        self.assertIn('tshark', reason)  # type: ignore[arg-type]

    def test_an_absent_pyshark_is_left_to_the_import_test(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        # Reporting "not installed" here as well would produce two warnings for
        # one problem: ``Extractor.import_test`` already says it, in its own words.
        with mock.patch.object(sys, 'version_info', SUPPORTED_VERSION):
            with mock.patch.dict('sys.modules', {'pyshark.tshark.tshark': None}):
                self.assertIsNone(PyShark.unsupported_reason())


if __name__ == '__main__':
    unittest.main()
