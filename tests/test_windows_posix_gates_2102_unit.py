# -*- coding: utf-8 -*-
"""The POSIX-only stdlib the tests use is gated off on Windows (#2102).

Without the gates, a Windows run fails on :mod:`resource`, :func:`signal.alarm`
and ``chmod`` mode bits. Windows is not available here, so each case below loads or
runs the affected module with the platform faked -- ``os.name`` set to ``'nt'``,
:func:`signal.alarm` and ``SIGALRM`` removed, ``chmod`` keeping only the
read-only bit -- and checks that it collects and skips, rather than errors.

"""
from __future__ import annotations

import contextlib
import importlib.util
import os
import signal
import stat
import sys
import types
import typing
import unittest
from unittest import mock

from tests._tiers import ROOT
from tests.vendor import test_vendor_snapshot_restore_unit as vendor_cases

_MISSING = object()


@contextlib.contextmanager
def _no_alarm() -> 'typing.Iterator[None]':
    """:mod:`signal` without ``alarm`` and ``SIGALRM``, as on Windows."""
    saved = {name: getattr(signal, name, _MISSING) for name in ('alarm', 'SIGALRM')}
    for name, value in saved.items():
        if value is not _MISSING:
            delattr(signal, name)
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is not _MISSING:
                setattr(signal, name, value)


def _load(relpath: str) -> 'types.ModuleType':
    """A fresh copy of the test module at ``relpath``, executed under the caller's fakes."""
    name = f'_windows_gate_2102_{relpath.replace("/", "_")[:-3]}'
    spec = importlib.util.spec_from_file_location(name, ROOT / relpath)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


class _OSAsOnWindows:
    """:mod:`os` as a test module sees it on Windows: ``name`` and ``chmod`` only differ."""

    name = 'nt'

    def __getattr__(self, attr: str) -> object:
        return getattr(os, attr)

    @staticmethod
    def chmod(path: str, mode: int) -> None:
        os.chmod(path, 0o666 if mode & stat.S_IWRITE else 0o444)


class WindowsGateTests(unittest.TestCase):

    def assertSkipsFor2102(self, target: object) -> None:
        self.assertTrue(getattr(target, '__unittest_skip__', False), f'{target!r} does not skip')
        self.assertIn('#2102', target.__unittest_skip_why__)  # type: ignore[attr-defined]

    def test_no_eof_children_do_not_import_resource(self) -> None:
        relpath = 'tests/foundation/test_extraction_no_eof.py'
        self.assertIn('resource.setrlimit', _load(relpath).CHILD_PREAMBLE)
        with mock.patch.object(os, 'name', 'nt'):
            module = _load(relpath)
        self.assertNotIn('resource', module.CHILD_PREAMBLE)

    def test_the_cap_file_size_case_skips(self) -> None:
        with mock.patch.object(os, 'name', 'nt'):
            module = _load('tests/test_tier_guard.py')
        self.assertSkipsFor2102(
            module.PythonStubTests.test_the_capped_command_is_recorded_without_the_real_interpreter)

    def test_modules_without_signal_alarm_collect_and_skip(self) -> None:
        for relpath, gated in (('tests/test_support_helpers.py', 'TimeLimitTests'),
                               ('tests/protocols/test_option_generator_deadline_scale_1428_unit.py',
                                'GeneratorDeadlineScaleTests')):
            with self.subTest(relpath), _no_alarm():
                module = _load(relpath)
                self.assertIsNone(module._ALARM)
                self.assertSkipsFor2102(getattr(module, gated))

    @unittest.skipUnless(vendor_cases.HAS_VENDOR_DEPS, 'vendor extra not installed')
    def test_the_vendor_restore_case_keeps_its_byte_check_without_the_mode_check(self) -> None:
        case = vendor_cases.SnapshotRestoreTests(
            'test_a_failure_leaves_the_previous_file_byte_for_byte_intact')
        result = unittest.TestResult()
        with mock.patch.object(vendor_cases, 'os', _OSAsOnWindows()):
            unittest.TestSuite([case]).run(result)
        self.assertEqual(result.testsRun, 1)
        self.assertEqual([trace.splitlines()[-1] for _, trace in result.errors + result.failures], [])
