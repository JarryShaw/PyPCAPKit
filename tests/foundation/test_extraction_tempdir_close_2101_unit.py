# -*- coding: utf-8 -*-
"""The patched-run ``ExtractorTests`` close their capture before its directory goes (#2101).

Windows cannot delete a file that is still open, so a
:class:`tempfile.TemporaryDirectory` whose capture is still held by
``Extractor._ifile`` fails to clean up with ``WinError 32``. Linux deletes it
regardless, so the cases below are re-run here with the directory's ``cleanup``
refusing, as Windows does, while any descriptor of this process still points
into the directory.

"""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from tests.foundation import test_extraction

#: The ``ExtractorTests`` cases that failed on the first Windows run (#2101).
CASES = (
    'test_a_dict_capable_trace_format_is_left_alone',
    'test_an_engine_with_real_frames_keeps_the_pcap_trace_format',
    'test_auto_mode_call_raises_the_class_the_docstring_names',
    'test_constructor_initialises_without_running_when_patched',
    'test_pcap_trace_format_is_replaced_only_for_dict_frame_engines',
    'test_warns_bullet_for_pcap_output_names_the_engines_its_guard_warns_for',
    'test_warns_bullet_for_pcap_trace_output_names_the_engines_its_guard_warns_for',
)

_CLEANUP = tempfile.TemporaryDirectory.cleanup


def _open_under(directory: str) -> 'list[str]':
    """Paths under ``directory`` that a descriptor of this process holds open."""
    root = os.path.realpath(directory) + os.sep
    held = []
    for fd in os.listdir('/proc/self/fd'):
        try:
            target = os.readlink(f'/proc/self/fd/{fd}')
        except OSError:
            continue
        if target.startswith(root):
            held.append(target)
    return held


def _cleanup_as_on_windows(self: tempfile.TemporaryDirectory) -> None:
    held = _open_under(self.name)
    if held:
        raise PermissionError(f'[WinError 32] still open at cleanup: {held}')
    _CLEANUP(self)


@unittest.skipUnless(os.path.isdir('/proc/self/fd'), 'needs /proc/self/fd to see open files')
@unittest.skipUnless(test_extraction.HAS_RUNTIME, 'runtime dependencies not installed')
class TemporaryDirectoryOutlivesNoOpenCapture(unittest.TestCase):

    maxDiff = None

    def test_the_cases_close_the_capture_inside_the_directory(self) -> None:
        suite = unittest.TestSuite(test_extraction.ExtractorTests(name) for name in CASES)
        result = unittest.TestResult()
        with mock.patch.object(tempfile.TemporaryDirectory, 'cleanup', _cleanup_as_on_windows):
            suite.run(result)
        self.assertEqual(result.testsRun, len(CASES))
        problems = [f'{case.id()}: {trace.splitlines()[-1]}'
                    for case, trace in result.errors + result.failures]
        self.assertEqual(problems, [])
