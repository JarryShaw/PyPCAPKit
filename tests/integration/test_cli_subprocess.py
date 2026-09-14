# -*- coding: utf-8 -*-
"""End-to-end runs of the command line tool.

:file:`tests/cli/test_main.py` exercises :func:`pcapkit.__main__.main` with the
extractor replaced by a stub, so it checks the argument wiring and nothing else.
This module runs the real thing in a subprocess -- the same entry point the
``pcapkit-cli`` console script installs -- against a real capture, and asserts on
the exit status, what it printed, and the report it left behind.

Every run is given a temporary working directory, so a report written to a
relative path could not touch the repository even if one of these grew a bug.

"""
from __future__ import annotations

import json
import pathlib
import subprocess  # nosec: B404
import sys
import unittest

from tests._support import sample_path
from tests.integration._helpers import HAS_EMOJI, HAS_RUNTIME, EndToEndTestCase

#: How long a single CLI run is allowed to take. The captures used here are two
#: to six frames, so this is a hang guard rather than a budget.
TIMEOUT = 120

#: Path of the installed console script, if it is on this interpreter's path.
CLI_SCRIPT = pathlib.Path(sys.executable).with_name('pcapkit-cli')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_EMOJI, "the cli extra's 'emoji' dependency is not installed")
class CommandLineTests(EndToEndTestCase):
    """``python -m pcapkit``, i.e. ``pcapkit.__main__:main``."""

    def run_cli(self, *args: 'str', expect: 'int | None' = 0) -> 'subprocess.CompletedProcess[str]':
        """Run the CLI in this test's temporary directory."""
        completed = subprocess.run(  # nosec: B603
            [sys.executable, '-m', 'pcapkit', *args],
            cwd=str(self.tmp_path), capture_output=True, text=True,
            timeout=TIMEOUT, check=False,
        )
        if expect is not None:
            self.assertEqual(completed.returncode, expect,
                             f'unexpected exit status; stderr was:\n{completed.stderr}')
        return completed

    def test_version_flag_reports_the_installed_version(self) -> None:
        import pcapkit

        completed = self.run_cli('-V')

        self.assertEqual(completed.stdout.strip(), pcapkit.__version__)

    def test_json_report_is_written_and_every_chain_is_printed(self) -> None:
        completed = self.run_cli(sample_path('in.pcap'), '-o', 'report', '-j', '-a', '-v')

        report = self.tmp_path / 'report.json'
        self.assertTrue(report.is_file())
        with report.open(encoding='utf-8') as stream:
            self.assertEqual(list(json.load(stream)), [
                'Global Header', 'Frame 1', 'Frame 2', 'Frame 3',
                'Frame 4', 'Frame 5', 'Frame 6',
            ])

        self.assertIn(sample_path('in.pcap'), completed.stdout)
        self.assertIn('Frame   1: Ethernet:IPv6:IPv6_ICMP', completed.stdout)
        self.assertIn('Frame   6: Ethernet:IPv4:UDP:Raw', completed.stdout)
        # ``-o report`` is relative, and the run happens in the temporary
        # directory, so the name the tool reports is relative too.
        self.assertIn("Report file stored in 'report.json'", completed.stdout)

    def test_tree_report_is_written_without_verbose_output(self) -> None:
        completed = self.run_cli(sample_path('arp.pcap'), '-o', 'report', '-t', '-a')

        report = self.tmp_path / 'report.txt'
        self.assertTrue(report.is_file())
        self.assertIn('Frame 2', report.read_text(encoding='utf-8'))
        self.assertEqual(completed.stdout, '')

    def test_plist_report_is_written(self) -> None:
        completed = self.run_cli(sample_path('arp.pcap'), '-o', 'report', '-p', '-a')

        report = self.tmp_path / 'report.plist'
        self.assertTrue(report.is_file())
        self.assertTrue(report.read_text(encoding='utf-8').startswith('<?xml'))
        self.assertEqual(completed.returncode, 0)

    def test_format_option_is_accepted_by_name(self) -> None:
        self.run_cli(sample_path('arp.pcap'), '-o', 'named', '-f', 'json', '-a')

        self.assertTrue((self.tmp_path / 'named.json').is_file())

    def test_files_flag_writes_a_directory_of_reports(self) -> None:
        completed = self.run_cli(sample_path('arp.pcap'), '-o', 'frames', '-j', '-F', '-v')

        frames = self.tmp_path / 'frames'
        self.assertTrue(frames.is_dir())
        self.assertEqual(sorted(entry.name.split('.', 1)[0] for entry in frames.iterdir()),
                         ['Frame 1', 'Frame 2', 'Global Header'])
        self.assertIn('Report files stored in', completed.stdout)

    def test_engine_option_selects_an_alternative_engine(self) -> None:
        self.run_cli(sample_path('in.pcap'), '-o', 'report', '-t', '-a', '-E', 'default')

        self.assertTrue((self.tmp_path / 'report.txt').is_file())

    def test_missing_capture_fails_and_names_the_path(self) -> None:
        missing = str(self.tmp_path / 'absent.pcap')
        completed = self.run_cli(missing, '-o', 'report', '-j', expect=None)

        self.assertNotEqual(completed.returncode, 0)
        self.assertIn('absent.pcap', completed.stderr)
        self.assertFalse((self.tmp_path / 'report.json').exists())

    def test_no_arguments_fails_with_the_usage_message(self) -> None:
        completed = self.run_cli(expect=2)

        self.assertIn('pcapkit-cli', completed.stderr)
        self.assertIn('input-file-name', completed.stderr)

    def test_unknown_option_fails_with_the_usage_message(self) -> None:
        completed = self.run_cli('--no-such-option', expect=2)

        self.assertIn('usage: pcapkit-cli', completed.stderr)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
@unittest.skipUnless(HAS_EMOJI, "the cli extra's 'emoji' dependency is not installed")
@unittest.skipUnless(CLI_SCRIPT.is_file(), 'pcapkit-cli console script is not installed')
class ConsoleScriptTests(EndToEndTestCase):
    """The installed ``pcapkit-cli`` script, rather than ``python -m pcapkit``."""

    def test_console_script_writes_the_same_report(self) -> None:
        completed = subprocess.run(  # nosec: B603
            [str(CLI_SCRIPT), sample_path('arp.pcap'), '-o', 'report', '-j', '-a'],
            cwd=str(self.tmp_path), capture_output=True, text=True,
            timeout=TIMEOUT, check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = self.tmp_path / 'report.json'
        self.assertTrue(report.is_file())
        with report.open(encoding='utf-8') as stream:
            self.assertEqual(list(json.load(stream)), ['Global Header', 'Frame 1', 'Frame 2'])


if __name__ == '__main__':
    unittest.main()
