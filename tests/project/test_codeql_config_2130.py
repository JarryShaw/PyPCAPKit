# -*- coding: utf-8 -*-
"""#2130: CodeQL scans everything but :file:`tests`.

``py/clear-text-logging-sensitive-data`` and
``py/clear-text-storage-sensitive-data`` call a value secret from its name
alone. The tests that build a pcapng Decryption Secrets Block call its bytes
``secrets``, and those bytes reached ``logger`` calls in :mod:`pcapkit`, as a
capture's stream, its name, or its magic number, and a buffer file's write.
Each dismissal was lost when a
pull request moved the line the alert named. Python is not built, so a path the
config ignores is not extracted and cannot be a flow source.

* :class:`TestTheInitStep` checks ``Initialize CodeQL`` in
  :file:`codeql-analysis.yml` reads :file:`.github/codeql/codeql-config.yml`
  and nothing else.
* :class:`TestTheConfig` checks the config ignores :file:`tests` and sets
  nothing else: every query runs, over every other path.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._tiers import ROOT
from tests._workflows import load, loads

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads a workflow and the CodeQL config, a question about the tree.
__tier__ = 'LATEST'

NAME = 'codeql-analysis.yml'
CONFIG = '.github/codeql/codeql-config.yml'


def config() -> 'dict[str, Any]':
    return loads((ROOT / CONFIG).read_text(encoding='utf-8'))


class TestTheInitStep(unittest.TestCase):
    """``Initialize CodeQL`` names the config file."""

    def test_it_reads_the_config(self) -> None:
        [step] = [entry for entry in load(NAME)['jobs']['analyze']['steps']
                  if entry.get('name') == 'Initialize CodeQL']
        self.assertEqual(step.get('with'), {'config-file': f'./{CONFIG}'})
        self.assertTrue((ROOT / CONFIG).is_file())

    def test_no_other_step_passes_a_config(self) -> None:
        """An inline ``config`` would take precedence over the file."""
        for entry in load(NAME)['jobs']['analyze']['steps']:
            with self.subTest(step=entry.get('name')):
                self.assertNotIn('config', entry.get('with') or {})
                if entry.get('name') != 'Initialize CodeQL':
                    self.assertNotIn('config-file', entry.get('with') or {})


class TestTheConfig(unittest.TestCase):
    """:file:`tests` left out, and no other filter on the scan."""

    def test_only_the_tests_are_ignored(self) -> None:
        self.assertEqual(config()['paths-ignore'], ['tests'])

    def test_every_query_still_runs(self) -> None:
        spec = config()
        for key in ('query-filters', 'paths', 'disable-default-queries', 'queries', 'packs'):
            with self.subTest(key=key):
                self.assertNotIn(key, spec)
        self.assertEqual(sorted(spec), ['name', 'paths-ignore'])


if __name__ == '__main__':
    unittest.main()
