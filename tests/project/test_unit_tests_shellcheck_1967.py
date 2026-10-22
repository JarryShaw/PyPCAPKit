# -*- coding: utf-8 -*-
"""#1967: every ``run:`` block of unit-tests.yml passes shellcheck.

Lint's ``actionlint`` step runs shellcheck over every workflow's ``run:`` blocks,
and a finding fails Lint. Step 5 of #1967 fixed unit-tests.yml's findings at the
root, and this test keeps it clean without waiting for a Lint run: it checks each
``run:`` block of a ``bash`` or ``sh`` step as actionlint does: each
``${{ ... }}`` expression replaced by underscores of the same length, the
shell's ``set -e`` line above it, and the checks actionlint disables left out.
It skips where no ``shellcheck`` is on ``PATH``.

"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec: B404
import unittest
from typing import TYPE_CHECKING

from tests import _workflows

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): reads the workflow files, a question about the tree.
__tier__ = 'LATEST'

WORKFLOW = 'unit-tests.yml'
#: The checks actionlint 1.7.12 passes to ``shellcheck -e`` (rhysd/actionlint's
#: ``rule_shellcheck.go``): each misfires on a ``run:`` block taken alone.
EXCLUDED = 'SC1091,SC2194,SC2050,SC2153,SC2154,SC2157,SC2043'
#: The line actionlint puts above each script, as GitHub runs that shell.
SETUP = {'bash': 'set -eo pipefail', 'sh': 'set -e'}
#: A GitHub expression, which actionlint replaces before running shellcheck.
EXPRESSION = re.compile(r'\$\{\{.*?\}\}', re.S)
SHELLCHECK = shutil.which('shellcheck')


def scripts(workflow: 'dict[str, Any]') -> 'list[tuple[str, str, str]]':
    """``(job / step, shell, script)`` for each ``bash`` or ``sh`` ``run:`` step."""
    default = ((workflow.get('defaults') or {}).get('run') or {}).get('shell', 'bash')
    found = []
    for job_id, job in workflow['jobs'].items():
        job_default = ((job.get('defaults') or {}).get('run') or {}).get('shell', default)
        for index, step in enumerate(job.get('steps') or ()):
            shell = str(step.get('shell', job_default)).split()[0]
            if 'run' in step and shell in ('bash', 'sh'):
                name = f"{job_id} / {step.get('name', f'step {index}')}"
                script = EXPRESSION.sub(lambda m: '_' * len(m.group(0)), step['run'])
                found.append((name, shell, script))
    return found


def findings(shell: 'str', script: 'str') -> 'list[str]':
    """shellcheck's findings on ``script``, one ``SCnnnn (level) line N: message`` each."""
    result = subprocess.run(  # nosec: B603
        [SHELLCHECK, '--norc', '-f', 'json', '-x',  # type: ignore[list-item]
         '--shell', shell, '-e', EXCLUDED, '-'],
        input=f'{SETUP[shell]}\n{script}\n', capture_output=True, text=True, check=False)
    return [f"SC{item['code']} ({item['level']}) line {item['line'] - 1}: {item['message']}"
            for item in json.loads(result.stdout or '[]')]


@unittest.skipIf(SHELLCHECK is None, 'shellcheck is not on PATH')
class TestShellcheck(unittest.TestCase):
    """unit-tests.yml's ``run:`` blocks carry no shellcheck finding."""

    def test_there_are_scripts_to_check(self) -> None:
        self.assertTrue(scripts(_workflows.load(WORKFLOW)))

    def test_every_run_block_is_clean(self) -> None:
        for name, shell, script in scripts(_workflows.load(WORKFLOW)):
            with self.subTest(step=name):
                self.assertEqual(findings(shell, script), [])

    def test_a_finding_is_reported(self) -> None:
        """The check itself sees the finding #1967 fixed, an unquoted selection."""
        self.assertTrue(findings('bash', 'selection=$(echo a b)\npytest $selection\n'))


if __name__ == '__main__':
    unittest.main()
