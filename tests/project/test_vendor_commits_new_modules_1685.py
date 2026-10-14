# -*- coding: utf-8 -*-
"""#1685: Vendor Update's bump commit carries the modules a crawl adds.

``Commit changes`` in :file:`.github/workflows/cron-vendor.yml` ran ``git commit
-am``, which stages modified and deleted tracked files and never an untracked
one. ``tj-actions/verify-changed-files@v17`` reports untracked files too (the
``??`` entries of ``git status -u --porcelain``), so a crawl that generated a
module for a new registry bumped the version and left the module out of the
commit. Every later crawl found it untracked again, and bumped again.

:class:`TestTheBumpCommitStep` runs that step's script in a throwaway repository
the way the runner runs it, with ``${{ }}`` substituted first. The second test
classifies a new module with :file:`util/vendor_code_changed.py` and walks the
steps, which shows ``Commit documentation changes``, still ``-a`` alone, never
sees one. The harness is #1674's, from
:mod:`tests.project.test_vendor_comment_only_no_bump_1674`.

"""

from __future__ import annotations

import os
import re
import shlex
import subprocess
import sys
import unittest

from tests._support import scale_timeout
from tests.project.test_release_gates import (_RUN_LITERAL, NULL, block_scalar_after,
                                              evaluate_expression, step_block, step_mapping)
from tests.project.test_vendor_comment_only_no_bump_1674 import (BOT, EDITS, HUMAN, MODULE, PATH,
                                                                 SCRIPT, WATCHED, ScratchRepository,
                                                                 WorkflowMixin, edited, walk)

#: The module a crawl generates for a registry IANA added, untracked until committed.
ADDED = 'pcapkit/const/reg/apptype/sctp.py'
#: A module the crawl stops generating, tracked in ``HEAD``.
DELETED = 'pcapkit/const/reg/apptype/tcp.py'
#: What ``Bump Version`` rewrites outside :file:`pcapkit/const/`, tracked.
VERSION_FILE = 'pcapkit/__init__.py'

#: Files in the working tree the crawl did not write as output: the backup
#: ``pcapkit.vendor.__main__._snapshot_and_restore`` leaves beside a module when
#: it cannot remove it, which ``.gitignore`` does not cover, and a file outside
#: the generated tree.
STRAYS = ('pcapkit/const/reg/apptype/.udp.py.k2j3h4.bak', 'scratch.txt')

#: One ``${{ }}`` in a ``run:`` script, substituted before the shell sees it.
_EXPRESSION = re.compile(r'\$\{\{(.*?)\}\}', re.DOTALL)


def interpolate(text: 'str', context: 'dict[str, object]') -> 'str':
    """``text`` with each ``${{ }}`` replaced by its value, as the runner does."""
    def value(match: 're.Match[str]') -> 'str':
        answer = evaluate_expression(match.group(1), context)
        return '' if answer is NULL else str(answer)
    return _EXPRESSION.sub(value, text)


class TestTheBumpCommitStep(WorkflowMixin, ScratchRepository):
    """``Commit changes``' script, after a crawl that added, changed and dropped a module."""

    def setUp(self) -> None:
        super().setUp()
        # `python -c 'import pcapkit'` in the step reads this tree's version.
        bin_dir = self.root / 'bin'
        bin_dir.mkdir()
        (bin_dir / 'python').write_text(
            f'#!/bin/sh\nexec {shlex.quote(sys.executable)} -S "$@"\n', encoding='utf-8')
        (bin_dir / 'python').chmod(0o755)
        self.env['PATH'] = f'{bin_dir}{os.pathsep}{self.env["PATH"]}'

        # The real tree has one, so an unquoted `pcapkit/const/*.py` would be
        # expanded by the shell to this file alone, and not reach the modules.
        self.write('pcapkit/const/__init__.py', '# the generated tree\n')
        self.git('add', 'pcapkit/const/__init__.py')
        self.commit('chore(const): the package marker', HUMAN)
        self.base = self.git('rev-parse', 'HEAD')

    def reported(self) -> 'list[str]':
        """What ``verify-changed-files@v17`` reports: its ``entrypoint.sh`` with no
        ``files`` pattern, so ``git diff --diff-filter=ACMUXTR``, the ``??`` lines
        of ``git status -u --porcelain`` and ``git ls-files --deleted``, de-duplicated.

        """
        tracked = self.git('diff', '--diff-filter=ACMUXTR', '--name-only').splitlines()
        untracked = [line[3:] for line in self.git('status', '-u', '--porcelain').splitlines()
                     if line.startswith('?? ')]
        deleted = self.git('ls-files', '--deleted').splitlines()
        return sorted(set(tracked + untracked + deleted) - {''})

    def classify(self, paths: 'list[str]') -> 'tuple[tuple[str, dict[str, object]], str]':
        """``Classify Changed files``' outcome and outputs, from the script itself,
        and what it printed.

        """
        output = self.root / 'classify.output'
        output.write_text('', encoding='utf-8')
        result = subprocess.run([sys.executable, str(SCRIPT)], cwd=self.repo,
                                env=dict(self.env, GITHUB_OUTPUT=str(output),
                                         CHANGED_FILES=' '.join(paths)),
                                capture_output=True, text=True, check=False,
                                timeout=scale_timeout(60))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        outputs = {}  # type: dict[str, object]
        for line in output.read_text(encoding='utf-8').splitlines():
            key, sep, value = line.partition('=')
            if sep:
                outputs[key] = value
        return ('success', outputs), result.stdout

    def bump(self) -> None:
        """What ``Bump Version`` leaves behind that this step reads."""
        self.write(VERSION_FILE, "# the package\n__version__ = '9.9.9b10'\n")

    def run_commit_step(self, changed_files: 'list[str]') -> 'subprocess.CompletedProcess[str]':
        """``Commit changes``' script, given what ``verify-changed-files`` reported."""
        block = step_block(self.block, 'Commit changes')
        context = {'github': {'event_name': 'schedule', 'event': {}}, 'steps': {
            'verify-changed-files': {'outputs': {'files_changed': 'true',
                                                 'changed_files': ' '.join(changed_files)}},
        }}  # type: dict[str, object]
        env = {}  # type: dict[str, str]
        for key, value in step_mapping(block, 'env').items():
            answer = evaluate_expression(value, context)
            env[key] = '' if answer is NULL else str(answer)

        path = self.root / 'step.sh'
        path.write_text(interpolate(block_scalar_after(block, _RUN_LITERAL), context), encoding='utf-8')
        # `bash -e {0}`, as for a `run:` with no `shell:`.
        return subprocess.run(['bash', '-e', str(path)], cwd=self.repo, env=dict(self.env, **env),
                              capture_output=True, text=True, check=False,
                              timeout=scale_timeout(60))

    def committed(self) -> 'set[tuple[str, str]]':
        """``{(status, path)}`` of the bot commit on top of :attr:`base`."""
        self.assertEqual(self.git('rev-parse', 'HEAD~1'), self.base)
        listing = self.git('diff', '--name-status', '--no-renames', 'HEAD~1', 'HEAD')
        pairs = set()  # type: set[tuple[str, str]]
        for line in listing.splitlines():
            status, path = line.split('\t', 1)
            pairs.add((status, path))
        return pairs

    def test_a_new_a_changed_and_a_deleted_module_all_land(self) -> None:
        self.write(ADDED, MODULE.replace('UDP', 'SCTP'))
        self.write(PATH, edited(EDITS[6][1]))  # b8: a member renamed
        (self.repo / DELETED).unlink()
        for stray in STRAYS:
            self.write(stray, 'not output\n')
        changed = self.reported()
        self.assertEqual(changed, sorted([ADDED, PATH, DELETED, *STRAYS]))
        self.bump()

        result = self.run_commit_step(changed)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.committed(), {('A', ADDED), ('M', PATH), ('D', DELETED),
                                            ('M', VERSION_FILE)})
        self.assertEqual(self.git('show', '-s', '--format=%ae'), BOT[1])
        message = self.git('show', '-s', '--format=%B')
        self.assertEqual(message.splitlines()[0], 'Bumped version to 9.9.9b10')
        self.assertIn(ADDED, message)
        # Nothing the crawl did not write was staged, and nothing it wrote is left.
        self.assertEqual(self.git('diff', '--cached', '--name-only'), '')
        self.assertEqual(self.reported(), sorted(STRAYS))

    def test_a_new_module_bumps_once(self) -> None:
        """The issue's own case: the crawl adds a module, and nothing else changes."""
        self.write(ADDED, MODULE.replace('UDP', 'SCTP'))
        changed = self.reported()
        self.assertEqual(changed, [ADDED])

        # A new file is code to the classifier, so it takes the bump path, and
        # `Commit documentation changes`, which stages with `-a` alone, is skipped.
        context = {'github': {'event_name': 'schedule', 'event': {}}}  # type: dict[str, object]
        classified, stdout = self.classify(changed)
        self.assertEqual(classified[1].get('code_changed'), 'true')
        self.assertIn(f'code: {ADDED}: new file', stdout)
        outcomes = walk(self.steps, context, {
            'verify-changed-files': ('success', {'files_changed': 'true', 'changed_files': ADDED}),
            'classify': classified,
        })
        self.assertEqual(tuple(name for name in WATCHED if outcomes[name] != 'skipped'),
                         ('Classify Changed files', 'Bump Version', 'Commit changes', 'Push changes'))

        self.bump()
        result = self.run_commit_step(changed)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.committed(), {('A', ADDED), ('M', VERSION_FILE)})

        # The next crawl writes the same module: nothing to report, so no bump.
        self.write(ADDED, MODULE.replace('UDP', 'SCTP'))
        self.assertEqual(self.reported(), [])
        outcomes = walk(self.steps, context, {
            'verify-changed-files': ('success', {'files_changed': 'false', 'changed_files': NULL}),
        })
        self.assertEqual(tuple(name for name in WATCHED if outcomes[name] != 'skipped'), ())


if __name__ == '__main__':
    unittest.main()
