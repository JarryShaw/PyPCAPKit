# -*- coding: utf-8 -*-
"""#1748: a Vendor Update that skipped ``vendor-update`` is not a real one to Create Release.

Vendor Update 38650191283 was raised by the Unit Tests verdict for an older
commit than the tip it checked out, so its ``verdict`` job read "not covered"
and ``vendor-update`` skipped -- yet the run concluded ``success``, the
conclusion Create Release's ``workflow_run`` trigger proceeds on, and
``0cdd3cdd1`` got a second Create Release run. Read live with ``gh api`` while
writing this: that run's jobs were ``Verdict covers this commit`` ``success``,
``Vendor test gate`` ``skipped`` and ``vendor-update`` ``skipped``; the run
covering that commit, 38650782750, had ``vendor-update`` ``success``.

A run concludes ``skipped`` only when nothing in it ran, and ``verdict`` has to
run to decide, so Vendor Update cannot conclude anything but ``success`` there
without going red or cancelled. Create Release's ``vendor_update`` job reads the
triggering run's jobs instead, and ``version_check`` skips on ``updated ==
'false'``. Its script, :file:`util/release_vendor_update.py` since #1967, runs
here against a stand-in ``gh`` that applies the real ``--jq`` filter with ``jq``.

"""

from __future__ import annotations

import json
import pathlib
import shutil
import subprocess
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import scale_timeout
from tests.project.test_release_gates import (NULL, WORKFLOW, declared_if, declared_needs,
                                              evaluate_condition, job_blocks, release_context)
from tests.project.test_release_tags_the_run_sha_1634 import script_command, workflow_steps

if TYPE_CHECKING:
    from typing import Any, Optional

#: The stand-in ``gh``: records its arguments, fails when ``GH_FAIL`` is set, and
#: otherwise applies its ``--jq`` filter to ``$REPLY`` as ``gh`` does, raw.
FAKE_GH = ('#!/bin/sh\nprintf \'%s\\n\' "$@" > "$ARGS"\n'
           '[ -z "$GH_FAIL" ] || { echo "HTTP 404: Not Found" >&2; exit 1; }\n'
           'filter=""\nwhile [ $# -gt 0 ]; do [ "$1" = --jq ] && filter="$2"; shift; done\n'
           'exec jq -r "$filter" "$REPLY"\n')

#: The jobs of Vendor Update 38650191283 and 38650782750, as "List jobs for a
#: workflow run" returned them, trimmed to the fields the filter reads.
NOT_COVERED = {'total_count': 3, 'jobs': [
    {'name': 'Verdict covers this commit', 'conclusion': 'success'},
    {'name': 'Vendor test gate', 'conclusion': 'skipped'},
    {'name': 'vendor-update', 'conclusion': 'skipped'},
]}
COVERED = {'total_count': 3, 'jobs': [
    {'name': 'Verdict covers this commit', 'conclusion': 'success'},
    {'name': 'Vendor test gate', 'conclusion': 'skipped'},
    {'name': 'vendor-update', 'conclusion': 'success'},
]}

STEP = 'Read whether its vendor-update job ran'
#: ``release_status``'s one step that runs a script.
REPORT_STEP = 'Report why this run did or did not release anything'


def named(steps: 'list[dict[str, Any]]', name: 'str') -> 'dict[str, Any]':
    """The one step of ``steps`` called ``name``."""
    [step] = [step for step in steps if step.get('name') == name]
    return step


class TestTheJob(unittest.TestCase):
    """What ``vendor_update`` reads, with which token, and who reads it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.jobs = job_blocks(WORKFLOW.read_text(encoding='utf-8'))
        cls.steps = workflow_steps(WORKFLOW.read_text(encoding='utf-8'))

    def test_it_runs_only_for_a_vendor_update_that_succeeded(self) -> None:
        condition = declared_if(self.jobs['vendor_update'])
        for event_name, conclusion, expected in (('workflow_run', 'success', True),
                                                 ('workflow_run', 'skipped', False),
                                                 ('workflow_run', 'failure', False),
                                                 ('push', 'success', False)):
            with self.subTest(event_name=event_name, conclusion=conclusion):
                context = release_context(event_name=event_name, workflow_run_conclusion=conclusion)
                self.assertEqual(evaluate_condition(condition, context), expected)

    def test_it_reads_the_triggering_runs_jobs_with_read_scopes_only(self) -> None:
        """``actions: read`` for the listing; ``contents: read`` for the checkout of its script (#1967)."""
        block = self.jobs['vendor_update']
        self.assertIn('    permissions:\n      actions: read\n      contents: read\n    outputs:', block)
        self.assertIn('updated: ${{ steps.updated.outputs.updated }}', block)
        step = named(self.steps['vendor_update'], STEP)
        self.assertEqual(step.get('id'), 'updated')
        self.assertEqual(step.get('env'), {'GH_TOKEN': '${{ github.token }}',
                                           'PCAPKIT_VENDOR_RUN_ID': '${{ github.event.workflow_run.id }}'})
        self.assertNotIn('${{', step['run'])

    def test_version_check_and_release_status_read_it(self) -> None:
        self.assertEqual(declared_needs(self.jobs['version_check']), ['vendor_update'])
        self.assertIn("needs.vendor_update.outputs.updated != 'false'", declared_if(self.jobs['version_check']))
        report = named(self.steps['release_status'], REPORT_STEP)
        self.assertEqual(report['env'].get('PCAPKIT_VENDOR_UPDATED'), '${{ needs.vendor_update.outputs.updated }}')

    def test_only_a_skipped_vendor_update_job_stops_version_check(self) -> None:
        """Run 38650191283's ``'false'`` skips it; an unread ``null`` runs it, as before #1748."""
        condition = declared_if(self.jobs['version_check'])
        for updated, expected in (('false', False), ('true', True), (NULL, True)):
            with self.subTest(updated=updated):
                self.assertEqual(evaluate_condition(condition, release_context(vendor_updated=updated)),
                                 expected)


@unittest.skipIf(shutil.which('jq') is None or shutil.which('bash') is None, 'needs jq and bash on PATH')
class TestTheScript(unittest.TestCase):
    """``vendor_update``'s step against the two real shapes and the ones it cannot read.

    It runs ``python3 util/release_vendor_update.py`` (#1967), here on this
    interpreter.

    """

    @classmethod
    def setUpClass(cls) -> None:
        run = named(workflow_steps(WORKFLOW.read_text(encoding='utf-8'))['vendor_update'], STEP)['run']
        cls.command = script_command(run)
        assert cls.command is not None, run

    def setUp(self) -> None:
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix='pcapkit-1748-'))
        self.addCleanup(shutil.rmtree, self.tmp, True)
        (self.tmp / 'bin').mkdir()
        (self.tmp / 'bin' / 'gh').write_text(FAKE_GH, encoding='utf-8')
        (self.tmp / 'bin' / 'gh').chmod(0o755)

    def run_step(self, reply: 'Optional[dict[str, Any]]',
                 fail: 'bool' = False) -> 'tuple[subprocess.CompletedProcess[str], str]':
        (self.tmp / 'reply.json').write_text(json.dumps(reply), encoding='utf-8')
        output = self.tmp / 'github-output'
        output.write_text('', encoding='utf-8')
        env = {
            'PATH': f'{self.tmp / "bin"}:/usr/bin:/bin:{shutil.which("jq").rsplit("/", 1)[0]}',  # type: ignore[union-attr]
            'GITHUB_OUTPUT': str(output), 'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit',
            'GH_TOKEN': 'token', 'PCAPKIT_VENDOR_RUN_ID': '38650191283',
            'REPLY': str(self.tmp / 'reply.json'), 'ARGS': str(self.tmp / 'args'),
            'GH_FAIL': '1' if fail else '',
        }
        result = subprocess.run(self.command, cwd=self.tmp, env=env, capture_output=True,
                                text=True, check=False, timeout=scale_timeout(30))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return result, output.read_text(encoding='utf-8')

    def test_run_38650191283_updated_nothing(self) -> None:
        _, written = self.run_step(NOT_COVERED)
        self.assertEqual(written, 'updated=false\n')
        self.assertEqual((self.tmp / 'args').read_text(encoding='utf-8').splitlines()[:3],
                         ['api', 'repos/JarryShaw/PyPCAPKit/actions/runs/38650191283/jobs', '--paginate'])

    def test_run_38650782750_updated(self) -> None:
        self.assertEqual(self.run_step(COVERED)[1], 'updated=true\n')

    def test_what_it_cannot_read_leaves_updated_unset_and_warns(self) -> None:
        """Unset runs ``version_check`` as before #1748: it can cost a run, never a release."""
        cases = {
            'the API refused': (COVERED, True),
            'no vendor-update job': ({'total_count': 0, 'jobs': []}, False),
            'vendor-update failed': ({'jobs': [{'name': 'vendor-update', 'conclusion': 'failure'}]}, False),
        }
        for name, (reply, fail) in sorted(cases.items()):
            with self.subTest(case=name):
                result, written = self.run_step(reply, fail=fail)
                self.assertEqual(written, '')
                self.assertIn('::warning title=Vendor Update not read (#1748)::', result.stdout)
                self.assertIn('treats it as one that updated', result.stdout)


if __name__ == '__main__':
    unittest.main()
