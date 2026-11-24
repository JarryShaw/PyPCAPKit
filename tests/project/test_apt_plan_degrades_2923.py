# -*- coding: utf-8 -*-
"""#2923: a plan whose ``apt-get update`` misses its bound twice degrades rather than failing.

The plan step has no fallback mirror, so a slow one must not fail it: after its last
failed update :file:`util/apt_packages.py`'s ``plan`` writes ``degraded`` and no key and
exits 0, and the install step, which has the fallback (#1432), updates again.

Each test runs the plan and install steps' own ``run:``, with ``sudo``, ``timeout`` and
``apt-get`` stubbed as :mod:`tests.project.test_workflow_apt_cache` stubs them, and then
steps through each job's apt steps as the runner does, with the status and outputs those
runs left: an ``if:`` without a status function gets ``success()`` prepended, and a
failure under ``continue-on-error`` concludes ``success``.

* :meth:`~TestADegradedPlan.test_a_slow_mirror_costs_the_cache_not_the_job` -- the
  cache steps skip and the install runs and succeeds, where a keyed plan restores.
* :meth:`~TestADegradedPlan.test_a_dead_mirror_still_fails_at_the_install` -- #974's
  intent: the job fails at the install step, the plan having succeeded.

"""

from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._workflows import steps
from tests.project.test_ktlo_legs_stay_green_1672 import STATUS_FUNCTION, continue_on_error, label, leg_env
from tests.project.test_python_matrix_tiers_1633 import job, legs
from tests.project.test_release_gates import STATUS, evaluate_condition
from tests.project.test_workflow_apt_cache import SIMULATION, _Stubbed
from util.apt_packages import ATTEMPTS

if TYPE_CHECKING:
    from typing import Any

WORKFLOW = 'unit-tests.yml'
#: ``pypcap-parity``'s plan, restore, seed, install, collect and save steps, which its
#: KTLO twin runs too.
PARITY = ('Plan the system packages', 'Restore the cached .deb files', "Seed apt's archive with the cached .deb files",
          'Install libpcap headers, a C toolchain, and tshark', 'Collect the installed .deb files for the cache',
          'Save the .deb files to the cache')
#: Each job running the plan, with those steps of its own.
SITES = {
    'engine-tests': ("Plan this engine's system packages", "Restore this engine's cached .deb files",
                     "Seed apt's archive with this engine's cached .deb files", "Install this engine's system packages",
                     "Collect this engine's installed .deb files for the cache",
                     "Save this engine's .deb files to the cache"),
    'pypcap-parity': PARITY,
    'pypcap-parity-ktlo': PARITY,
}


class TestADegradedPlan(_Stubbed):
    """Each job's apt steps after a plan whose updates all fail, run and then stepped through."""

    def planned(self) -> 'list[tuple[str, dict[str, Any]]]':
        """``(job, leg)`` for every leg whose plan step runs, as the tier file expands them."""
        found = [(job_id, leg) for job_id in SITES for leg in legs(WORKFLOW, job_id)
                 if leg_env(WORKFLOW, job(WORKFLOW, job_id), leg)['APT_PACKAGES']]
        self.assertEqual({job_id for job_id, _ in found}, set(SITES))
        return found

    def run_steps(self, job_id: 'str', leg: 'dict[str, Any]',
                  fail_updates: 'int') -> 'dict[str, tuple[int, dict[str, str], str]]':
        """The plan, then the install, each its ``run:``, with the first ``fail_updates`` updates failing.

        Each is ``(status, outputs, log)``, by step name.

        """
        self.reset()
        sim = self.tmp / 'sim'
        sim.write_text(SIMULATION, encoding='utf-8')
        found = {}  # type: dict[str, tuple[int, dict[str, str], str]]
        for name in (SITES[job_id][0], SITES[job_id][3]):
            run = next(item for item in steps(WORKFLOW, job_id) if item.get('name') == name)['run']
            output = self.tmp / 'output'
            output.write_text('', encoding='utf-8')
            env = dict(leg_env(WORKFLOW, job(WORKFLOW, job_id), leg), STUB_SIM=str(sim), GITHUB_OUTPUT=str(output),
                       ImageOS='ubuntu24', RUNNER_ARCH='X64', FAIL_UPDATES=str(fail_updates))
            status, log = self.run_script(run, env)
            outputs = dict(line.split('=', 1) for line in output.read_text(encoding='utf-8').splitlines())
            found[name] = (status, outputs, log)
        return found

    def walk(self, job_id: 'str', leg: 'dict[str, Any]',
             ran: 'dict[str, tuple[int, dict[str, str], str]]') -> 'tuple[str, dict[str, str]]':
        """The conclusion of the job's apt steps on ``leg``, and each one's outcome, by name.

        A step in ``ran`` takes the status and outputs given there; any other that runs
        succeeds and sets none, so a restore that runs is a miss.

        """
        spec = job(WORKFLOW, job_id)
        env = leg_env(WORKFLOW, spec, leg)
        found = steps(WORKFLOW, job_id)
        names = [label(item) for item in found]
        context_steps = {}  # type: dict[str, dict[str, Any]]
        failed = False
        outcomes = {}  # type: dict[str, str]
        for item in found[names.index(SITES[job_id][0]):names.index(SITES[job_id][-1]) + 1]:
            context = {'matrix': leg, 'env': env, 'steps': context_steps, 'inputs': {}, 'needs': {},
                       STATUS: {'success': not failed, 'failure': failed, 'cancelled': False}}
            condition = '' if item.get('if') is None else str(item['if'])
            runs = STATUS_FUNCTION.search(condition) is not None or not failed
            if runs and condition:
                runs = evaluate_condition(condition, context)
            status, outputs, _ = ran.get(label(item), (0, {}, ''))
            if runs:
                outcome = 'success' if status == 0 else 'failure'
                conclusion = 'success' if outcome == 'failure' and continue_on_error(item, context) else outcome
                failed = failed or conclusion == 'failure'
            else:
                outcome = conclusion = 'skipped'
                outputs = {}
            if 'id' in item:
                context_steps[item['id']] = {'outcome': outcome, 'conclusion': conclusion, 'outputs': dict(outputs)}
            outcomes[label(item)] = outcome
        return ('failure' if failed else 'success'), outcomes

    def test_a_slow_mirror_costs_the_cache_not_the_job(self) -> None:
        """Its updates fail, the install's succeed: no cache step runs, and the job succeeds."""
        for job_id, leg in self.planned():
            plan, restore, seed, install, collect, save = SITES[job_id]
            with self.subTest(job=job_id, leg=leg):
                ran = self.run_steps(job_id, leg, ATTEMPTS)
                conclusion, outcomes = self.walk(job_id, leg, ran)
                self.assertEqual(({name: outcomes[name] for name in SITES[job_id]}, conclusion), ({
                    plan: 'success', restore: 'skipped', seed: 'skipped', install: 'success',
                    collect: 'skipped', save: 'skipped'}, 'success'))
                self.assertEqual(ran[plan][:2], (0, {'degraded': 'true'}), ran[plan][2])
                self.assertIn('no cache this run, and the install step updates again', ran[plan][2])
                self.assertEqual(ran[install][0], 0, ran[install][2])
                # A plan whose retry succeeds writes its key, and the restore reads it.
                keyed = self.run_steps(job_id, leg, ATTEMPTS - 1)
                self.assertEqual(set(keyed[plan][1]), {'restore-prefix', 'key'}, keyed[plan][2])
                saves = 'success' if leg_env(WORKFLOW, job(WORKFLOW, job_id), leg)['APT_CACHE_SAVE'] == 'true' \
                    else 'skipped'
                self.assertEqual(self.walk(job_id, leg, keyed), ('success', {
                    **outcomes, restore: 'success', collect: saves, save: saves}))

    def test_a_dead_mirror_still_fails_at_the_install(self) -> None:
        """Every update fails: the plan degrades, and the install fails the job, unless the leg is KTLO."""
        for job_id, leg in self.planned():
            plan, _, _, install, _, _ = SITES[job_id]
            with self.subTest(job=job_id, leg=leg):
                ran = self.run_steps(job_id, leg, 2 * ATTEMPTS)
                conclusion, outcomes = self.walk(job_id, leg, ran)
                self.assertEqual((outcomes[plan], outcomes[install], conclusion),
                                 ('success', 'failure', 'success' if leg.get('ktlo') is True else 'failure'))
                self.assertEqual(ran[plan][:2], (0, {'degraded': 'true'}), ran[plan][2])
                self.assertEqual(ran[install][0], 1, ran[install][2])


if __name__ == '__main__':
    unittest.main()
