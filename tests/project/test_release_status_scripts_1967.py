# -*- coding: utf-8 -*-
"""#1967: :file:`util/release_status.py`, and ``vendor_update``'s inline shell, run as Create Release runs them.

* :class:`TestTheStepMatchesTheReferenceShell` runs ``release_status``'s "Report why this
  run did or did not release anything" in its inline shell form, the reference
  the script must match, on the cases below, and the script on the same, and requires the same status,
  standard output and error, ``$GITHUB_OUTPUT``, ``$GITHUB_STEP_SUMMARY`` and
  ``gh`` calls. That form is kept here verbatim, and the case table is
  checked to reach every branch of it. The one sentence the shell form lacks,
  the Anaconda remedy (#2140), is dropped from the script's output first;
  :mod:`tests.project.test_release_gates` pins it.
* :class:`TestTheVendorUpdateStaysInline` pins ``vendor_update``'s "Read whether
  its vendor-update job ran", inline as too plain to need a script (#1967), to
  its shell verbatim, with no checkout, and runs that ``run:`` on its own case
  table, which reaches each of its branches.
* :class:`TestTheStepsRunTheScripts` pins ``release_status``'s step to its
  script, after a checkout of :file:`util/` alone, and the script to
  :file:`util/`, the standard library and Python 3.8's syntax.

The shell form runs as a step with no ``shell:`` runs on the runner, ``bash -e``, and
``bash`` prefixes each of its own errors with the script's path and line, which
:meth:`_Stand.reference` strips; the rest of standard error is compared whole.
What the steps report, case by case, is
:mod:`tests.project.test_release_gates`'s and
:mod:`tests.project.test_release_reads_the_vendor_update_1748`'s.

"""

from __future__ import annotations

import ast
import os
import pathlib
import random
import re
import shutil
import subprocess  # nosec: B404
import sys
import tempfile
import textwrap
import unittest
from typing import TYPE_CHECKING

from tests._support import bash_argv
from tests._workflows import load, steps
from tests.project.test_release_gates import job_blocks
from tests.project.test_requires_python_floor_2051 import FLOOR

if TYPE_CHECKING:
    from typing import Callable, Optional

#: Test tier (#1958): runs the tree's own scripts and the step's inline shell form.
__tier__ = 'LATEST'

ROOT = pathlib.Path(__file__).resolve().parents[2]
UTIL = ROOT / 'util'
WORKFLOW = 'create-release.yml'
BASH = shutil.which('bash') or ''

RUN = '1' * 40
OTHER = '2' * 40
BOT = '41898282'
HUMAN = '5352553'

#: A ``gh`` answering ``api`` with ``$GH_REPLY``'s bytes as its ``--jq`` output, or
#: failing with ``$GH_FAIL``'s status (``TERM``, killed by SIGTERM).
FAKE_GH = r'''#!/bin/sh
printf '%s\n' "$*" >> "$GH_LOG"
[ "$1" = api ] || exit 99
if [ -n "${GH_FAIL:-}" ]; then
  echo "HTTP 404: Not Found (https://api.github.com/$2)" >&2
  [ "$GH_FAIL" != TERM ] || kill -TERM $$
  exit "$GH_FAIL"
fi
cat "$GH_REPLY"
'''

#: "Report why this run did or did not release anything" in ``release_status``, in
#: its inline shell form, the reference :file:`util/release_status.py` must match.
REFERENCE_STATUS = textwrap.dedent(r'''
    set -euo pipefail

    # #1633: pypi's KTLO legs reach neither needs.pypi.result
    # (continue-on-error) nor PCAPKIT_PYPI_COMPLETE's count, so each is
    # only reported here, as a notice, from its own job output.
    ktlo_310="${PCAPKIT_PYPI_KTLO_310:-}"
    ktlo_pypy310="${PCAPKIT_PYPI_KTLO_PYPY310:-}"
    if [ -n "${ktlo_310}${ktlo_pypy310}" ]; then
      echo "::notice title=KTLO legs (non-blocking)::pypi 3.10=${ktlo_310:-not run} pypy3.10=${ktlo_pypy310:-not run}. End-of-life Python, built and published but never blocking (#1633); neither result changes this run's verdict."
    fi

    # Case 1: version_check never ran. On `workflow_run`, Vendor Update did
    # not conclude `success`: `skipped`, nothing to update, gets a quiet
    # notice; anything else a warning, as Vendor Update needs attention --
    # but no tag exists to strand, so it is not #888. On a push it is quiet
    # only for the release App's own tag (#1634); an unset bot id never
    # matches. #1748: a `success` that never ran vendor-update is quiet too.
    if [ "$PCAPKIT_VERSION_CHECK" = "skipped" ]; then
      if [ "$PCAPKIT_EVENT_NAME" = "push" ] && [ -n "$PCAPKIT_RELEASE_APP_BOT_ID" ] \
         && [ "$PCAPKIT_ACTOR_ID" = "$PCAPKIT_RELEASE_APP_BOT_ID" ]; then
        echo "::notice title=Nothing to release::the release App's bot pushed this tag from the Create Release run that released its commit, so this run correctly released nothing (#1634)."
      elif [ "$PCAPKIT_EVENT_NAME" = "workflow_run" ] && [ "$PCAPKIT_WORKFLOW_RUN_CONCLUSION" = "skipped" ]; then
        echo "::notice title=Nothing to release::the triggering Vendor Update run found nothing to update, so this run correctly released nothing."
      elif [ "$PCAPKIT_EVENT_NAME" = "workflow_run" ] && [ "$PCAPKIT_WORKFLOW_RUN_CONCLUSION" = "success" ] \
         && [ "${PCAPKIT_VENDOR_UPDATED:-}" = "false" ]; then
        echo "::notice title=Nothing to release::the triggering Vendor Update run skipped vendor-update, since its Unit Tests verdict did not cover the commit it checked out, so it updated nothing and this run correctly released nothing (#1748)."
      elif [ "$PCAPKIT_EVENT_NAME" = "workflow_run" ]; then
        echo "::warning title=Release skipped::the triggering Vendor Update run concluded '${PCAPKIT_WORKFLOW_RUN_CONCLUSION}', not 'success', so version_check, the release test gate and every release job were skipped. Not #888 -- no tag was created that could be left stranded -- but Vendor Update likely needs attention."
      else
        echo "::warning title=Release skipped for an unexpected reason::version_check reported 'skipped' with event_name='${PCAPKIT_EVENT_NAME}', which is not the workflow_run non-success case this job otherwise expects. Check the version_check job's own if: condition."
      fi
      exit 0
    fi

    # version_check ran and did not succeed: a workflow failure, not #888.
    if [ "$PCAPKIT_VERSION_CHECK" != "success" ]; then
      echo "::warning title=Release blocked before it could start::version_check did not succeed (result: '${PCAPKIT_VERSION_CHECK}'), so neither the release test gate nor any release job ran. This is a workflow failure, not #888."
      exit 0
    fi

    # The gate did not pass, so every release job skipped: a test failure,
    # not #888, and already red in this run's checks.
    if [ "$PCAPKIT_UNIT_TESTS" = "failure" ] || [ "$PCAPKIT_UNIT_TESTS" = "cancelled" ]; then
      echo "::warning title=Release blocked by the test gate::the release test gate concluded '${PCAPKIT_UNIT_TESTS}', so no release job ran for ${PCAPKIT_VERSION}. This is a test failure, not #888."
      exit 0
    fi

    # #1748: tagged at another commit, with the gate and every publisher
    # skipped for it, which happens only off a v* ref. That release is that
    # commit's (#1634): a notice if complete, else a warning naming what it
    # lacks, both green. A publisher that ran on a v* push meets #1634's
    # check and is reported below.
    if [ "${PCAPKIT_RELEASED_ELSEWHERE:-}" = "true" ] && [ "$PCAPKIT_GITHUB_JOB" = "skipped" ] \
       && [ "$PCAPKIT_TAG_JOB" = "skipped" ] && [ "$PCAPKIT_PYPI_JOB" = "skipped" ] \
       && [ "$PCAPKIT_CONDA_JOB" = "skipped" ]; then
      missing=""
      [ "$PCAPKIT_CONDA_TAG_EXISTS" = "true" ] || missing="${missing:+${missing}, }the conda-${PCAPKIT_VERSION}+0 tag"
      [ "$PCAPKIT_PYPI_COMPLETE" = "true" ] || missing="${missing:+${missing}, }some of its PyPI files"
      [ "$PCAPKIT_CONDA_COMPLETE" = "true" ] || missing="${missing:+${missing}, }some of its Anaconda files"
      if [ -z "$missing" ]; then
        echo "::notice title=Nothing to release::v${PCAPKIT_VERSION} names ${PCAPKIT_RELEASED_AT}, not this run's commit ${PCAPKIT_RUN_SHA}, and that release is complete, so this run correctly released nothing (#1748)."
      else
        echo "::warning title=v${PCAPKIT_VERSION} is unfinished (#1634)::v${PCAPKIT_VERSION} names ${PCAPKIT_RELEASED_AT}, not this run's commit ${PCAPKIT_RUN_SHA}, and still lacks ${missing}. Only that commit's run may finish it (#1634), so this run released nothing: re-run the Create Release run created for ${PCAPKIT_RELEASED_AT}, or release the next version."
      fi
      exit 0
    fi

    # Owner ruling, 2026-10-30: this run's version carries a PEP 440 dev-release
    # suffix, and the PCAPKIT_DEV_RELEASE gate skips every publisher for it on
    # purpose, so this is a deliberate no-op, never the #888 shape.
    if [ "${PCAPKIT_DEV_RELEASE:-}" = "true" ] && [ "$PCAPKIT_GITHUB_JOB" = "skipped" ] \
       && [ "$PCAPKIT_TAG_JOB" = "skipped" ] && [ "$PCAPKIT_PYPI_JOB" = "skipped" ] \
       && [ "$PCAPKIT_CONDA_JOB" = "skipped" ]; then
      echo "::notice title=Nothing to release::this run's version, ${PCAPKIT_VERSION}, carries a PEP 440 dev-release suffix (.devN), so the PCAPKIT_DEV_RELEASE gate skipped every publisher deliberately: this run correctly released nothing."
      exit 0
    fi

    # From here the evidence outputs are meaningful. A skipped gate (#1052)
    # falls through on purpose: it skips only when every evidence output
    # reads 'true' off a v* ref, reported as "Nothing to release" below; if
    # its predicate drifts, every publisher skips behind it and this
    # reaches the loud #888 branch instead.
    #
    # Reconcile each job against its OWN evidence, not against each other:
    # a self-heal mixes jobs that skipped because their artefact existed
    # with jobs that ran, and demanding uniformity would read that mix as
    # #888 on the run that finished the release. Reconciled = succeeded, or
    # skipped with its own evidence saying done.
    reconciled_github=false
    [ "$PCAPKIT_GITHUB_JOB" = "success" ] && reconciled_github=true
    [ "$PCAPKIT_GITHUB_JOB" = "skipped" ] && [ "$PCAPKIT_TAG_EXISTS" = "true" ] && reconciled_github=true

    reconciled_tag=false
    [ "$PCAPKIT_TAG_JOB" = "success" ] && reconciled_tag=true
    [ "$PCAPKIT_TAG_JOB" = "skipped" ] && [ "$PCAPKIT_CONDA_TAG_EXISTS" = "true" ] && reconciled_tag=true

    reconciled_pypi=false
    [ "$PCAPKIT_PYPI_JOB" = "success" ] && reconciled_pypi=true
    [ "$PCAPKIT_PYPI_JOB" = "skipped" ] && [ "$PCAPKIT_PYPI_COMPLETE" = "true" ] && reconciled_pypi=true

    reconciled_conda=false
    [ "$PCAPKIT_CONDA_JOB" = "success" ] && reconciled_conda=true
    [ "$PCAPKIT_CONDA_JOB" = "skipped" ] && [ "$PCAPKIT_CONDA_COMPLETE" = "true" ] && reconciled_conda=true

    all_reconciled=false
    if [ "$reconciled_github" = "true" ] && [ "$reconciled_tag" = "true" ] \
       && [ "$reconciled_pypi" = "true" ] && [ "$reconciled_conda" = "true" ]; then
      all_reconciled=true
    fi

    all_skipped=true
    any_broken=false
    for result in "$PCAPKIT_GITHUB_JOB" "$PCAPKIT_TAG_JOB" "$PCAPKIT_PYPI_JOB" "$PCAPKIT_CONDA_JOB"; do
      [ "$result" = "skipped" ] || all_skipped=false
      if [ "$result" = "failure" ] || [ "$result" = "cancelled" ]; then
        any_broken=true
      fi
    done

    # Case 2: every target reconciled by skipping -- the usual steady state.
    if [ "$all_reconciled" = "true" ] && [ "$all_skipped" = "true" ]; then
      echo "::notice title=Nothing to release::pypcapkit ${PCAPKIT_VERSION} is already fully released -- the v* tag, the conda-*+0 tag and every PyPI and Anaconda file version_check expects are present. This run correctly released nothing."
      exit 0
    fi

    # Every target reconciled and at least one ran: a fresh release or a
    # self-heal, both quiet.
    if [ "$all_reconciled" = "true" ]; then
      echo "::notice title=Release complete::pypcapkit ${PCAPKIT_VERSION} is now fully released -- github=${PCAPKIT_GITHUB_JOB} tag=${PCAPKIT_TAG_JOB} pypi=${PCAPKIT_PYPI_JOB} conda=${PCAPKIT_CONDA_JOB}. A 'skipped' entry there means that target's own artefact already existed before this run, not that anything was missed."
      exit 0
    fi

    if [ "$any_broken" = "true" ]; then
      echo "::warning title=Release did not complete::github=${PCAPKIT_GITHUB_JOB} tag=${PCAPKIT_TAG_JOB} pypi=${PCAPKIT_PYPI_JOB} conda=${PCAPKIT_CONDA_JOB} for ${PCAPKIT_VERSION}. At least one release job failed or was cancelled outright -- see its own log; this run's checks already show that failure in red."
      exit 0
    fi

    # Case 3, the #888 shape: a target skipped despite its own evidence
    # saying incomplete, with nothing failed or cancelled to explain it.
    # The evidence-based `if:`s should make this unreachable, so reaching
    # it means that assumption broke: loud, and never green.
    echo "::error title=Stranded partial release (#888)::${PCAPKIT_VERSION} is only partially published (tag exists=${PCAPKIT_TAG_EXISTS}, conda tag exists=${PCAPKIT_CONDA_TAG_EXISTS}, pypi complete=${PCAPKIT_PYPI_COMPLETE}, conda complete=${PCAPKIT_CONDA_COMPLETE}) but github=${PCAPKIT_GITHUB_JOB} tag=${PCAPKIT_TAG_JOB} pypi=${PCAPKIT_PYPI_JOB} conda=${PCAPKIT_CONDA_JOB} -- at least one target skipped despite its own evidence saying it is not done. Re-running this workflow should let the incomplete jobs self-heal; if this recurs on the next run too, the evidence checks in version_check are the first thing to check."
    exit 1
''').lstrip()

#: "Read whether its vendor-update job ran" in ``vendor_update``: its ``run:``,
#: inline rather than a script (#1967).
VENDOR_SHELL = textwrap.dedent(r'''
    set -uo pipefail

    if ! result="$(gh api "repos/${GITHUB_REPOSITORY}/actions/runs/${PCAPKIT_VENDOR_RUN_ID}/jobs" \
                     --paginate --jq '.jobs[] | select(.name == "vendor-update") | .conclusion')"; then
      echo "::warning title=Vendor Update not read (#1748)::could not list the jobs of Vendor Update run ${PCAPKIT_VENDOR_RUN_ID}, so this run treats it as one that updated."
      exit 0
    fi
    case "$result" in
      success)
        echo "updated=true" >> "$GITHUB_OUTPUT"
        ;;
      skipped)
        echo "updated=false" >> "$GITHUB_OUTPUT"
        echo "Vendor Update run ${PCAPKIT_VENDOR_RUN_ID} skipped vendor-update: its verdict did not cover the commit it checked out."
        ;;
      *)
        echo "::warning title=Vendor Update not read (#1748)::Vendor Update run ${PCAPKIT_VENDOR_RUN_ID} reports vendor-update as '${result//$'\n'/ }', so this run treats it as one that updated."
        ;;
    esac
''').lstrip()

#: Each job, the step its script runs as, the ``run:`` it holds, and its
#: permissions.
JOBS = {
    'release_status': ('Report why this run did or did not release anything', 'python3 util/release_status.py',
                       {'contents': 'read'}),
}
#: ``vendor_update``'s one step, and its permissions: the listing's alone.
VENDOR_STEP = 'Read whether its vendor-update job ran'
VENDOR_PERMISSIONS = {'actions': 'read'}
#: The checkout each job opens with: this run's commit, :file:`util/` alone.
CHECKOUT = {'ref': '${{ github.sha }}', 'sparse-checkout': 'util', 'persist-credentials': False}

#: What ``release_status``'s variables hold unless a case says otherwise: a fresh
#: release on a Vendor Update that updated, every publisher succeeding.
STATUS_BASE = {
    'PCAPKIT_EVENT_NAME': 'workflow_run', 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'success',
    'PCAPKIT_VENDOR_UPDATED': 'true', 'PCAPKIT_ACTOR_ID': HUMAN, 'PCAPKIT_RELEASE_APP_BOT_ID': BOT,
    'PCAPKIT_RUN_SHA': RUN, 'PCAPKIT_UNIT_TESTS': 'success', 'PCAPKIT_VERSION_CHECK': 'success',
    'PCAPKIT_GITHUB_JOB': 'success', 'PCAPKIT_TAG_JOB': 'success', 'PCAPKIT_PYPI_JOB': 'success',
    'PCAPKIT_CONDA_JOB': 'success', 'PCAPKIT_VERSION': '1.5.0', 'PCAPKIT_TAG_EXISTS': 'false',
    'PCAPKIT_CONDA_TAG_EXISTS': 'false', 'PCAPKIT_PYPI_COMPLETE': 'false', 'PCAPKIT_CONDA_COMPLETE': 'false',
    'PCAPKIT_RELEASED_AT': RUN, 'PCAPKIT_RELEASED_ELSEWHERE': 'false', 'PCAPKIT_DEV_RELEASE': 'false',
    'PCAPKIT_PYPI_KTLO_310': '', 'PCAPKIT_PYPI_KTLO_PYPY310': '',
    # The Vendor Update's own event. Only a manual one reads differently, a
    # branch the shell form lacks; test_build_only_dispatch.py pins it.
    'PCAPKIT_WORKFLOW_RUN_EVENT': 'push',
}
#: Every publisher skipped, and each one's evidence.
ALL_SKIPPED = {'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped', 'PCAPKIT_PYPI_JOB': 'skipped',
               'PCAPKIT_CONDA_JOB': 'skipped'}
ALL_DONE = {'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_CONDA_TAG_EXISTS': 'true', 'PCAPKIT_PYPI_COMPLETE': 'true',
            'PCAPKIT_CONDA_COMPLETE': 'true'}
SKIPPED_CHECK = {'PCAPKIT_VERSION_CHECK': 'skipped', 'PCAPKIT_UNIT_TESTS': 'skipped', **ALL_SKIPPED}
ELSEWHERE = {'PCAPKIT_UNIT_TESTS': 'skipped', **ALL_SKIPPED, 'PCAPKIT_RELEASED_ELSEWHERE': 'true',
             'PCAPKIT_RELEASED_AT': OTHER}
#: A value standing for a variable left unset.
UNSET = None
#: The sentence ending the unfinished warning where Anaconda files are missing
#: (#2140), which the shell form never prints.
ANACONDA_REMEDY = re.compile(r"(?m) Its Anaconda files are the exception: while main's version is still .*?, "
                             r"dispatch Conda Update with publish on main, .*? only if that run's own conda legs "
                             r'can still succeed\.$')

#: ``release_status``'s cases: ``(name, overrides of STATUS_BASE)``.
STATUS_CASES = (
    ('the release app pushed the tag', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': 'push',
                                        'PCAPKIT_WORKFLOW_RUN_CONCLUSION': '', 'PCAPKIT_ACTOR_ID': BOT}),
    ('a person pushed the tag', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': 'push',
                                 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': ''}),
    ('no release app and no actor', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': 'push', 'PCAPKIT_ACTOR_ID': '',
                                     'PCAPKIT_RELEASE_APP_BOT_ID': '', 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': ''}),
    ('the bot id on a workflow_run', {**SKIPPED_CHECK, 'PCAPKIT_ACTOR_ID': BOT,
                                      'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'skipped'}),
    ('vendor update had nothing to do', {**SKIPPED_CHECK, 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'skipped'}),
    ('vendor update updated nothing', {**SKIPPED_CHECK, 'PCAPKIT_VENDOR_UPDATED': 'false'}),
    ('vendor update unread', {**SKIPPED_CHECK, 'PCAPKIT_VENDOR_UPDATED': ''}),
    ('vendor update failed', {**SKIPPED_CHECK, 'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'failure'}),
    ('vendor update updated nothing but failed', {**SKIPPED_CHECK, 'PCAPKIT_VENDOR_UPDATED': 'false',
                                                  'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'failure'}),
    ('an unexpected event', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': 'workflow_dispatch'}),
    ('version check failed', {'PCAPKIT_VERSION_CHECK': 'failure', 'PCAPKIT_UNIT_TESTS': 'skipped', **ALL_SKIPPED}),
    ('version check cancelled', {'PCAPKIT_VERSION_CHECK': 'cancelled', **ALL_SKIPPED}),
    ('version check empty', {'PCAPKIT_VERSION_CHECK': ''}),
    ('the gate failed', {'PCAPKIT_UNIT_TESTS': 'failure', **ALL_SKIPPED}),
    ('the gate was cancelled', {'PCAPKIT_UNIT_TESTS': 'cancelled', **ALL_SKIPPED, **ALL_DONE}),
    ('the gate skipped with nothing publishable', {'PCAPKIT_UNIT_TESTS': 'skipped', **ALL_SKIPPED, **ALL_DONE}),
    ('the gate skipped with work outstanding', {'PCAPKIT_UNIT_TESTS': 'skipped', **ALL_SKIPPED, **ALL_DONE,
                                                'PCAPKIT_PYPI_COMPLETE': 'false'}),
    ('elsewhere and complete', {**ELSEWHERE, **ALL_DONE}),
    ('elsewhere lacking the conda tag', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_CONDA_TAG_EXISTS': 'false'}),
    ('elsewhere lacking pypi', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_PYPI_COMPLETE': ''}),
    ('elsewhere lacking anaconda', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_CONDA_COMPLETE': 'false'}),
    ('elsewhere lacking pypi and anaconda', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_VERSION': '1.5.0b12',
                                             'PCAPKIT_PYPI_COMPLETE': 'false', 'PCAPKIT_CONDA_COMPLETE': 'false'}),
    ('elsewhere lacking everything', {**ELSEWHERE}),
    ('elsewhere and a publisher ran', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_CONDA_JOB': 'failure'}),
    ('elsewhere with no owner output', {**ALL_SKIPPED, 'PCAPKIT_TAG_EXISTS': 'true',
                                        'PCAPKIT_RELEASED_ELSEWHERE': '', 'PCAPKIT_RELEASED_AT': ''}),
    ('a dev release skips every publisher', {**ALL_SKIPPED, 'PCAPKIT_DEV_RELEASE': 'true'}),
    # The critical regression check: the identical skip pattern with
    # PCAPKIT_DEV_RELEASE false (not a dev release) must still be the loud
    # #888 shape, not swallowed by the new branch above.
    ('the same skip pattern with dev release false stays 888', {**ALL_SKIPPED, 'PCAPKIT_DEV_RELEASE': 'false'}),
    # A dev flag does not make a publisher that ran quiet: only every one
    # skipping is the deliberate no-op.
    ('a dev release with a publisher that failed', {**ALL_SKIPPED, 'PCAPKIT_DEV_RELEASE': 'true',
                                                    'PCAPKIT_PYPI_JOB': 'failure'}),
    # Run 41098750345, 1.5.1's partial publish: only the dev flag's 'true'
    # opens the quiet branch, so an empty or absent one stays #888.
    ('the 1.5.1 shape with the dev flag empty', {**ALL_SKIPPED, 'PCAPKIT_VERSION': '1.5.1',
                                                 'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_DEV_RELEASE': ''}),
    ('the 1.5.1 shape with the dev flag unset', {**ALL_SKIPPED, 'PCAPKIT_VERSION': '1.5.1',
                                                 'PCAPKIT_TAG_EXISTS': 'true', 'PCAPKIT_DEV_RELEASE': UNSET}),
    ('steady state', {**ALL_SKIPPED, **ALL_DONE}),
    ('a fresh release', {}),
    ('a self-heal', {'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_JOB': 'skipped', 'PCAPKIT_TAG_EXISTS': 'true',
                     'PCAPKIT_CONDA_TAG_EXISTS': 'true'}),
    ('each target reconciled by skipping but one', {'PCAPKIT_GITHUB_JOB': 'skipped', 'PCAPKIT_TAG_EXISTS': 'true',
                                                    'PCAPKIT_TAG_JOB': 'skipped',
                                                    'PCAPKIT_CONDA_TAG_EXISTS': 'true',
                                                    'PCAPKIT_PYPI_JOB': 'skipped', 'PCAPKIT_PYPI_COMPLETE': 'true'}),
    ('a publisher failed', {'PCAPKIT_PYPI_JOB': 'failure', **ALL_DONE, 'PCAPKIT_PYPI_COMPLETE': 'false'}),
    ('a publisher was cancelled', {'PCAPKIT_GITHUB_JOB': 'cancelled', 'PCAPKIT_TAG_JOB': 'skipped'}),
    ('the 888 shape', {**ALL_SKIPPED, 'PCAPKIT_TAG_EXISTS': 'true'}),
    ('a publisher with no result', {'PCAPKIT_CONDA_JOB': ''}),
    ('both ktlo legs failed', {'PCAPKIT_PYPI_KTLO_310': 'failure', 'PCAPKIT_PYPI_KTLO_PYPY310': 'failure'}),
    ('one ktlo leg recorded', {**SKIPPED_CHECK, 'PCAPKIT_PYPI_KTLO_PYPY310': 'success',
                               'PCAPKIT_WORKFLOW_RUN_CONCLUSION': 'skipped'}),
    ('the other ktlo leg recorded', {'PCAPKIT_PYPI_KTLO_310': 'success', **ALL_SKIPPED, 'PCAPKIT_TAG_EXISTS': 'true'}),
    ('ktlo legs unset', {'PCAPKIT_PYPI_KTLO_310': UNSET, 'PCAPKIT_PYPI_KTLO_PYPY310': UNSET}),
    ('the owner outputs unset', {**ALL_SKIPPED, **ALL_DONE, 'PCAPKIT_RELEASED_ELSEWHERE': UNSET,
                                 'PCAPKIT_VENDOR_UPDATED': UNSET}),
    ('awkward values pass through', {'PCAPKIT_VERSION_CHECK': "100% a:b, c\\nd 'e' $f `g`", **ALL_SKIPPED,
                                     'PCAPKIT_PYPI_KTLO_310': '%0A::x'}),
    ('a value holding a line break', {'PCAPKIT_UNIT_TESTS': 'failure', 'PCAPKIT_VERSION': '1.5.0\nv2'}),
    ('a value not in utf-8', {'PCAPKIT_VERSION': os.fsdecode(b'1.5.0\xff'), **ALL_SKIPPED, **ALL_DONE}),
    ('the check result unset', {'PCAPKIT_VERSION_CHECK': UNSET, 'PCAPKIT_PYPI_KTLO_310': 'success'}),
    ('the event unset', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': UNSET}),
    ('the bot id unset on a push', {**SKIPPED_CHECK, 'PCAPKIT_EVENT_NAME': 'push',
                                    'PCAPKIT_RELEASE_APP_BOT_ID': UNSET}),
    ('the version unset elsewhere', {**ELSEWHERE, 'PCAPKIT_VERSION': UNSET}),
    ('an evidence output unset', {**ALL_SKIPPED, 'PCAPKIT_CONDA_COMPLETE': UNSET}),
    # The shell form reads every publisher's evidence before any verdict, so a
    # later skipped publisher's unset evidence ends it even after an earlier
    # failure; reconciling with a short-circuiting generator would not.
    ('an evidence output unset after a failure', {'PCAPKIT_GITHUB_JOB': 'failure', 'PCAPKIT_TAG_JOB': 'skipped',
                                                  'PCAPKIT_CONDA_TAG_EXISTS': UNSET}),
    ('the run sha unset where it is named', {**ELSEWHERE, **ALL_DONE, 'PCAPKIT_RUN_SHA': UNSET}),
)

#: Each way the ``release_status`` shell form ends: ``name -> (status, its last
#: line of standard output, as a pattern)``. Every case matches one, and every one
#: is matched.
STATUS_BRANCHES = {
    "the release app's tag": (0, r"::notice title=Nothing to release::the release App's bot"),
    'vendor update skipped': (0, r'::notice title=Nothing to release::the triggering Vendor Update run found '),
    'vendor-update skipped': (0, r'::notice title=Nothing to release::the triggering Vendor Update run skipped '),
    'vendor update did not succeed': (0, r'::warning title=Release skipped::'),
    'an unexpected skip': (0, r'::warning title=Release skipped for an unexpected reason::'),
    'version check did not succeed': (0, r'::warning title=Release blocked before it could start::'),
    'the gate did not pass': (0, r'::warning title=Release blocked by the test gate::'),
    'released elsewhere, complete': (0, r'::notice title=Nothing to release::v.* names '),
    'released elsewhere, unfinished': (0, r'::warning title=v.* is unfinished \(#1634\)::'),
    'a dev release skipped every publisher': (0, r"::notice title=Nothing to release::this run's version, "),
    'already released': (0, r'::notice title=Nothing to release::pypcapkit '),
    'released': (0, r'::notice title=Release complete::'),
    'a publisher broke': (0, r'::warning title=Release did not complete::'),
    'the 888 shape': (1, r'::error title=Stranded partial release \(#888\)::'),
    'an unset variable': (1, r'(?!::(?:notice|warning|error) title=(?!KTLO))'),
}

#: Vendor Update's job listing as ``gh --jq`` prints it: the cases' replies.
VENDOR_CASES = (
    ('run 38650782750 updated', b'success\n', {}),
    ('run 38650191283 updated nothing', b'skipped\n', {}),
    ('vendor-update failed', b'failure\n', {}),
    ('vendor-update was cancelled', b'cancelled\n', {}),
    ('no vendor-update job', b'', {}),
    ('two vendor-update jobs', b'success\nskipped\n', {}),
    ('trailing blank lines are dropped', b'success\n\n\n', {}),
    ('no trailing newline', b'skipped', {}),
    ('a leading blank line is kept', b'\nsuccess\n', {}),
    ('a carriage return is kept', b'success\r\n', {}),
    ('spaces are kept', b' success\n', {}),
    ('awkward text passes through', b"100% a:b, c 'd' $e\n", {}),
    ('text not in utf-8', b'succ\xffess\n', {}),
    ('the api refused', b'success\n', {'GH_FAIL': '1'}),
    ('the api refused with another status', b'', {'GH_FAIL': '4'}),
    ('gh was killed', b'success\n', {'GH_FAIL': 'TERM'}),
    ('no gh at all', b'success\n', {'PATH': '/nonexistent'}),
    ('no output file for success', b'success\n', {'GITHUB_OUTPUT': UNSET}),
    ('no output file for skipped', b'skipped\n', {'GITHUB_OUTPUT': UNSET}),
    ('no output file for a warning', b'failure\n', {'GITHUB_OUTPUT': UNSET}),
    ('no repository', b'success\n', {'GITHUB_REPOSITORY': UNSET}),
    ('no run id', b'success\n', {'PCAPKIT_VENDOR_RUN_ID': UNSET}),
    ('neither', b'success\n', {'PCAPKIT_VENDOR_RUN_ID': UNSET, 'GITHUB_REPOSITORY': UNSET}),
)

#: Each way the ``vendor_update`` shell ends: ``name -> (status,
#: $GITHUB_OUTPUT, its standard output, as a pattern)``.
VENDOR_BRANCHES = {
    'not listed': (0, '', r'::warning title=Vendor Update not read \(#1748\)::could not list the jobs of '),
    'updated': (0, 'updated=true\n', r'$'),
    'updated nothing': (0, 'updated=false\n', r'Vendor Update run \d+ skipped vendor-update: '),
    'not read': (0, '', r'::warning title=Vendor Update not read \(#1748\)::Vendor Update run \d+ reports '),
    'an unset variable': (1, '', r'$'),
}


class _Stand(unittest.TestCase):
    """A scratch directory with the stand-in ``gh`` first on ``PATH``."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(prefix='pcapkit-1967-status-')  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = pathlib.Path(tmp.name)
        self.bin = self.tmp / 'bin'
        self.bin.mkdir()
        (self.bin / 'gh').write_text(FAKE_GH, encoding='utf-8')
        (self.bin / 'gh').chmod(0o755)
        self.work = self.tmp / 'work'
        self.work.mkdir()
        self.output = self.tmp / 'output'
        self.summary = self.tmp / 'summary'
        self.gh_log = self.tmp / 'gh.log'
        self.reply = self.tmp / 'reply'
        self.shell = self.tmp / 'step.sh'

    def env(self, base: 'dict[str, str]', overrides: 'dict[str, Optional[str]]') -> 'dict[str, str]':
        env = {'PATH': f'{self.bin}{os.pathsep}{os.environ.get("PATH", os.defpath)}', 'HOME': str(self.tmp),
               'LC_ALL': 'C', 'GITHUB_OUTPUT': str(self.output), 'GITHUB_STEP_SUMMARY': str(self.summary),
               'GITHUB_REPOSITORY': 'JarryShaw/PyPCAPKit', 'GH_LOG': str(self.gh_log), 'GH_REPLY': str(self.reply),
               **base}
        for name, value in overrides.items():
            if value is UNSET:
                env.pop(name, None)
            else:
                env[name] = value
        return env

    def state(self, command: 'list[str]', env: 'dict[str, str]', reply: 'bytes') -> 'tuple[object, ...]':
        """What ``command`` left: status, both streams, ``$GITHUB_OUTPUT``, ``$GITHUB_STEP_SUMMARY`` and ``gh``'s calls.

        Both files hold a line already, as a job's earlier steps may have left.

        """
        for path in (self.output, self.summary, self.gh_log):
            if path.exists():
                path.unlink()
        self.output.write_text('earlier=1\n', encoding='utf-8')
        self.summary.write_text('earlier\n', encoding='utf-8')
        self.reply.write_bytes(reply)
        result = subprocess.run(command, cwd=self.work, env=env, capture_output=True,  # nosec: B603
                                check=False, timeout=120)
        return (result.returncode, result.stdout.decode('utf-8', 'surrogateescape'),
                result.stderr.decode('utf-8', 'surrogateescape'),
                *(path.read_text(encoding='utf-8', errors='surrogateescape') if path.exists() else None
                  for path in (self.output, self.summary, self.gh_log)))

    def reference(self, shell: 'str', env: 'dict[str, str]', reply: 'bytes' = b'') -> 'tuple[object, ...]':
        """``shell`` as a step with no ``shell:`` runs it, ``bash -e``, its own errors' ``<path>: line N:`` dropped."""
        self.shell.write_text(shell, encoding='utf-8')
        found = self.state(bash_argv('-e', str(self.shell), executable=BASH), env, reply)
        stderr = re.sub(rf'(?m)^{re.escape(str(self.shell))}: line \d+: ', '', str(found[2]))
        return (*found[:2], stderr, *found[3:])

    def run_both(self, shell: 'str', script: 'str', env: 'dict[str, str]',
                 reply: 'bytes' = b'') -> 'tuple[tuple[object, ...], tuple[object, ...]]':
        """The state each leaves: :meth:`reference` on ``shell``, then ``python3 util/<script>`` as its step runs it."""
        return self.reference(shell, env, reply), self.state([sys.executable, str(UTIL / script)], env, reply)

    def branches(self, shell: 'str', cases: 'list[tuple[str, dict[str, str], bytes]]',
                 classify: 'Callable[[tuple[object, ...]], list[str]]') -> 'dict[str, list[str]]':
        """Each case's branch, as ``classify(state)`` names it from ``shell``'s run."""
        reached = {}  # type: dict[str, list[str]]
        for name, env, reply in cases:
            old = self.reference(shell, env, reply)
            branch = classify(old)
            with self.subTest(case=name):
                self.assertEqual(len(branch), 1, f'{name} matches {branch}: {old!r}')
            for found in branch:
                reached.setdefault(found, []).append(name)
        return reached


def status_env_names() -> 'list[str]':
    """The variables ``release_status``'s step's ``env:`` sets, each of them, as Actions does."""
    name = JOBS['release_status'][0]
    return list(next(step for step in steps(WORKFLOW, 'release_status') if step.get('name') == name)['env'])


def sampled_status_cases(count: 'int' = 150) -> 'list[tuple[str, dict[str, Optional[str]]]]':
    """``count`` seeded draws over every variable, weighted towards the branches past the early exits."""
    draw = random.Random(1967)
    results = ['success', 'skipped', 'failure', 'cancelled', '']
    flags = ['true', 'false', '']
    domains = {
        'PCAPKIT_EVENT_NAME': (['workflow_run', 'push', 'schedule', ''], [6, 3, 1, 1]),
        'PCAPKIT_WORKFLOW_RUN_CONCLUSION': (['success', 'skipped', 'failure', ''], [5, 2, 2, 1]),
        'PCAPKIT_VENDOR_UPDATED': (flags, [3, 3, 2]),
        'PCAPKIT_ACTOR_ID': ([BOT, HUMAN, ''], [2, 2, 1]),
        'PCAPKIT_RELEASE_APP_BOT_ID': ([BOT, ''], [3, 1]),
        'PCAPKIT_UNIT_TESTS': (results, [4, 4, 1, 1, 1]),
        'PCAPKIT_VERSION_CHECK': (results, [12, 3, 1, 1, 1]),
        'PCAPKIT_RELEASED_ELSEWHERE': (flags, [2, 4, 1]),
        'PCAPKIT_DEV_RELEASE': (flags, [2, 4, 1]),
        'PCAPKIT_PYPI_KTLO_310': (['', 'success', 'failure'], [4, 1, 1]),
        'PCAPKIT_PYPI_KTLO_PYPY310': (['', 'success', 'failure'], [4, 1, 1]),
        'PCAPKIT_VERSION': (['1.5.0', '1.5.0b12'], [1, 1]),
        'PCAPKIT_RELEASED_AT': ([RUN, OTHER, ''], [1, 2, 1]),
    }
    for job in ('PCAPKIT_GITHUB_JOB', 'PCAPKIT_TAG_JOB', 'PCAPKIT_PYPI_JOB', 'PCAPKIT_CONDA_JOB'):
        domains[job] = (results, [4, 6, 1, 1, 1])
    for evidence in ('PCAPKIT_TAG_EXISTS', 'PCAPKIT_CONDA_TAG_EXISTS', 'PCAPKIT_PYPI_COMPLETE',
                     'PCAPKIT_CONDA_COMPLETE'):
        domains[evidence] = (flags, [6, 3, 1])
    return [(f'sample {index}', {name: draw.choices(values, weights)[0]
                                 for name, (values, weights) in sorted(domains.items())})
            for index in range(count)]


@unittest.skipIf(not BASH, 'needs bash, which runs the reference shell')
class TestTheStepMatchesTheReferenceShell(_Stand):
    """Each script exits, prints, writes and calls exactly as its step's inline shell form, on every case."""

    def status_env(self, overrides: 'dict[str, Optional[str]]') -> 'dict[str, str]':
        base = dict.fromkeys(status_env_names(), '')
        base.update(STATUS_BASE)
        return self.env(base, overrides)

    def test_the_cases_set_what_the_step_sets(self) -> None:
        """The base sets every ``env:`` name, as Actions does, so an unset one is a case's own."""
        self.assertEqual(sorted(STATUS_BASE), sorted(status_env_names()))

    def test_the_release_status(self) -> None:
        for name, overrides in STATUS_CASES + tuple(sampled_status_cases()):
            with self.subTest(case=name):
                old, new = self.run_both(REFERENCE_STATUS, 'release_status.py', self.status_env(overrides))
                self.assertEqual((new[0], ANACONDA_REMEDY.sub('', str(new[1])), *new[2:]), old)

    def test_every_status_branch_is_reached(self) -> None:
        """The curated cases alone reach each of :data:`STATUS_BRANCHES`, each case exactly one."""
        def classify(state: 'tuple[object, ...]') -> 'list[str]':
            # The last annotation, since a value holding a line break splits one.
            status = state[0]
            last = ([line for line in str(state[1]).splitlines() if line.startswith('::')] or [''])[-1]
            return [name for name, (code, pattern) in STATUS_BRANCHES.items()
                    if status == code and re.match(pattern, last)
                    and (name != 'an unset variable' or 'unbound variable' in str(state[2]))]
        reached = self.branches(REFERENCE_STATUS,
                                [(name, self.status_env(overrides), b'') for name, overrides in STATUS_CASES],
                                classify)
        self.assertEqual(sorted(reached), sorted(STATUS_BRANCHES))

    def test_the_samples_reach_past_the_early_exits(self) -> None:
        """So agreement on them is agreement on the reconciliation, not only on case 1."""
        titles = set()
        for _, overrides in sampled_status_cases():
            stdout = str(self.reference(REFERENCE_STATUS, self.status_env(overrides))[1])
            titles.add(stdout.splitlines()[-1].split('::', 2)[1])
        for title in ('notice title=Release complete', 'warning title=Release did not complete',
                      'error title=Stranded partial release (#888)', 'notice title=Nothing to release'):
            with self.subTest(title=title):
                self.assertIn(title, titles)


@unittest.skipIf(not BASH, 'needs bash, which runs the step')
class TestTheVendorUpdateStaysInline(_Stand):
    """``vendor_update`` runs its shell inline (#1967), and that shell ends each way it should."""

    def setUp(self) -> None:
        super().setUp()
        self.found = steps(WORKFLOW, 'vendor_update')

    def vendor_env(self, overrides: 'dict[str, Optional[str]]') -> 'dict[str, str]':
        return self.env({'GH_TOKEN': 'not-a-token', 'PCAPKIT_VENDOR_RUN_ID': '38650191283'}, overrides)

    def test_the_step_holds_its_shell_and_nothing_checks_out(self) -> None:
        self.assertEqual([step.get('name') for step in self.found], [VENDOR_STEP])
        self.assertEqual(self.found[0]['run'], VENDOR_SHELL)
        self.assertEqual(load(WORKFLOW)['jobs']['vendor_update']['permissions'], VENDOR_PERMISSIONS)

    def test_every_branch_is_reached(self) -> None:
        """Each case of :data:`VENDOR_CASES` ends one way, and between them every way."""
        def classify(state: 'tuple[object, ...]') -> 'list[str]':
            status, stdout, stderr, output = state[0], str(state[1]), str(state[2]), state[3]
            written = str(output)[len('earlier=1\n'):] if output is not None else ''
            return [name for name, (code, lines, pattern) in VENDOR_BRANCHES.items()
                    if status == code and written == lines and re.match(pattern, stdout)
                    and (pattern != '$' or stdout == '')
                    and (name != 'an unset variable' or 'unbound variable' in stderr)]
        reached = self.branches(self.found[0]['run'],
                                [(name, self.vendor_env(overrides), reply) for name, reply, overrides in VENDOR_CASES],
                                classify)
        self.assertEqual(sorted(reached), sorted(VENDOR_BRANCHES))


class TestTheStepsRunTheScripts(unittest.TestCase):
    """The job checks out :file:`util/` alone, at this run's commit, and runs its script on the image's ``python3``."""

    def test_each_job_checks_out_util_then_runs_its_script(self) -> None:
        blocks = job_blocks((ROOT / '.github' / 'workflows' / WORKFLOW).read_text(encoding='utf-8'))
        pin = next(step['uses'] for step in steps(WORKFLOW, 'version_check')
                   if str(step.get('uses', '')).startswith('actions/checkout@'))
        for job, (name, run, permissions) in sorted(JOBS.items()):
            found = steps(WORKFLOW, job)
            with self.subTest(job=job):
                self.assertEqual([step.get('name') for step in found], ['Checkout code', name])
                self.assertEqual(found[0]['uses'], pin)
                self.assertEqual(found[0]['with'], CHECKOUT)
                self.assertIn(f'uses: {pin} # v', blocks[job])
                self.assertEqual(found[1]['run'], run)
                self.assertEqual(load(WORKFLOW)['jobs'][job]['permissions'], permissions)
                self.assertFalse([step for step in found if 'setup-python' in str(step.get('uses', ''))])

    def test_no_step_holds_the_reference_shell(self) -> None:
        for job, found in sorted(load(WORKFLOW)['jobs'].items()):
            for step in found.get('steps', []):
                for line in ('reconciled_github', 'Stranded partial release'):
                    with self.subTest(job=job, step=step.get('name'), line=line):
                        self.assertNotIn(line, step.get('run', ''))

    def test_the_scripts_need_only_util_and_python_3_8(self) -> None:
        """The sparse checkout holds :file:`util/`, and the image's ``python3`` nothing installed.

        ``feature_version`` is best-effort on a newer interpreter, so the 3.8
        compat leg's ``Compile the 3.8-floor util scripts`` is the authoritative
        check (#2206).

        """
        allowed = {'__future__', 'argparse', 'os', 'subprocess', 'sys', 'typing', '_actions', 'util'}
        for name in ('release_status.py',):
            with self.subTest(script=name):
                tree = ast.parse((UTIL / name).read_text(encoding='utf-8'), feature_version=FLOOR)
                imported = {alias.name.split('.')[0] for node in ast.walk(tree) if isinstance(node, ast.Import)
                            for alias in node.names}
                imported |= {str(node.module).split('.')[0] for node in ast.walk(tree)
                             if isinstance(node, ast.ImportFrom)}
                self.assertLessEqual(imported, allowed)


if __name__ == '__main__':
    unittest.main()
