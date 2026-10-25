# -*- coding: utf-8 -*-
"""Why a Create Release run did or did not release anything (#888), in one place.

:file:`.github/workflows/create-release.yml`'s ``release_status`` job runs it as
``python3 util/release_status.py``, the step "Report why this run did or did not
release anything". ``version_check`` can skip before any evidence exists, and
``unit-tests`` can fail or skip (#1052), so it reconstructs the outcome from the
``needs.*.result`` values and the trigger its ``env:`` passes in, and reports it
as one annotation. Only the stranded partial release, a target skipped despite
its own evidence saying it is not done, exits 1; every other outcome exits 0.

In order, the first that applies:

1. ``version_check`` skipped: why, quiet where the trigger had nothing to do --
   the release App's own tag push (#1634), a Vendor Update that concluded
   ``skipped``, one that skipped ``vendor-update`` (#1748), or a manual one,
   which builds only -- and a warning otherwise.
2. ``version_check`` did not succeed: a warning.
3. The release test gate failed or was cancelled: a warning.
4. The version is tagged at another commit and every publisher skipped (#1748):
   a notice if that release is complete, else a warning naming what it lacks,
   and, for Anaconda files, Conda Update's ``publish`` dispatch (#2140).
5. Each publisher reconciled against its own evidence -- succeeded, or skipped
   with its evidence saying done: a notice if all reconciled, a warning if one
   failed or was cancelled, and otherwise the ``::error``.

Before any of them, a notice reports ``pypi``'s KTLO legs where either recorded
an outcome (#1633), since neither reaches ``needs.pypi.result``.

The step formerly held this as shell, run under ``set -euo pipefail``; this
prints the same annotations, unescaped as ``echo`` wrote them. A variable the
step's ``env:`` names that is unset, which Actions never leaves it, ends the
script with ``<name>: unbound variable`` and status 1 at the point the shell's
``set -u`` would have, rather than with a traceback.

The job checks out only :file:`util/` and has no setup-python, so this runs on
the image's ``python3``: standard library only, and Python 3.8's syntax.

"""

from __future__ import annotations

import argparse
import os
import sys
from typing import TYPE_CHECKING

try:  # #2047: run as `python util/<script>.py`, with util/ first on sys.path
    import _actions
except ImportError:  # imported as util.<script>, or loaded by path, from the repository root
    from util import _actions

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['Unbound', 'var', 'report', 'main']

#: The publishers, by the variable carrying each one's ``needs.<job>.result``,
#: and the evidence output that says its artefact already exists.
TARGETS = (
    ('PCAPKIT_GITHUB_JOB', 'PCAPKIT_TAG_EXISTS'),
    ('PCAPKIT_TAG_JOB', 'PCAPKIT_CONDA_TAG_EXISTS'),
    ('PCAPKIT_PYPI_JOB', 'PCAPKIT_PYPI_COMPLETE'),
    ('PCAPKIT_CONDA_JOB', 'PCAPKIT_CONDA_COMPLETE'),
)


class Unbound(Exception):
    """A variable read as ``$NAME`` that is unset, which ``set -u`` refused."""


def var(name: 'str') -> 'str':
    """``$name``; :exc:`Unbound` where it is unset."""
    try:
        return os.environ[name]
    except KeyError:
        raise Unbound(name) from None


def say(level: 'str', title: 'str', message: 'str') -> 'None':
    """Print the ``::level`` annotation as the shell's ``echo`` did, unescaped."""
    _actions.say(_actions.annotation(level, message, title=title, escape=False))


def reconciled(job: 'str', evidence: 'str') -> 'bool':
    """Whether ``$job`` succeeded, or skipped with ``$evidence`` reading ``true``."""
    return var(job) == 'success' or (var(job) == 'skipped' and var(evidence) == 'true')


def skipped_version_check() -> 'None':
    """Case 1: why ``version_check`` skipped."""
    event = var('PCAPKIT_EVENT_NAME')
    if event == 'push' and var('PCAPKIT_RELEASE_APP_BOT_ID') \
            and var('PCAPKIT_ACTOR_ID') == var('PCAPKIT_RELEASE_APP_BOT_ID'):
        say('notice', 'Nothing to release', "the release App's bot pushed this tag from the Create Release run "
                                            'that released its commit, so this run correctly released nothing '
                                            '(#1634).')
    elif var('PCAPKIT_EVENT_NAME') == 'workflow_run' \
            and os.environ.get('PCAPKIT_WORKFLOW_RUN_EVENT', '') == 'workflow_dispatch':
        say('notice', 'Nothing to release', 'the triggering Vendor Update run was a manual, build-only run, '
                                            'which pushes nothing, so this run correctly released nothing.')
    elif var('PCAPKIT_EVENT_NAME') == 'workflow_run' and var('PCAPKIT_WORKFLOW_RUN_CONCLUSION') == 'skipped':
        say('notice', 'Nothing to release', 'the triggering Vendor Update run found nothing to update, so this '
                                            'run correctly released nothing.')
    elif var('PCAPKIT_EVENT_NAME') == 'workflow_run' and var('PCAPKIT_WORKFLOW_RUN_CONCLUSION') == 'success' \
            and os.environ.get('PCAPKIT_VENDOR_UPDATED', '') == 'false':
        say('notice', 'Nothing to release', 'the triggering Vendor Update run skipped vendor-update, since its '
                                            'Unit Tests verdict did not cover the commit it checked out, so it '
                                            'updated nothing and this run correctly released nothing (#1748).')
    elif var('PCAPKIT_EVENT_NAME') == 'workflow_run':
        say('warning', 'Release skipped', 'the triggering Vendor Update run concluded '
                                          f"'{var('PCAPKIT_WORKFLOW_RUN_CONCLUSION')}', not 'success', so "
                                          'version_check, the release test gate and every release job were '
                                          'skipped. Not #888 -- no tag was created that could be left stranded '
                                          '-- but Vendor Update likely needs attention.')
    else:
        say('warning', 'Release skipped for an unexpected reason',
            f"version_check reported 'skipped' with event_name='{var('PCAPKIT_EVENT_NAME')}', which is not the "
            "workflow_run non-success case this job otherwise expects. Check the version_check job's own if: "
            'condition.')


def released_elsewhere() -> 'bool':
    """#1748: whether the version is another commit's, with every publisher skipped for it."""
    return (os.environ.get('PCAPKIT_RELEASED_ELSEWHERE', '') == 'true'
            and all(var(job) == 'skipped' for job, _ in TARGETS))


def report_elsewhere() -> 'None':
    """Case 4: the other commit's release, complete or not; both green."""
    missing = []
    if var('PCAPKIT_CONDA_TAG_EXISTS') != 'true':
        missing.append(f"the conda-{var('PCAPKIT_VERSION')}+0 tag")
    if var('PCAPKIT_PYPI_COMPLETE') != 'true':
        missing.append('some of its PyPI files')
    if var('PCAPKIT_CONDA_COMPLETE') != 'true':
        missing.append('some of its Anaconda files')
    if not missing:
        say('notice', 'Nothing to release',
            f"v{var('PCAPKIT_VERSION')} names {var('PCAPKIT_RELEASED_AT')}, not this run's commit "
            f"{var('PCAPKIT_RUN_SHA')}, and that release is complete, so this run correctly released nothing "
            '(#1748).')
        return
    version = var('PCAPKIT_VERSION')
    # #2140: the re-run repeats the tagged commit's own conda legs, so it cannot
    # upload what they could not build -- 1.5.0b14's osx-64, broken at its tag.
    # Conda Update's `publish` dispatch builds main instead (#2060).
    anaconda = (f" Its Anaconda files are the exception: while main's version is still {version}, dispatch Conda "
                'Update with publish on main, which uploads every platform under a bumped build (#2060); the '
                "re-run finishes them only if that run's own conda legs can still succeed."
                if var('PCAPKIT_CONDA_COMPLETE') != 'true' else '')
    say('warning', f'v{version} is unfinished (#1634)',
        f"v{var('PCAPKIT_VERSION')} names {var('PCAPKIT_RELEASED_AT')}, not this run's commit "
        f"{var('PCAPKIT_RUN_SHA')}, and still lacks {', '.join(missing)}. Only that commit's run may finish it "
        '(#1634), so this run released nothing: re-run the Create Release run created for '
        f"{var('PCAPKIT_RELEASED_AT')}, or release the next version.{anaconda}")


def jobs() -> 'str':
    """``github=... tag=... pypi=... conda=...``, each publisher's result."""
    return (f"github={var('PCAPKIT_GITHUB_JOB')} tag={var('PCAPKIT_TAG_JOB')} pypi={var('PCAPKIT_PYPI_JOB')} "
            f"conda={var('PCAPKIT_CONDA_JOB')}")


def report() -> 'int':
    """Print the run's outcome; the exit status."""
    ktlo_310 = os.environ.get('PCAPKIT_PYPI_KTLO_310', '')
    ktlo_pypy310 = os.environ.get('PCAPKIT_PYPI_KTLO_PYPY310', '')
    if ktlo_310 or ktlo_pypy310:
        say('notice', 'KTLO legs (non-blocking)',
            f"pypi 3.10={ktlo_310 or 'not run'} pypy3.10={ktlo_pypy310 or 'not run'}. End-of-life Python, built "
            "and published but never blocking (#1633); neither result changes this run's verdict.")

    if var('PCAPKIT_VERSION_CHECK') == 'skipped':
        skipped_version_check()
        return 0

    if var('PCAPKIT_VERSION_CHECK') != 'success':
        say('warning', 'Release blocked before it could start',
            f"version_check did not succeed (result: '{var('PCAPKIT_VERSION_CHECK')}'), so neither the release "
            'test gate nor any release job ran. This is a workflow failure, not #888.')
        return 0

    if var('PCAPKIT_UNIT_TESTS') in ('failure', 'cancelled'):
        say('warning', 'Release blocked by the test gate',
            f"the release test gate concluded '{var('PCAPKIT_UNIT_TESTS')}', so no release job ran for "
            f"{var('PCAPKIT_VERSION')}. This is a test failure, not #888.")
        return 0

    if released_elsewhere():
        report_elsewhere()
        return 0

    # Reconcile each job against its OWN evidence, not against each other: a
    # self-heal mixes jobs that skipped because their artefact existed with jobs
    # that ran, and demanding uniformity would read that mix as #888.
    all_reconciled = all([reconciled(job, evidence) for job, evidence in TARGETS])
    results = [var(job) for job, _ in TARGETS]
    all_skipped = all(result == 'skipped' for result in results)
    any_broken = any(result in ('failure', 'cancelled') for result in results)

    if all_reconciled and all_skipped:
        say('notice', 'Nothing to release',
            f"pypcapkit {var('PCAPKIT_VERSION')} is already fully released -- the v* tag, the conda-*+0 tag and "
            'every PyPI and Anaconda file version_check expects are present. This run correctly released '
            'nothing.')
        return 0

    if all_reconciled:
        say('notice', 'Release complete',
            f"pypcapkit {var('PCAPKIT_VERSION')} is now fully released -- {jobs()}. A 'skipped' entry there "
            "means that target's own artefact already existed before this run, not that anything was missed.")
        return 0

    if any_broken:
        say('warning', 'Release did not complete',
            f"{jobs()} for {var('PCAPKIT_VERSION')}. At least one release job failed or was cancelled outright "
            "-- see its own log; this run's checks already show that failure in red.")
        return 0

    # The #888 shape: a target skipped despite its own evidence saying
    # incomplete, with nothing failed or cancelled to explain it. Loud, and
    # never green.
    say('error', 'Stranded partial release (#888)',
        f"{var('PCAPKIT_VERSION')} is only partially published (tag exists={var('PCAPKIT_TAG_EXISTS')}, conda "
        f"tag exists={var('PCAPKIT_CONDA_TAG_EXISTS')}, pypi complete={var('PCAPKIT_PYPI_COMPLETE')}, conda "
        f"complete={var('PCAPKIT_CONDA_COMPLETE')}) but {jobs()} -- at least one target skipped despite its own "
        'evidence saying it is not done. Re-running this workflow should let the incomplete jobs self-heal; if '
        'this recurs on the next run too, the evidence checks in version_check are the first thing to check.')
    return 1


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Report the run's outcome from the step's ``env:``; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.parse_args(argv)
    try:
        return report()
    except Unbound as error:
        sys.stdout.flush()
        print(f'{error}: unbound variable', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    sys.exit(main())
