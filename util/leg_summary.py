# -*- coding: utf-8 -*-
"""The last step of every non-blocking matrix job: one warning per failed step (#1672, #1660).

Each step that can fail on a KTLO or experimental leg carries an ``id`` and a
``continue-on-error`` that holds on that leg, so its failure leaves the job, and
``required-checks``, at success. This script makes the failure visible again. The
``KTLO summary`` steps of :file:`.github/workflows/unit-tests.yml`'s ``test``,
``integration`` and ``pypcap-parity`` jobs and :file:`.github/workflows/python-compatibility.yml`'s
``compatibility`` job, and the ``Experimental summary`` step of
:file:`.github/workflows/experimental.yml`'s ``experimental`` job, each run::

    /usr/bin/python3 util/leg_summary.py ktlo          # or: experimental

with ``LEG``, the leg's display name, and ``STEPS``, ``${{ toJSON(steps) }}``, in
the environment. ``STEPS`` holds each earlier step with an ``id``, and its
``outcome`` is the step's result before ``continue-on-error`` applied. For each
step whose ``outcome`` is ``failure``, in the order ``STEPS`` lists them, it writes
one ``::warning`` annotation to standard output and one line to
``$GITHUB_STEP_SUMMARY``. With none, it says so and writes nothing else.

The step runs the image's own interpreter rather than the leg's, since the leg's
setup-python may have failed or installed an interpreter too broken to run this.
So the script is standard library only. It exits 0 unless ``STEPS`` is not the
JSON the runner writes, or the tier is unknown.

"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any, Optional

__all__ = ['REASONS', 'failed_steps', 'main']

#: Why each tier's warning says the job still succeeds, by the tier's argument.
REASONS = {
    'ktlo': 'KTLO legs never block (#1633), so this job still succeeds (#1672)',
    'experimental': 'Experimental legs never block (#1660), so this job still succeeds',
}


def failed_steps(steps: 'dict[str, Any]') -> 'list[str]':
    """The ``id`` of each step in ``steps``, ``toJSON(steps)`` parsed, whose ``outcome`` is ``failure``."""
    return [key for key, value in steps.items() if value['outcome'] == 'failure']


def main(argv: 'Optional[list[str]]' = None) -> 'int':
    """Report each failed step of the leg ``$LEG`` from ``$STEPS``; the exit status."""
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('tier', choices=sorted(REASONS), help='the tier of the leg, which words the warning')
    args = parser.parse_args(argv)

    leg = os.environ['LEG']
    failed = failed_steps(json.loads(os.environ['STEPS']))
    if not failed:
        print(f'{leg}: no step failed.')
        return 0
    # The runner splits an annotation's properties on `,`, so the title's are escaped.
    title = leg.replace(',', '%2C')
    with open(os.environ['GITHUB_STEP_SUMMARY'], 'a', encoding='utf-8') as summary:
        for step in failed:
            print(f"::warning title={step} failed on {title}::{REASONS[args.tier]}; see the {step} step's log.")
            print(f'- {leg}: step `{step}` failed; non-blocking, so this job still succeeds.', file=summary)
    return 0


if __name__ == '__main__':
    sys.exit(main())
