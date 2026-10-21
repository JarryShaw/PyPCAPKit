# -*- coding: utf-8 -*-
"""The check that a free-threaded CI leg ran its tests with the GIL off (#1958).

Free-threaded CPython 3.14t is a supported leg of :file:`unit-tests.yml`'s
``test`` and ``integration`` jobs, by the owner's ruling on #1958 that its tests
run with the GIL truly off. An extension module that does not declare
``Py_mod_gil`` turns the GIL back on when it is imported -- ``lxml.etree``, by
way of :mod:`bs4`, did so in every experimental run before the promotion -- so
those legs set ``PYTHON_GIL=0`` and install no ``lxml``. This module is what
fails such a leg if either stops holding: :func:`tests.conftest.pytest_runtest_makereport`
asks :func:`failure` after each test's teardown, in every process, xdist
workers included.

It enforces on a free-threaded build under GitHub Actions alone
(:func:`enforced`), so a local free-threaded run that imports such a module is
left to the interpreter's own ``RuntimeWarning``. Only the first test after which
the GIL is found on fails, once per process: it stays on from then.

"""

from __future__ import annotations

import os
import sys
import sysconfig
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable, Mapping, Optional

#: Whether this process has already failed a test for the GIL.
_reported = False


def free_threaded() -> 'bool':
    """Whether this interpreter is a free-threaded build, by ``Py_GIL_DISABLED``."""
    return bool(sysconfig.get_config_var('Py_GIL_DISABLED'))


def enforced(environ: 'Optional[Mapping[str, str]]' = None) -> 'bool':
    """Whether this process must keep the GIL off: a free-threaded build, under GitHub Actions."""
    environ = os.environ if environ is None else environ
    return free_threaded() and environ.get('GITHUB_ACTIONS') == 'true'


def gil_enabled() -> 'bool':
    """``sys._is_gil_enabled()``, which every free-threaded build has (3.13+)."""
    return sys._is_gil_enabled()  # type: ignore[attr-defined]


def failure(when: 'str', nodeid: 'str', *, enforce: 'Optional[Callable[[], bool]]' = None,
            probe: 'Optional[Callable[[], bool]]' = None) -> 'Optional[str]':
    """The failure to report for ``nodeid``'s phase ``when``, if the GIL is on where it must not be.

    Args:
        when: The report's phase; only ``'teardown'`` is checked, once the test
            and its fixtures have run.
        nodeid: The test just run, named in the message.
        enforce: :func:`enforced`, replaceable for the tests of this module.
        probe: :func:`gil_enabled`, likewise.

    Returns:
        The message, the first time a teardown finds the GIL on in this
        process; :data:`None` otherwise.

    """
    global _reported
    if when != 'teardown' or _reported or not (enforce or enforced)():
        return None
    if not (probe or gil_enabled)():
        return None
    _reported = True
    return (f'The GIL is on in this free-threaded process, found after {nodeid}: a module imported by now '
            'turned it back on. The free-threaded legs keep it off with PYTHON_GIL=0 and install no lxml '
            "(#1958); check that the job's env still sets PYTHON_GIL=0, and which extension module "
            'without Py_mod_gil the tests now import.')
