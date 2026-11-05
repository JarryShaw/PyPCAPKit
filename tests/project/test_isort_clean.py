# -*- coding: utf-8 -*-
"""Pins ``make isort`` clean on every one of its lines (#757).

Each line of the Makefile's ``isort:`` target, one :data:`MAKEFILE_LINES` entry per
line, runs as a real ``isort`` with that line's exact flags, so an unsorted or
mis-wrapped import anywhere ``make isort`` reaches fails here rather than going
"clean locally, red in CI" as #757 did.

The width is 100, as :file:`CONTRIBUTING.md` documents ("120 for ``pylint`` and 100
for ``isort``, not PEP 8's 79"), a deliberate split. #757 came from a bare
``isort --check-only --diff pcapkit/protocols/schema.py``, which wraps at isort's
default 79 and so flagged an 89-character import the Makefile accepts; this module
does not re-litigate the width.

Every line is covered, not only the whole-tree one. That line (:file:`pcapkit`,
skipping ``__init__.py``) reaches neither :file:`examples/generators/` nor
:file:`util/`, which the last line sorts, nor the ``__init__.py`` files at least one
directory below :file:`pcapkit/const/` or :file:`pcapkit/vendor/`, which the const
and vendor lines, having no ``--skip-glob``, re-cover. Their shape closes these
gaps (#765):

* **Any depth.** A brace-expanded ``pcapkit/{const,vendor}/*/*.py`` stops at two
  levels, missing :file:`pcapkit/const/reg/apptype/__init__.py`. A ``**`` glob under
  ``shopt -s globstar`` needs bash >= 4.0, but :file:`Makefile`'s ``SHELL := $(shell
  command -v bash ...)`` takes whichever ``bash`` is on ``$PATH``, and macOS ships
  3.2 as ``/bin/bash``. There ``shopt`` fails and the next command still runs with
  the non-recursive glob, silently, since make judges the recipe line by the isort
  invocation after it. ``find`` reaches any depth on any bash.
* **One invocation per directory.** Handed to one ``isort``, the two ``find``
  calls fail loudly only when *both* are empty (``isort`` gets no paths and exits
  1); with one empty, ``isort`` exits 0 having sorted half the tree. Neither is
  reachable today, but one call per directory rules it out, matching
  :file:`.github/workflows/cron-vendor.yml`'s two calls.
* **``-mindepth 2``.** Keeps ``find`` off :file:`pcapkit/const/__init__.py` and
  :file:`pcapkit/vendor/__init__.py`, whose hand-grouped import order isort would
  flatten; see :func:`_const_targets` and :func:`_vendor_targets`.

:file:`.github/workflows/cron-vendor.yml` sorts the deep files the same way for the
same reason (#765): it writes them, as ``pcapkit-vendor`` regenerates
:mod:`pcapkit.const` from the :mod:`pcapkit.vendor` crawlers, on ``macos-latest``.
This module does not cover that job: its ``vendor-update`` job never runs
``make isort``, and runs only :file:`tests/const` and :file:`tests/vendor` before it
commits (#1853).

The gate and the install line go together (#766). The gate is a module-level
:data:`HAS_ISORT` read by ``@unittest.skipUnless``, not a ``try: import isort``
raising :exc:`~unittest.SkipTest` in
:meth:`~TestIsortIsCleanOnThePackage.setUpClass`, because
:func:`tests._dependency_gates._gates_of` walks a definition's ``decorator_list``,
never a function body; an inline ``skipTest`` would be the dark test #745 exists to
stop, which #779 avoids the same way for ``mypy``.

``isort`` is a ``test`` extra requirement, so the pytest jobs collecting this module,
``project-tests`` and ``gate`` but not ``engine-tests`` (#849), run it rather than
skip. ``mypy``'s :data:`~tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS` entry
declines the install line instead because :file:`lint.yml` already runs ``make mypy``,
while that workflow's header records that ``isort`` is deliberately not a linter it
installs; it appears only in :file:`cron-vendor.yml`, as a formatter. Declining here
would leave ``make isort`` checked nowhere, which #766 objected to, and the run is
cheap.

``isort`` is also in ``Pipfile``'s ``[dev-packages]`` (#810), which ``make isort``'s
``pipenv run`` prefix resolves against. The two are additive: the ``pyproject.toml``
extra serves those installing the package, ``Pipfile`` this repository's dev
environment.

"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import pathlib
import re
import subprocess
import sys
import unittest
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Optional

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'pcapkit'
MAKEFILE = ROOT / 'Makefile'

#: Whether :mod:`isort` is importable, for the one test that runs it. A visible
#: ``skipUnless`` flag rather than an inline ``skipTest`` (#766), so
#: :func:`~tests._dependency_gates.gated_scopes` counts the gate and
#: :mod:`tests.test_tier_guard` can audit which CI jobs it darkens: none, as the
#: ``test`` extra carries isort.
HAS_ISORT = importlib.util.find_spec('isort') is not None

#: The oldest isort whose verdict on this tree the test below was written for
#: (#1696). The ``test`` extra leaves isort unpinned (the comment above it in
#: :file:`pyproject.toml` says why), so each CI leg gets the newest release its
#: Python can install: 5.13.2 on 3.8, 6.1.0 on 3.9, 9.x from 3.10. The older
#: ones place blank lines around function-body ``# isort:skip`` imports
#: differently from 9.x, so they call a tree red that 9.x calls clean.
#:
#: Bisected on CPython 3.10.21, one fresh venv per release, each recipe line run as
#: the test runs it (``python -m isort --check-only`` plus that line's flags):
#:
#: * 5.13.2, 6.1.0, 7.0.0, 8.0.0 -- red on the whole-tree line, in five files
#:   (``scapy.py``, ``pyshark.py`` and ``dpkt.py`` under
#:   :file:`pcapkit/foundation/engines/`, :file:`pcapkit/protocols/protocol.py`,
#:   :file:`pcapkit/protocols/application/http/protocol.py`): ten blank lines after
#:   ``# isort:skip`` imports to drop, and one to add in ``dpkt.py``.
#:   5.13.2 on 3.8.20 and 6.1.0 on 3.9.25 flag the same five, so the verdict
#:   follows the isort release, not the Python.
#: * 8.0.1, 9.0.0a2, 9.0.0a3 -- red on ``dpkt.py`` only: the one added line.
#: * 9.0.0b1, 9.0.0b2 -- clean. This is where the verdict moved.
#: * 9.0.0b5, 9.0.0 -- cannot run. Both ship ``isort/__main__`` compiled to an
#:   extension module, and ``python -m isort`` stops at "No code object
#:   available for isort.__main__". Their ``isort`` console script calls all
#:   four lines clean, but this test runs the module.
#: * 9.0.1, 9.0.2 -- clean, on all four lines.
#:
#: So 9.0.1 is the first final release this test gets a verdict from. Anything
#: older skips, the 9.0.0 pre-releases included, and a later release whose verdict
#: moves still turns the test red, as :file:`pyproject.toml` intends.
ISORT_FLOOR = (9, 0, 1)


def _isort_version() -> 'Optional[str]':
    """The installed isort's version, read from its distribution metadata
    rather than by importing it; :data:`None` when there is none to read.

    """
    if not HAS_ISORT:
        return None
    try:
        return importlib.metadata.version('isort')
    except importlib.metadata.PackageNotFoundError:
        return None


def _predates_floor(version: 'Optional[str]') -> 'bool':
    """Whether ``version`` is older than :data:`ISORT_FLOOR`, by its numeric
    release segment alone -- ``9.0.0b5`` counts as ``9.0.0``, and a
    pre-release of the floor itself would count as the floor (isort has
    published none). An absent or unparsable version is not older, so the
    test runs rather than skipping on no evidence.

    """
    match = re.match(r'\d+(?:\.\d+)*', version or '')
    if match is None:
        return False
    return tuple(int(part) for part in match.group().split('.')) < ISORT_FLOOR


ISORT_VERSION = _isort_version()
ISORT_TOO_OLD = _predates_floor(ISORT_VERSION)


def _pcapkit_tree_targets() -> 'list[str]':
    """``pcapkit $(wildcard temp/sort.py)`` -- the scratch file is untracked
    and normally absent, so this mirrors make's ``$(wildcard ...)`` by only
    adding it when it actually exists.

    """
    targets = [str(PACKAGE)]
    scratch = ROOT / 'temp' / 'sort.py'
    if scratch.exists():
        targets.append(str(scratch))
    return targets


def _find_mindepth_2_targets(sub: str) -> 'list[str]':
    """``$(find pcapkit/<sub> -mindepth 2 -name '*.py')`` (#765).

    ``Path.glob('*/**/*.py')`` matches the set ``find -mindepth 2`` does, at least
    one subdirectory below ``<sub>`` and then any depth, with no shell to depend on.
    The leading ``*/`` is deliberate: a bare ``**/*.py`` would reach
    :file:`pcapkit/<sub>/__init__.py`, whose hand-grouped, commented import order
    (``# base crawler``, only under ``vendor``; ``# IANA registration``,
    ``# Miscellanous`` and ``# per protocol`` under both) isort's ``-l100 -ppcapkit``
    would flatten into one alphabetical block, as ``isort --diff`` confirms. Neither
    this call nor the whole-tree line, which skips every ``__init__.py``, reaches
    that file.

    """
    return sorted(str(path) for path in (PACKAGE / sub).glob('*/**/*.py'))


def _const_targets() -> 'list[str]':
    """``pcapkit/const/`` half of the pair :func:`_find_mindepth_2_targets` describes.

    On its own line (#765), matching :file:`cron-vendor.yml`'s separate calls for
    ``const`` and ``vendor``.

    """
    return _find_mindepth_2_targets('const')


def _vendor_targets() -> 'list[str]':
    """``pcapkit/vendor/`` half of the pair described in
    :func:`_find_mindepth_2_targets`.

    """
    return _find_mindepth_2_targets('vendor')


def _util_examples_targets() -> 'list[str]':
    """``util/*.py examples/generators/*.py``, expanded the way bash would."""
    targets = sorted(str(path) for path in (ROOT / 'util').glob('*.py'))
    targets.extend(sorted(str(path) for path in (ROOT / 'examples' / 'generators').glob('*.py')))
    return targets


def _isort_recipe_line_numbers() -> 'list[int]':
    """The 1-indexed line numbers of the Makefile's ``isort:`` recipe lines.

    Read from :file:`Makefile` on every run rather than hardcoded, since a
    hardcoded number rots silently once a comment above the target grows. So no
    function below is named after a line; :data:`MAKEFILE_LINES` pairs each number
    with its callable by position.

    A recipe line begins with a tab and follows ``isort:``, another such line, a
    blank line, or a column-0 comment: ``make -n isort`` reports the same commands
    with either of the last two between recipe lines, so make treats them as
    transparent. The first other line not tab-indented ends the target.

    ``isort:`` must match the *whole* line, so an ``isort-check:`` target or a
    ``.PHONY: isort`` line is not mistaken for it. A ``define``/``endef`` body
    holding a bare ``isort:`` at column 0 is undefended; nothing in this file uses
    ``define``.

    """
    lines = MAKEFILE.read_text().splitlines()
    numbers = []  # type: list[int]
    in_target = False
    for lineno, text in enumerate(lines, start=1):
        if text == 'isort:':
            in_target = True
            continue
        if not in_target:
            continue
        if text.startswith('\t'):
            numbers.append(lineno)
        elif not text.strip() or text.lstrip().startswith('#'):
            continue
        else:
            break
    return numbers


#: One entry per recipe line of the Makefile's ``isort:`` target, in order, as the
#: flags before the targets and the callable resolving those targets on this
#: checkout. A list, not a dict keyed by line number (see
#: :func:`_isort_recipe_line_numbers`).
#:
#: Kept matched to the Makefile, since a flag changed on one side only is how
#: "clean locally, red in CI" starts; but the length check catches only a recipe
#: *line* added or removed without an entry. Flags and targets here are literals,
#: never read back from :file:`Makefile`, so a flag edited there (``-l100`` to
#: ``-l120``, say) goes unnoticed. A wrong line number is cheap for the same
#: reason: it only labels a subtest's failure message, and never decides what
#: isort is asked to check.
MAKEFILE_LINES = [
    (['-l100', '-ppcapkit', '--skip-glob', '**/__init__.py'], _pcapkit_tree_targets),
    (['-l100', '-ppcapkit'], _const_targets),
    (['-l100', '-ppcapkit'], _vendor_targets),
    (['-l100', '-ppcapkit'], _util_examples_targets),
]


@unittest.skipUnless(HAS_ISORT, 'isort is not installed')
class TestIsortIsCleanOnThePackage(unittest.TestCase):
    """``make isort`` must not be red on a clean checkout, on any of its
    lines (#757).

    """

    @unittest.skipIf(ISORT_TOO_OLD,
                     f'isort {ISORT_VERSION} predates '
                     f"{'.'.join(map(str, ISORT_FLOOR))}, the oldest release whose "
                     f'verdict on this tree the test was written for (#1696)')
    def test_check_only_is_clean_on_every_makefile_line(self) -> None:
        """Each line of the Makefile's ``isort:`` target, run the way it runs."""
        line_numbers = _isort_recipe_line_numbers()
        self.assertEqual(
            len(line_numbers), len(MAKEFILE_LINES),
            f"Makefile's isort: target has {len(line_numbers)} recipe line(s) "
            f'now (at {line_numbers}), not {len(MAKEFILE_LINES)} -- '
            f'MAKEFILE_LINES needs an entry added or removed to match'
        )

        for line, (flags, targets_fn) in zip(line_numbers, MAKEFILE_LINES):
            with self.subTest(makefile_line=line):
                targets = targets_fn()
                self.assertTrue(targets, f'Makefile:{line} resolved to no targets on this '
                                          f'checkout -- the glob is broken, not clean')

                result = subprocess.run(
                    [sys.executable, '-m', 'isort', '--check-only', *flags, *targets],
                    cwd=ROOT, capture_output=True, text=True, check=False,
                )
                self.assertEqual(
                    result.returncode, 0,
                    f'`make isort` is red on a clean checkout -- Makefile:{line} wants '
                    f'changes:\n{result.stdout}{result.stderr}',
                )


if __name__ == '__main__':
    unittest.main()
