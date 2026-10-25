# -*- coding: utf-8 -*-
"""Pins ``make isort`` clean on every one of its lines (#757).

Each line of the Makefile's ``isort:`` target -- see :data:`MAKEFILE_LINES`
below, one entry per line -- is run as a real ``isort`` invocation with that
line's exact flags, not a hand-rolled guess about what those flags imply, so an
edit that introduces an unsorted or mis-wrapped import anywhere ``make isort``
reaches fails here instead of surfacing as "clean locally, red in CI" the way
#757 did.

Those flags set the width to 100, exactly as :file:`CONTRIBUTING.md` documents
("120 for ``pylint`` and 100 for ``isort``, not PEP 8's 79"): a deliberate,
written-down split, not a misconfiguration. #757 was filed from a bare
``isort --check-only --diff pcapkit/protocols/schema/schema.py``, which wraps at
isort's own default of 79 columns and so flagged an 89-character import the
Makefile's width accepts. So this module does not re-litigate the width.

Every line is covered, not the whole-tree one alone. That line (:file:`pcapkit`,
skipping ``__init__.py``) reaches neither :file:`examples/generators/` nor
:file:`util/`, which the last line sorts, nor the ``__init__.py`` files that sit
at least one directory below :file:`pcapkit/const/` or :file:`pcapkit/vendor/`.
The const and vendor lines have no ``--skip-glob``, so between them they
re-cover whichever of the files the whole-tree line skips happen to live there.
Their shape closes these gaps (#765):

* **Any depth.** A brace-expanded ``pcapkit/{const,vendor}/*/*.py`` stops at a
  fixed two levels, so :file:`pcapkit/const/reg/apptype/__init__.py`, a level
  deeper still, would go unsorted. A ``**`` glob under ``shopt -s globstar``
  needs bash >= 4.0, but :file:`Makefile`'s ``SHELL := $(shell command -v bash
  ...)`` only ever picks *some* ``bash`` off ``$PATH``, and macOS ships 3.2 as
  ``/bin/bash`` with no guarantee a newer one sits ahead of it. There ``shopt``
  writes one line to stderr and returns non-zero, and the *next* command in the
  recipe still runs under the plain, non-recursive glob -- silently, since make
  judges that recipe line by the isort invocation that follows ``shopt``, not by
  ``shopt`` itself. ``find`` needs no particular bash version and no shell
  option at all, and reaches any depth the same way.
* **One invocation per directory.** Handed to a single ``isort``, the two
  ``find`` calls are loud only when *both* come back empty -- ``isort`` then
  gets zero paths, exits 1 rather than reading ``stdin``, and make reports the
  recipe as failed (no ``set -e`` needed for this, and none is set). If only
  *one* came back empty, the other's files would still reach ``isort``, which
  would exit 0 having quietly sorted half the tree. Neither case is reachable --
  no path under :file:`pcapkit/const/` or :file:`pcapkit/vendor/` contains
  whitespace to break the expansion, and neither directory can be absent where
  ``make isort`` runs -- but one call per directory leaves neither reachable
  even in principle, and matches :file:`.github/workflows/cron-vendor.yml`'s
  own two calls (below).
* **``-mindepth 2``.** Without it ``find`` would also reach
  :file:`pcapkit/const/__init__.py` and :file:`pcapkit/vendor/__init__.py`
  themselves, whose hand-grouped import order isort would flatten -- see
  :func:`_const_targets` and :func:`_vendor_targets`.

:file:`.github/workflows/cron-vendor.yml` sorts the deep files the same way and
for the same reason (#765): it is the path that actually *writes* them, as
``pcapkit-vendor`` regenerates :mod:`pcapkit.const` from the :mod:`pcapkit.vendor`
crawlers, and that job runs on a ``macos-latest`` runner, where ``bash`` >= 4.0
cannot be relied on. This module does not cover that job, though: it only
exercises ``make isort``, and :file:`cron-vendor.yml`'s ``vendor-update`` job
never runs it -- the tests that job runs before it commits are
:file:`tests/const` and :file:`tests/vendor` alone (#1853).

The gate and the install line go together (#766). The gate is a module-level
:data:`HAS_ISORT` read by an ``@unittest.skipUnless`` decorator, not a
``try: import isort`` raising :exc:`~unittest.SkipTest` inside
:meth:`~TestIsortIsCleanOnThePackage.setUpClass`, because
:func:`tests._dependency_gates._gates_of` walks a definition's
``decorator_list`` and never a function body: an inline ``skipTest`` is
invisible to that scan *by construction*, which is the dark-test hazard #745
exists to stop and which #779 avoids the same way for the sibling ``mypy``
check.

The install line is the other half. ``isort`` is a ``test`` extra requirement,
so the pytest jobs whose selection collects this module -- ``test`` and
``gate``, not ``engine-tests`` (#849) -- run it for real rather than reporting
a skip. That is the opposite resolution from ``mypy``'s, whose
:data:`~tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS` entry declines the
install line, and the difference is not taste: :file:`lint.yml` already runs
``make mypy`` over the whole package, so a pytest copy would be a *second*
copy, while that same workflow's header records that ``isort`` is deliberately
not one of the linters it installs -- it appears only in
:file:`cron-vendor.yml`, as a formatter that rewrites the generated constants
on a schedule rather than as a check. So declining the install line here would
leave ``make isort``'s verdict checked nowhere at all, which is what #766
objected to. It is cheap enough to be uncontroversial, too: the lines below
take about 1.5s together, the "costs nothing per leg" category the test job's
own install comment puts ``DPKT`` in rather than the ``Scapy`` one.

``isort`` is in ``Pipfile``'s ``[dev-packages]`` too (#810) -- that being what
``make isort``'s own ``pipenv run`` prefix resolves against, so the target does
not depend on a contributor happening to have isort on ``PATH``. The two
declarations are additive rather than duplicate: the ``pyproject.toml`` extra
serves consumers installing the package, ``Pipfile`` serves this repository's
own dev environment, and ``make isort`` reads only the latter.

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
#: :mod:`tests.test_tier_guard` can audit which CI jobs it darkens -- none of
#: them, as the ``test`` extra carries isort; see this module's own
#: docstring for why that install line was the right answer here and the wrong
#: one for ``mypy``.
HAS_ISORT = importlib.util.find_spec('isort') is not None

#: The oldest isort whose verdict on this tree the test below was written for
#: (#1696). The ``test`` extra leaves isort unpinned (the comment above it in
#: :file:`pyproject.toml` says why), so each CI leg gets the newest release its
#: Python can install: 5.13.2 on 3.8, 6.1.0 on 3.9, 9.x from 3.10. The older
#: ones place blank lines around function-body ``# isort:skip`` imports
#: differently from 9.x, so they call a tree red that 9.x calls clean.
#:
#: Bisected on CPython 3.10.21, one fresh venv per release, each recipe line run
#: the way the test runs it (``python -m isort --check-only`` plus that line's
#: Makefile flags):
#:
#: * 5.13.2, 6.1.0, 7.0.0, 8.0.0 -- red on the whole-tree line, in five files
#:   (``scapy.py``, ``pyshark.py`` and ``dpkt.py`` under
#:   :file:`pcapkit/foundation/engines/`, :file:`pcapkit/protocols/protocol.py`,
#:   :file:`pcapkit/protocols/application/http.py`): ten blank lines after
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
#: older skips, the 9.0.0 pre-releases included; 9.0.1 and newer run,
#: so a later release whose verdict moves still turns the test red, as
#: :file:`pyproject.toml` intends.
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
    """``$(find pcapkit/<sub> -mindepth 2 -name '*.py')`` (#765) --
    ``Path.glob('*/**/*.py')`` matches the same set ``find -mindepth 2`` does: at
    least one subdirectory below ``<sub>``, then any depth. Pathlib's own glob has
    no shell and no bash version to depend on in the first place, so this mirror
    is not exposed to the bash-version bug the module docstring describes. The
    leading ``*/`` (equivalently, the ``-mindepth 2``) is deliberate, not slack --
    a bare ``**/*.py`` would also reach :file:`pcapkit/<sub>/__init__.py` itself,
    whose hand-grouped, commented import order (``# base crawler``, only under
    ``vendor``; ``# IANA registration``, ``# Miscellanous`` and ``# per protocol``
    under both) isort's ``-l100 -ppcapkit`` would flatten into one alphabetical
    block, scattering the comments across it -- confirmed with ``isort --diff``,
    not assumed. That file stays reached by neither this call nor the whole-tree
    line (which skips every ``__init__.py``).

    """
    return sorted(str(path) for path in (PACKAGE / sub).glob('*/**/*.py'))


def _const_targets() -> 'list[str]':
    """``pcapkit/const/`` half of the pair described in
    :func:`_find_mindepth_2_targets` -- on its own line (#765; see the
    module docstring), matching :file:`cron-vendor.yml`'s own separate
    calls for ``const`` and ``vendor``.

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
    """The physical, 1-indexed line numbers of the Makefile's ``isort:``
    target's own recipe lines, computed fresh from :file:`Makefile` every
    run rather than hardcoded -- a hardcoded number is exactly the kind of
    silent rot this module exists to catch: a function called
    ``_line_125_targets`` stops matching reality the moment a
    :file:`Makefile` comment above the target grows by a few lines, with
    nothing here to notice. So none of the functions below is named after a
    line number; :data:`MAKEFILE_LINES` carries the number as data instead,
    paired with the callable it belongs to positionally rather than by a
    key that could drift out of sync with what it claims to label.

    A recipe line is any line beginning with a tab that immediately follows
    ``isort:`` or another such line, a blank line, or a comment line at
    column 0 -- make itself treats a blank or a column-0 ``#`` line inside a
    recipe as transparent rather than as ending the rule (measured with
    ``make -n isort`` as the oracle: it still reports the same commands with
    either dropped in between two recipe lines, so breaking on the first
    line that is not tab-indented, comment or not, would be wrong). The
    first following line that is genuine content and not tab-indented ends
    the target -- a new target declaration, most likely, since nothing above
    passes that test.

    Matching ``isort:`` requires the *whole* line, not a prefix: an
    ``isort-check:`` target, or a ``.PHONY: isort`` line naming ``isort`` as
    a dependency rather than declaring it, must not be mistaken for the
    target this function is looking for. The one case this does not defend
    against is a ``define``/``endef`` block whose body contains a bare
    ``isort:`` at column 0 followed by tab-indented lines --
    nothing in this file uses ``define``, so it is undefended rather than
    handled.

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


#: One entry per recipe line of the Makefile's ``isort:`` target, in the
#: order those lines appear: the flags that precede the targets, and the
#: callable that resolves those targets on this checkout. A plain list, not
#: a dict keyed by line number -- see :func:`_isort_recipe_line_numbers` for
#: why a line number is not safe to key anything on here.
#:
#: A flag changed in one place and not the other -- here or in the Makefile
#: -- is exactly how "clean locally, red in CI" (or the reverse) starts,
#: which is the motive for keeping this list matched to the Makefile at
#: all. The mechanism the test below actually has for that is narrower than
#: the motive, though: the length check catches a recipe *line* added or
#: removed without a matching entry here, nothing more. Flags and target
#: expressions are plain literals in this list, never read back out of
#: :file:`Makefile`, so a flag edited there (``-l100`` to ``-l120``, say)
#: is not something this file would notice at all, and out of scope for
#: :func:`_isort_recipe_line_numbers` to fix. That asymmetry
#: is also what keeps a wrong line number cheap rather than dangerous: the
#: number only labels which real Makefile line a subtest's failure message
#: points at, and never decides which flags or targets the *test* actually
#: runs, so a line-number bug can misdirect where a human looks, but cannot
#: change what isort is asked to check.
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
