# -*- coding: utf-8 -*-
"""Pins ``make isort`` clean on all four of its lines (#757).

#757 was filed from a reproduction that ran bare ``isort --check-only --diff
pcapkit/protocols/schema/schema.py``, with none of the flags ``make isort``
actually uses. Bare isort wraps at its own default of 79 columns, so it flagged
the ``misc`` import (89 characters) and proposed wrapping it -- and from that
diff the issue reasoned that isort's wrap width must disagree with the
project's ``line-too-long`` threshold of 120, since 89 is under 120 but over
79.

Re-running with the Makefile's own flags -- see :data:`MAKEFILE_LINES` below,
one entry per line of the ``isort:`` target -- shows a different picture.
Those flags set the width to 100, exactly as :file:`CONTRIBUTING.md` documents
("120 for ``pylint`` and 100 for ``isort``, not PEP 8's 79"): a deliberate,
written-down split, not a misconfiguration. Under *that* width the ``misc``
import is not flagged at all (89 < 100). What *was* flagged, on the commit
this test landed with, were three things the whole-tree line's flags alone
would not have caught:

* :file:`pcapkit/protocols/schema/schema.py` -- its ``pcapkit.utilities.warnings``
  import was wrapped across two lines at some earlier width, and unwrapped it
  is 96 characters, under 100, so isort's real verdict was to collapse it back
  to one line rather than wrap another import.
* :file:`examples/generators/dispatch.py` -- two function-local import blocks
  isort wants a blank line after (the util/examples-generators line's
  targets, unreachable from the whole-tree line's ``pcapkit`` argument).
* :file:`examples/generators/options.py` -- an ``import ipaddress`` isort wants
  moved above the ``from pcapkit...`` block, and a ``from scapy.all import
  ...`` isort wants reordered by its constant/class split (``IP, TCP`` before
  ``Ether, IPv6, Raw``). Also the util/examples-generators line only; only
  import order changed, since this module is loaded and run at test time,
  not just read at review time.
  Three test modules load it by path via
  ``importlib.util.spec_from_file_location``:
  :file:`tests/protocols/test_option_generator_tcp_base_unit.py`,
  :file:`tests/protocols/test_option_coverage_runtime.py`, and
  :file:`tests/protocols/test_option_roundtrip_unit.py`.
  :file:`examples/generators/dispatch.py:20` and
  :file:`docs/source/changelog/1.5.0.rst` (lines 691 and 1169) both name it
  directly, too.

So this module does not re-litigate the width. It just pins isort's own
verdict on each of the four lines -- via real ``isort`` invocations with the
Makefile's exact flags, not a hand-rolled guess about what those flags imply --
so a future edit that reintroduces an unsorted or mis-wrapped import anywhere
``make isort`` reaches fails here instead of surfacing as "clean locally, red
in CI" the way #757 did. Earlier revisions of this test covered the
whole-tree line only (:file:`pcapkit`, skipping ``__init__.py``) and so
missed exactly the :file:`examples/generators/` files above and the
``__init__.py`` files that sit at least one directory below
:file:`pcapkit/const/` or :file:`pcapkit/vendor/` -- the const and vendor
lines have no ``--skip-glob``, so between them they re-cover whichever of
the 71 files the whole-tree line skips happen to live there, even though
the whole-tree line skips all 71 package-wide. The const and vendor lines
used to be one, :file:`pcapkit/const/*/*.py` and :file:`pcapkit/vendor/*/*.py`
combined into a single brace-expanded glob that stopped at a fixed two
levels, which the #754 split outgrew the moment
:file:`pcapkit/const/reg/apptype/__init__.py` landed a level deeper still and
nothing sorted it any more (#765).

The first fix tried here widened that one line to
``pcapkit/{const,vendor}/*/**/*.py`` under ``shopt -s globstar``, reaching
any depth below the first subdirectory. That was itself wrong, and in the
same shape as the bug it fixed: ``globstar`` needs bash >= 4.0,
:file:`Makefile`'s ``SHELL := $(shell command -v bash ...)`` only ever picks
*some* ``bash`` off ``$PATH``, and macOS ships 3.2 as ``/bin/bash`` with no
guarantee a newer one sits ahead of it. Without ``globstar`` the shell option
itself fails, ``shopt`` writes one line to stderr and returns non-zero, and
the *next* command in the recipe still runs under the plain, non-recursive
glob -- silently, since make does not stop a recipe line for a failed
``shopt``, only for the isort invocation that follows it. So on such a
machine that one line would have gone from reaching 264 files to reaching
12, sorting none of the 32 depth-two ``__init__.py`` files it used to cover
(the other two, three levels down under :file:`.../reg/apptype/`, stayed
reachable even by the degraded glob) -- the #765 hole reopened one level up,
by #765's own fix.

The second fix replaced that with ``$$(find pcapkit/const -mindepth 2 -name
'*.py') $$(find pcapkit/vendor -mindepth 2 -name '*.py')``, both handed to
one ``isort`` invocation: ``find`` needs no particular bash version and no
shell option at all, and reaches any depth the same way. That closed the
bash-version gap but opened a narrower one of its own: merged into a single
invocation, only the case where *both* ``find`` calls come back empty is
loud -- ``isort`` then gets zero paths, exits 1 rather than reading
``stdin``, and make reports the recipe as failed because that command's own
status was non-zero, the same as it would for any other line (no ``set -e``
needed for this, and none is set). If only *one* of the two came back empty,
though, the other's files would still reach ``isort`` in that same
invocation, which would exit 0 having quietly sorted half the tree. Neither
case is reachable today -- no path under :file:`pcapkit/const/` or
:file:`pcapkit/vendor/` contains whitespace to break the expansion, and
neither directory can be absent where ``make isort`` runs -- but it is the
same shape of latent gap #765 itself was, so the third fix, now in place, is
to split the one invocation into two: one call covers
:file:`pcapkit/const/`, the other covers :file:`pcapkit/vendor/`, matching
:file:`.github/workflows/cron-vendor.yml`'s own two calls exactly (below) and
leaving neither case above reachable even in principle. The leading
``-mindepth 2`` on each stays for the same reason the original glob's
leading ``*/`` did: dropping it would also reach
:file:`pcapkit/const/__init__.py` and :file:`pcapkit/vendor/__init__.py`
themselves, whose hand-grouped import order isort would flatten -- see
:func:`_const_targets` and :func:`_vendor_targets`.

The identical two-level glob also lived in
:file:`.github/workflows/cron-vendor.yml`, on the path that actually *writes*
the deep files: ``pcapkit-vendor`` regenerates :mod:`pcapkit.const` from the
:mod:`pcapkit.vendor` crawlers, and that job's own ``isort`` calls -- already
two, one per directory -- were as blind to :file:`pcapkit/const/reg/apptype/`
as the Makefile's own line used to be. Fixed there too (#765), the same way
and for the same reason: that job runs on a ``macos-latest`` runner, so
relying on ``bash`` >= 4.0 would have been exactly the mistake the Makefile's
line first made. This module does not cover that fix, though: it only
exercises ``make isort``, and :file:`cron-vendor.yml`'s ``vendor-update`` job
never runs this test suite at all -- it commits and pushes on its own, with
no pytest step in between.

Until #766 this module gated on isort with a ``try: import isort`` inside
:meth:`~TestIsortIsCleanOnThePackage.setUpClass`, raising
:exc:`~unittest.SkipTest` from the body -- and isort was in no
:file:`pyproject.toml` extra, so every CI leg skipped it. Both halves of that
are fixed here, and they had to move together.

The gate is now a module-level :data:`HAS_ISORT` read by an
``@unittest.skipUnless`` decorator, because
:func:`tests._dependency_gates._gates_of` walks a definition's
``decorator_list`` and never a function body: an inline ``skipTest`` is
invisible to that scan *by construction*, which is the dark-test hazard #745
exists to stop and which #779 fixed the same way for the sibling ``mypy``
check.

The install line is the other half. ``isort`` is now a ``test`` extra
requirement, so the three jobs whose selection collects this module --
``test``, ``engine-tests`` and ``gate`` -- run it for real rather than
reporting a skip. That is the opposite resolution from ``mypy``'s, whose
:data:`~tests._dependency_gates.DEPENDENCY_GATE_EXCLUSIONS` entry declines the
install line, and the difference is not taste: :file:`lint.yml` already runs
``make mypy`` over the whole package, so a pytest copy would be a *second*
copy, while that same workflow's header records that ``isort`` is deliberately
not one of the four linters it installs -- it appears only in
:file:`cron-vendor.yml`, as a formatter that rewrites the generated constants
on a schedule rather than as a check. So declining the install line here would
have left ``make isort``'s verdict checked nowhere at all, which is what #766
objected to. It is cheap enough to be uncontroversial, too: all four lines
below take about 1.5s together, the "costs nothing per leg" category the test
job's own install comment puts ``DPKT`` in rather than the ``Scapy`` one.

``isort`` remains absent from ``Pipfile``, which is what ``make isort``'s own
``pipenv run`` prefix resolves against -- so the target still depends on a
contributor having isort on ``PATH``. Out of scope here: this module is reached
by pytest, not by ``make``.

"""

from __future__ import annotations

import importlib.util
import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'pcapkit'
MAKEFILE = ROOT / 'Makefile'

#: Whether :mod:`isort` is importable, for the one test that runs it. A visible
#: ``skipUnless`` flag rather than the inline ``skipTest`` this module used
#: until #766, so :func:`~tests._dependency_gates.gated_scopes` counts the gate
#: and :mod:`tests.test_tier_guard` can audit which CI jobs it darkens -- none
#: of them, now that the ``test`` extra carries isort; see this module's own
#: docstring for why that install line was the right answer here and the wrong
#: one for ``mypy``.
HAS_ISORT = importlib.util.find_spec('isort') is not None


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
    ``Path.glob('*/**/*.py')`` matches the same set ``find -mindepth 2`` does:
    at least one subdirectory below ``<sub>``, then any depth. Pathlib's own
    glob has no shell and no bash version to depend on in the first place, so
    this mirror was never exposed to the bug the Makefile itself just had.
    The leading ``*/`` (equivalently, the ``-mindepth 2``) is deliberate, not
    slack -- a bare ``**/*.py`` would also reach :file:`pcapkit/<sub>/__init__.py`
    itself, whose hand-grouped, commented import order (``# base crawler``,
    only under ``vendor``; ``# IANA registration``, ``# Miscellanous`` and
    ``# per protocol`` under both) isort's ``-l100 -ppcapkit`` would flatten
    into one alphabetical block, scattering the comments across it --
    confirmed with ``isort --diff``, not assumed. That file stays reached by
    neither this call nor the whole-tree line (which skips every
    ``__init__.py``), same as before #765.

    """
    return sorted(str(path) for path in (PACKAGE / sub).glob('*/**/*.py'))


def _const_targets() -> 'list[str]':
    """``pcapkit/const/`` half of the pair described in
    :func:`_find_mindepth_2_targets` -- its own line since #765's second fix
    (see the module docstring), matching :file:`cron-vendor.yml`'s own
    separate calls for ``const`` and ``vendor``.

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
    silent rot this module exists to catch, and an earlier revision of this
    file was guilty of it in its own name: functions called
    ``_line_125_targets`` and so on stopped matching reality the moment a
    :file:`Makefile` comment two lines above the target grew by a few
    lines, and nothing here noticed until a reviewer measured it by hand.
    None of the functions below are named after a line number any more for
    that reason; :data:`MAKEFILE_LINES` carries the number as data instead,
    paired with the callable it belongs to positionally rather than by a
    key that could drift out of sync with what it claims to label.

    A recipe line is any line beginning with a tab that immediately follows
    ``isort:`` or another such line, a blank line, or a comment line at
    column 0 -- make itself treats a blank or a column-0 ``#`` line inside a
    recipe as transparent rather than as ending the rule (measured with
    ``make -n isort`` as the oracle: it still reports the same four commands
    with either dropped in between two recipe lines, which an earlier
    revision of this function got wrong by breaking on the first line that
    was not tab-indented, comment or not). The first following line that is
    genuine content and not tab-indented ends the target -- a new target
    declaration, most likely, since nothing above passes that test.

    Matching ``isort:`` requires the *whole* line, not a prefix: an
    ``isort-check:`` target, or a ``.PHONY: isort`` line naming ``isort`` as
    a dependency rather than declaring it, must not be mistaken for the
    target this function is looking for. The one case this does not defend
    against is a ``define``/``endef`` block whose body contains a bare
    ``isort:`` at column 0 followed by four or more tab-indented lines --
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
#: is not something this file would notice at all -- pre-existing, and out
#: of scope for :func:`_isort_recipe_line_numbers` to fix. That asymmetry
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
    """``make isort`` must not be red on a clean checkout, on any of its four
    lines (#757).

    """

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
