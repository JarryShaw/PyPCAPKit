# -*- coding: utf-8 -*-
"""Pins ``make isort`` clean on all three of its lines (#757).

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
this test landed with, were three things line 125's flags alone would not
have caught:

* :file:`pcapkit/protocols/schema/schema.py` -- its ``pcapkit.utilities.warnings``
  import was wrapped across two lines at some earlier width, and unwrapped it
  is 96 characters, under 100, so isort's real verdict was to collapse it back
  to one line rather than wrap another import.
* :file:`examples/generators/dispatch.py` -- two function-local import blocks
  isort wants a blank line after (line 127's targets, unreachable from line
  125's ``pcapkit`` argument).
* :file:`examples/generators/options.py` -- an ``import ipaddress`` isort wants
  moved above the ``from pcapkit...`` block, and a ``from scapy.all import
  ...`` isort wants reordered by its constant/class split (``IP, TCP`` before
  ``Ether, IPv6, Raw``). Also line 127 only; only import order changed, since
  this module is loaded and run at test time, not just read at review time.
  Three test modules load it by path via
  ``importlib.util.spec_from_file_location``:
  :file:`tests/protocols/test_option_generator_tcp_base_unit.py`,
  :file:`tests/protocols/test_option_coverage_runtime.py`, and
  :file:`tests/protocols/test_option_roundtrip_unit.py`.
  :file:`examples/generators/dispatch.py:20` and
  :file:`docs/source/changelog/1.5.0.rst` (lines 691 and 1169) both name it
  directly, too.

So this module does not re-litigate the width. It just pins isort's own
verdict on each of the three lines -- via real ``isort`` invocations with the
Makefile's exact flags, not a hand-rolled guess about what those flags imply --
so a future edit that reintroduces an unsorted or mis-wrapped import anywhere
``make isort`` reaches fails here instead of surfacing as "clean locally, red
in CI" the way #757 did. Earlier revisions of this test covered line 125
only (:file:`pcapkit`, skipping ``__init__.py``) and so missed exactly the
:file:`examples/generators/` files above and the ``__init__.py`` files that
sit under :file:`pcapkit/const/*/` or :file:`pcapkit/vendor/*/` -- line 126 has
no ``--skip-glob``, so it re-covers whichever of the 71 files line 125 skips
happen to live there, even though line 125 skips all 71 package-wide.

``isort`` is deliberately absent from both ``Pipfile`` and ``pyproject.toml``:
:file:`.github/workflows/lint.yml` notes it stays local-only, unlike the other
three linters. So this test skips outright when isort is not installed, the
same way :class:`tests.project.test_release_gates.TestYAMLAgreesWithTheScanner`
skips its PyYAML-dependent half. #766 covers why that skip is itself invisible
to :file:`tests/_dependency_gates.py`'s guard -- deferred there, not fixed here.

"""

from __future__ import annotations

import pathlib
import subprocess
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PACKAGE = ROOT / 'pcapkit'


def _line_125_targets() -> 'list[str]':
    """``pcapkit $(wildcard temp/sort.py)`` -- the scratch file is untracked
    and normally absent, so this mirrors make's ``$(wildcard ...)`` by only
    adding it when it actually exists.

    """
    targets = [str(PACKAGE)]
    scratch = ROOT / 'temp' / 'sort.py'
    if scratch.exists():
        targets.append(str(scratch))
    return targets


def _line_126_targets() -> 'list[str]':
    """``pcapkit/{const,vendor}/*/*.py``, expanded the way bash would."""
    targets = []  # type: list[str]
    for sub in ('const', 'vendor'):
        targets.extend(sorted(str(path) for path in (PACKAGE / sub).glob('*/*.py')))
    return targets


def _line_127_targets() -> 'list[str]':
    """``util/*.py examples/generators/*.py``, expanded the way bash would."""
    targets = sorted(str(path) for path in (ROOT / 'util').glob('*.py'))
    targets.extend(sorted(str(path) for path in (ROOT / 'examples' / 'generators').glob('*.py')))
    return targets


#: One entry per line of the Makefile's ``isort:`` target: the flags that
#: precede the targets, and the callable that resolves those targets on this
#: checkout. Kept identical to those three lines on purpose -- a flag changed
#: in one place and not the other is exactly how "clean locally, red in CI"
#: (or the reverse) starts.
MAKEFILE_LINES = {
    125: (['-l100', '-ppcapkit', '--skip-glob', '**/__init__.py'], _line_125_targets),
    126: (['-l100', '-ppcapkit'], _line_126_targets),
    127: (['-l100', '-ppcapkit'], _line_127_targets),
}


class TestIsortIsCleanOnThePackage(unittest.TestCase):
    """``make isort`` must not be red on a clean checkout, on any of its three
    lines (#757).

    """

    @classmethod
    def setUpClass(cls) -> None:
        try:
            import isort  # noqa: F401  pylint: disable=unused-import,import-outside-toplevel
        except ImportError:
            raise unittest.SkipTest(
                "isort is not installed -- it is deliberately absent from both "
                "Pipfile and pyproject.toml (lint.yml: 'still local-only'), so "
                "this test only runs when a contributor has it installed, the "
                "same precondition `make isort` itself has"
            )

    def test_check_only_is_clean_on_every_makefile_line(self) -> None:
        """Each line of the Makefile's ``isort:`` target, run the way it runs."""
        for line, (flags, targets_fn) in sorted(MAKEFILE_LINES.items()):
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
