# -*- coding: utf-8 -*-
"""What git is allowed to track under :file:`examples/captures/`.

That directory holds two kinds of file, and only one of them belongs in the
index. The *inputs* -- :file:`in.pcap` and :file:`dhcp.pcapng` -- are captures
nothing in the repository can reconstruct, so they are committed. Everything else
is output: the captures :file:`examples/generators/make_samples.py` writes, and
the rendered reports :file:`examples/legacy_smoke/` produces out of those two
inputs -- :file:`out.json`, :file:`out.plist`, :file:`out.txt` and
:file:`pcapng.txt`, via ``make fixtures`` there.

Those four reports were tracked once, and GitHub issue #685 is why they are not
any more. A tracked report has no reader: no test asserts on one, and the
documentation only quotes them as prose. So a parser change that alters how a
frame renders leaves the committed copy wrong with nothing anywhere to say so --
:file:`pcapng.txt` sat recording ``packet -> NIL`` for four blocks that had
started carrying their captured octets, and it was found by somebody reading the
file rather than by anything failing.

Untracking them fixed that instance. This module is what keeps it fixed, because
the mistake is one commit away in either direction and neither direction looks
interesting in a diff review:

* ``git add -f examples/captures/out.txt`` on a freshly rebuilt report puts the
  staleness straight back, :file:`.gitignore` notwithstanding -- and so would a
  new ``!examples/captures/...`` exception line;
* an over-eager cleanup that dropped the two real inputs as well would break the
  whole unit tier, which is entitled to read them on a fresh clone.

The rule is stated by *suffix* rather than as a list of the two names, so adding
a genuine input capture needs no edit here while committing a rendered report
fails immediately. That is the same trade :mod:`tests._tiers` makes, and this
module reuses its answer rather than shelling out to git a second time.

This module is unit-tier and reads no capture: it asks what git tracks, and it
parses test modules as text. Both work on a fresh clone.

"""
from __future__ import annotations

import pathlib
import unittest

from tests import _tiers

#: Reports rendered by :file:`examples/legacy_smoke/`, none of which git tracks.
#: Named explicitly, rather than derived as "everything without a capture
#: suffix", because these four are the ones that were tracked and the ones any
#: regression would most likely reinstate.
RENDERED_REPORTS = ('out.json', 'out.plist', 'out.txt', 'pcapng.txt')
#: The captures that must stay committed, because nothing regenerates them:
#: :file:`in.pcap` is read by roughly fifty modules and :file:`dhcp.pcapng` by
#: nine, and the unit tier reads both on a fresh clone.
INPUT_CAPTURES = ('dhcp.pcapng', 'in.pcap')


class TrackedCaptureTests(unittest.TestCase):
    """Which files under :file:`examples/captures/` git has in its index."""

    def setUp(self) -> None:
        reason = _tiers.guard_unavailable_reason()
        if reason is not None:
            self.skipTest(f'git cannot answer here: {reason}')

        tracked = _tiers.committed_captures()
        assert tracked is not None
        self.tracked = tracked

    def test_every_tracked_file_is_an_input_capture(self) -> None:
        """No rendered report, and nothing else generated, is in the index.

        The assertion is on the suffix rather than on the exact set of names, so
        a new input fixture can be committed without touching this file. A
        rendered report cannot: none of :data:`RENDERED_REPORTS` ends in a
        capture suffix, which is precisely what makes them catchable here.

        """
        offenders = sorted(
            name for name in self.tracked
            if not name.endswith(_tiers.CAPTURE_SUFFIXES)
        )
        self.assertEqual(
            offenders, [],
            f'git tracks {offenders} under examples/captures/, which are not input '
            f'captures. Generated output does not belong in the index -- it goes stale '
            f'silently, which is GitHub issue #685. Rebuild these locally instead: '
            f'`cd examples/legacy_smoke && make fixtures` for the rendered reports, '
            f'`{_tiers.REGENERATE_SAMPLES_CMD}` for the captures.'
        )

    def test_no_rendered_report_is_tracked(self) -> None:
        """:data:`RENDERED_REPORTS` by name, in case the suffix rule is relaxed.

        Redundant with :meth:`test_every_tracked_file_is_an_input_capture` today
        and deliberately so: that test's reach depends on
        :data:`~tests._tiers.CAPTURE_SUFFIXES`, and a future ``.txt`` capture
        format would widen the suffix list and quietly let these four back in.

        """
        for name in RENDERED_REPORTS:
            with self.subTest(report=name):
                self.assertNotIn(
                    name, self.tracked,
                    f'examples/captures/{name} is a rendered report and must not be '
                    f'tracked -- see GitHub issue #685'
                )

    def test_both_input_captures_are_tracked(self) -> None:
        """The opposite mistake, which would break the unit tier.

        Without this, :meth:`test_every_tracked_file_is_an_input_capture` would
        pass on a checkout that tracks nothing under that directory at all.

        """
        for name in INPUT_CAPTURES:
            with self.subTest(capture=name):
                self.assertIn(
                    name, self.tracked,
                    f'examples/captures/{name} is an input nothing regenerates, and the '
                    f'unit tier reads it on a fresh clone, so it has to stay committed'
                )

    def test_tracked_inputs_are_present_on_disk(self) -> None:
        """A tracked name is a file that is actually there.

        Cheap, and it distinguishes "git tracks it" from "a checkout has it",
        which is the distinction the whole tier rule turns on.

        """
        for name in sorted(self.tracked):
            with self.subTest(capture=name):
                self.assertTrue(
                    (_tiers.SAMPLE_ROOT / name).is_file(),
                    f'git tracks examples/captures/{name} but it is not on disk'
                )


class ReportReadTests(unittest.TestCase):
    """That no test module reads a rendered report as though it were a capture.

    This is the regression untracking invites, and it is *not* covered by the
    tier guard's own audit. That audit only flags a **unit-tier** module reading
    a capture git does not track. These four are worse than untracked: nothing
    rebuilds them as part of fixture generation either, because
    :file:`examples/generators/make_samples.py` does not produce them -- only
    ``make fixtures`` under :file:`examples/legacy_smoke/` does, and neither CI
    nor ``make test-all`` runs that. So a read of one fails in *every* tier, on
    every machine that has not run that target by hand.

    """

    def test_sample_path_is_never_called_with_a_report(self) -> None:
        """Across the whole suite, both tiers, however the call is spelled."""
        reports = frozenset(RENDERED_REPORTS)
        offenders = []

        for module in sorted(_tiers.TESTS_ROOT.rglob('test_*.py')):
            for call in _tiers.sample_path_calls(str(module)):
                if call.name in reports:
                    location = module.relative_to(_tiers.ROOT).as_posix()
                    offenders.append(f'{location}:{call.lineno} reads {call.name!r}')

        self.assertEqual(
            offenders, [],
            f'{offenders} read a rendered report through sample_path(). Those reports '
            f'are not tracked and `{_tiers.REGENERATE_SAMPLES_CMD}` does not build them, '
            f'so the read fails wherever `make fixtures` has not been run by hand. Assert '
            f'on a report the test renders into its own temporary directory instead.'
        )


if __name__ == '__main__':
    unittest.main()
