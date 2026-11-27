# -*- coding: utf-8 -*-
"""A PCAP-NG capture cut at every octet still reports the frames before the cut.

The sweep of ``PCAPNGTruncatedFileTests`` in
:mod:`tests.protocols.misc.test_pcapng_unit`, whose docstring gives the defect
(#678, #431): ``dhcp.pcapng`` is cut at every octet boundary rather than at its
hand-picked levels, and each cut must parse, or fail from inside the library,
without the frame count rising as the cut deepens.

"""
from __future__ import annotations

import unittest

from tests._support import reimport_once_per_class, sample_path
from tests.protocols.misc.test_pcapng_unit import HAS_RUNTIME, extract_in_memory

#: Test tier (#1958): a sweep that cuts a capture at every offset, which the tier
#: rule puts on ``latest`` alone (#1732, #1958).
__tier__ = 'LATEST'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPNGEveryTruncationTests(unittest.TestCase):
    """Every truncation of a capture keeps the frames before the cut."""

    #: The result of :meth:`_sweep`, computed by the first test that asks for it
    #: and shared by the rest: one extraction per octet of the sample is
    #: this class's whole cost (GitHub issue #1062).
    _swept = None  # type: tuple[dict[int, int], dict[int, BaseException]] | None

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._swept = None
        # The failures keep their tracebacks, and with them this class's pcapkit
        # import, so the sweep goes once the class is done (#2750).
        cls.addClassCleanup(setattr, cls, '_swept', None)

    def setUp(self) -> None:
        reimport_once_per_class(self)

        with open(sample_path('dhcp.pcapng'), 'rb') as stream:
            self.whole = stream.read()

    def _sweep(self) -> 'tuple[dict[int, int], dict[int, BaseException]]':
        """Extract every truncation of the sample, one octet at a time.

        Returns the frame count for each level that parsed and the exception for
        each that did not. Sweeping every boundary rather than picking one is the
        point: the levels that behave differently are not the ones anybody would
        have chosen by hand -- 372 and 373 are where ``struct.error`` lived, and
        376 is where the cut happens to land on a block boundary.

        Computed once per class, lazily rather than in :meth:`setUpClass`, so the
        sweep runs against the class's own :mod:`pcapkit` import, which
        :func:`tests._support.reimport_once_per_class` sets up from ``setUp``.

        """
        if type(self)._swept is None:
            type(self)._swept = self._sweep_uncached()
        return type(self)._swept

    def _sweep_uncached(self) -> 'tuple[dict[int, int], dict[int, BaseException]]':
        """Run the sweep :meth:`_sweep` caches."""
        frames = {}  # type: dict[int, int]
        failures = {}  # type: dict[int, BaseException]

        for cut in range(len(self.whole) + 1):
            data = self.whole[:len(self.whole) - cut]
            try:
                extractor, _ = extract_in_memory(data)
            except BaseException as error:  # noqa: BLE001 -- classifying, not handling
                failures[cut] = error
            else:
                frames[cut] = len(extractor.frame)  # type: ignore[attr-defined]

        self.assertEqual(len(frames) + len(failures), len(self.whole) + 1)
        return frames, failures

    def test_no_truncation_level_raises_from_outside_the_library(self) -> None:
        """The whole of #678, asserted over every boundary rather than one.

        A caller cannot tell a bare ``ValueError`` or ``struct.error`` from a bug
        in its own code, and neither is an :exc:`EOFError`, so neither is caught
        where the frame loop catches the end of a file. Every failure that is
        left has to come from :mod:`pcapkit.utilities.exceptions`.

        """
        from pcapkit.utilities.exceptions import BaseError

        _, failures = self._sweep()

        foreign = {cut: error for cut, error in failures.items()
                   if not isinstance(error, BaseError)}
        self.assertEqual(
            foreign, {},
            f'{len(foreign)} truncation level(s) raised from outside '
            f'pcapkit.utilities.exceptions: '
            f'{sorted((cut, type(err).__name__) for cut, err in foreign.items())[:8]}'
        )

    def test_almost_every_truncation_level_parses(self) -> None:
        """The #431 bar: a truncated capture parses, it does not fail.

        Absence of a foreign exception would be satisfied by turning all 1,509
        levels into a tidy in-library refusal, which is the failure this guards
        against. Without the fix six levels parse; the rest is what the fix is
        for.

        """
        frames, failures = self._sweep()

        self.assertGreater(len(frames), 0.98 * (len(self.whole) + 1))
        self.assertLess(len(failures), 16)

    def test_every_failing_cut_fails_for_a_reason_of_its_own(self) -> None:
        """The handful left are all cuts that reach the section header itself.

        None of them costs a frame that was in the file: a cut that deep has
        already removed every packet block. A file under twelve octets cannot
        hold a block at all and is reported as end-of-stream; under four it
        cannot even be identified as PCAP-NG.

        """
        from pcapkit.utilities.exceptions import (FormatError, ProtocolError,
                                                  StreamEOFError)

        frames, failures = self._sweep()

        for cut, error in sorted(failures.items()):
            with self.subTest(cut=cut, error=type(error).__name__):
                self.assertIsInstance(error, (StreamEOFError, ProtocolError, FormatError))
                self.assertGreater(cut, len(self.whole) - 64)

        # every level that failed is deeper than every level that still had a
        # frame to report, so no failure cost a frame that was in the file
        deepest_with_a_frame = max(cut for cut, count in frames.items() if count)
        self.assertLess(deepest_with_a_frame, min(failures))

    def test_the_frame_count_never_rises_as_the_cut_deepens(self) -> None:
        """Removing octets may lose frames; it may not invent them.

        The structural property a zero-padded short read could break: padding a
        shortfall out of nothing is how a block gets fabricated, and a fabricated
        block would show up here as a frame count going *up* while the file got
        smaller.

        """
        frames, _ = self._sweep()

        levels = sorted(frames)
        for deeper, shallower in zip(levels[1:], levels):
            with self.subTest(cut=deeper):
                self.assertLessEqual(frames[deeper], frames[shallower])

        self.assertEqual(frames[0], 4)
        self.assertEqual(frames[max(levels)], 0)


if __name__ == '__main__':
    unittest.main()
