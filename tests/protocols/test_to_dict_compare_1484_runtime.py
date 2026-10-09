# -*- coding: utf-8 -*-
"""Two exports of the same packet compare ``==`` and not ``!=``.

GitHub issue #1484. :meth:`Info.to_dict <pcapkit.corekit.infoclass.Info.to_dict>`
returns an :class:`~pcapkit.corekit.multidict.OrderedMultiDict`, and Werkzeug's
class defines ``__eq__`` but no ``__ne__``: ``!=`` fell back to :obj:`dict`'s,
which compares the internal buckets, so ``info.to_dict() != info.to_dict()``
held for every frame. The export now negates its ``__eq__``.

For every frame of the option-heavy captures in :file:`examples/captures/`:

* two exports of the frame's info are ``==`` and not ``!=``, at the top and at
  every nested multi-mapping in them;
* two exports of every option list held by a layer's info are likewise.

The module reads generated captures, so it belongs to the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, time_limit
from tests._tiers import SAMPLE_ROOT

if TYPE_CHECKING:
    from typing import Any, Iterator

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Captures whose frames carry option lists, PCAP and PCAP-NG alike.
CAPTURES = ('options-internet.pcap', 'options-ipv4.pcap', 'options-ipv6.pcap', 'options-tcp.pcap',
            'options-transport.pcap', 'test.pcapng', 'dhcp.pcapng')

#: Whole seconds the sweep may take; it takes about two.
SWEEP_TIMEOUT = 120


def nested_pairs(one: 'Any', two: 'Any', path: 'str') -> 'Iterator[tuple[str, Any, Any]]':
    """``(path, a, b)`` for every multi-mapping at the same place in exports ``one`` and ``two``."""
    from pcapkit.corekit.multidict import MultiDict

    if isinstance(one, MultiDict) and isinstance(two, MultiDict):
        yield path, one, two
        for ((key, a), (_, b)) in zip(one.items(multi=True), two.items(multi=True)):
            yield from nested_pairs(a, b, f'{path}/{key}')


def option_lists(info: 'Any', path: 'str') -> 'Iterator[tuple[str, Any]]':
    """``(path, value)`` for every option list a layer's info holds, however deep."""
    from pcapkit.corekit.infoclass import Info, _MultiInfo

    for key, value in info.items(multi=True):
        if isinstance(value, _MultiInfo):
            yield f'{path}/{key}', value
        elif isinstance(value, Info):
            yield from option_lists(value, f'{path}/{key}')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ExportComparisonTests(unittest.TestCase):
    """Compare two exports of every frame and of every option list."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        quiet = warnings.catch_warnings()
        quiet.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(quiet.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def frames(self) -> 'Iterator[tuple[str, Any]]':
        """``(case, frame)`` for every frame of :data:`CAPTURES`."""
        from pcapkit import extract

        for name in CAPTURES:
            extractor = extract(fin=str(SAMPLE_ROOT / name), store=True, nofile=True)
            self.addCleanup(close_extractor, extractor)
            for number, frame in enumerate(extractor.frame, start=1):
                yield f'{name}#{number}', frame

    def test_two_exports_of_a_frame_are_equal_and_not_unequal(self) -> None:
        nested = 0
        with time_limit(SWEEP_TIMEOUT):
            for case, frame in self.frames():
                for path, one, two in nested_pairs(frame.info.to_dict(), frame.info.to_dict(), case):
                    nested += path != case
                    with self.subTest(case=path):
                        self.assertTrue(one == two)
                        self.assertFalse(one != two)
        self.assertGreater(nested, 0, 'no nested multi-mapping was compared')

    def test_two_exports_of_an_option_list_are_equal_and_not_unequal(self) -> None:
        compared = 0
        with time_limit(SWEEP_TIMEOUT):
            for case, frame in self.frames():
                for path, options in option_lists(frame.info, case):
                    compared += 1
                    with self.subTest(case=path):
                        self.assertTrue(options.to_dict() == options.to_dict())
                        self.assertFalse(options.to_dict() != options.to_dict())
        self.assertGreater(compared, 0, 'no option list was compared')


if __name__ == '__main__':
    unittest.main()
