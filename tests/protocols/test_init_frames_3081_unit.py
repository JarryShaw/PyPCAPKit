# -*- coding: utf-8 -*-
"""A parse costs the Python frames per layer it did before #3081 (GitHub issue #1610).

Each layer dissects the next from inside its own parse, so a frame added to one
layer's parse is a frame added per layer, and a deep frame meets the recursion limit
sooner. #3081 let ``Protocol.__init__`` construct as well as parse, and the parse
path keeps its frames:

* :class:`FramesPerLayerTests` -- an 802.1Q tag, parsed through the base
  ``__init__``, costs 10 frames, and an IPv4 header, parsed through
  ``IP.__init__`` and ``_parse``, 13, by the class call and by ``from_file`` alike.

The counts are what ``develop`` measured before #3081, on CPython 3.14 and 3.15
alike. They follow the interpreter's own Python-level calls, so the module is
``LATEST`` tier; ``test_init_constructs_3081_unit`` holds the structural check every
leg runs. This module is unit tier: it builds its own octets and reads no capture.

"""
from __future__ import annotations

import sys
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.foundation import _roundtrip as wire

if TYPE_CHECKING:
    from typing import Callable

#: Test tier (#1958): frame counts follow the interpreter's Python-level calls, so
#: they are pinned on the latest CPython alone.
__tier__ = 'LATEST'

#: The Python frames a layer of each kind adds to a parse, as ``develop`` measured them.
FRAMES_PER_LAYER = {'802.1Q': 10, 'IPv4': 13}


def depth(func: 'Callable[[], object]') -> int:
    """How many Python frames deeper than its caller ``func()`` goes, as #1610's test counts."""
    state = {'now': 0, 'most': 0}

    def profile(frame: object, event: str, arg: object) -> None:  # pylint: disable=unused-argument
        if event == 'call':
            state['now'] += 1
            state['most'] = max(state['most'], state['now'])
        elif event == 'return':
            state['now'] -= 1

    sys.setprofile(profile)
    try:
        func()
    finally:
        sys.setprofile(None)
    return state['most']


def tagged(count: int) -> bytes:
    """An Ethernet frame of ``count`` 802.1Q tags, then IPv4 and TCP."""
    data, ethertype = wire.ipv4(wire.tcp(b'payload', seq=1), proto=6), 0x0800
    for _ in range(count):
        data, ethertype = bytes(2) + ethertype.to_bytes(2, 'big') + data, 0x8100
    return wire.ethernet(data, ethertype)


def nested(count: int) -> bytes:
    """An Ethernet frame of ``count`` IPv4 headers, then TCP."""
    data, proto = wire.tcp(b'payload', seq=1), 6
    for _ in range(count):
        data, proto = wire.ipv4(data, proto=proto), 4
    return wire.ethernet(data, 0x0800)


@unittest.skipUnless(sys.implementation.name == 'cpython', 'frame counts are pinned on CPython')
class FramesPerLayerTests(unittest.TestCase):
    """Ten layers more cost ten times a layer's frames, through either form of parse."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_each_layer_costs_the_frames_it_did(self) -> None:
        from pcapkit.protocols.link.ethernet.protocol import Ethernet

        for kind, build in (('802.1Q', tagged), ('IPv4', nested)):
            for form, read in (('call', Ethernet), ('from_file', Ethernet.from_file)):
                with self.subTest(kind=kind, form=form), warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    short, deep = build(10), build(20)
                    read(short)
                    read(deep)
                    cost = depth(lambda: read(deep)) - depth(lambda: read(short))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(cost, 10 * FRAMES_PER_LAYER[kind])


if __name__ == '__main__':
    unittest.main()
