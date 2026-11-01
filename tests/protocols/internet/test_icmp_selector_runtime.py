# -*- coding: utf-8 -*-
"""Protocol selectors tell ICMPv4 and ICMPv6 apart on parsed frames.

``'ICMP'`` names the abstract :class:`~pcapkit.protocols.internet.icmp.ICMP`
and so selects both versions; ``'ICMPv4'`` and ``'ICMPv6'`` select one each.
Frame 1 of ``little_endian.pcap`` is an ICMPv4 echo request, and frame 1 of
``in.pcap`` an ICMPv6 Neighbor Solicitation.

"""

from __future__ import annotations

import importlib.util
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class, sample_path

if TYPE_CHECKING:
    from typing import Any, Iterator

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Capture holding each version in its first frame.
SAMPLES = {'ICMPv4': 'little_endian.pcap', 'ICMPv6': 'in.pcap'}

#: Which version each selector matches.
MATCHES = {
    'ICMP': {'ICMPv4', 'ICMPv6'},
    'ICMPv4': {'ICMPv4'},
    'ICMPv6': {'ICMPv6'},
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ICMPSelectorRuntimeTests(unittest.TestCase):
    """Pin ``in``, ``[]``, ``==``, the protochain and ``extract(protocol=)``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _frame(self, version: str, **kwargs: 'Any') -> 'Any':
        from pcapkit.interface import extract

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=sample_path(SAMPLES[version]), store=True, nofile=True,
                                engine='default', **kwargs)
        self.addCleanup(close_extractor, extractor)
        return extractor.frame[0]

    def _selectors(self) -> 'Iterator[tuple[str, Any, set[str]]]':
        import pcapkit

        for name in MATCHES:
            yield name, name, MATCHES[name]
            yield f'{name} class', getattr(pcapkit, name), MATCHES[name]

    def test_frame_selectors(self) -> None:
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.utilities.exceptions import ProtocolNotFound

        for version in SAMPLES:
            frame = self._frame(version)
            layer = frame.payload.payload.payload
            self.assertEqual(type(layer).__name__, version)
            self.assertIsInstance(layer.payload, NoPayload)

            for label, key, expected in self._selectors():
                match = version in expected
                with self.subTest(frame=version, selector=label):
                    self.assertEqual(key in frame, match)
                    self.assertEqual(key in frame.protochain, match)
                    if match:
                        self.assertIs(frame[key], layer)
                    else:
                        with self.assertRaises(ProtocolNotFound):
                            frame[key]  # pylint: disable=pointless-statement

    def test_layer_equality(self) -> None:
        """``==`` against a name compares :meth:`~pcapkit.protocols.protocol.Protocol.id`."""
        v4 = self._frame('ICMPv4').payload.payload.payload
        v6 = self._frame('ICMPv6').payload.payload.payload

        self.assertTrue(v4 == 'ICMP')
        self.assertFalse(v4 == 'ICMPv6')
        self.assertTrue(v6 == 'ICMPv6')
        self.assertFalse(v6 == 'ICMP')

    def test_class_name_matches_by_in_not_by_equality(self) -> None:
        """``==`` skips the class name, which is not in ``id()``; ``in`` resolves it."""
        v4 = self._frame('ICMPv4').payload.payload.payload

        self.assertFalse(v4 == 'ICMPv4')
        self.assertIn('ICMPv4', v4)

    def test_extract_protocol_threshold(self) -> None:
        for version in SAMPLES:
            for name, expected in MATCHES.items():
                with self.subTest(frame=version, protocol=name):
                    layer = self._frame(version, protocol=name).payload.payload.payload
                    self.assertEqual(layer._sigterm, version in expected)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
