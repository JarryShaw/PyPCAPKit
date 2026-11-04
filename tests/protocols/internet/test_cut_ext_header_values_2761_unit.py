# -*- coding: utf-8 -*-
"""A standalone IPv6 extension header cut short rebuilds with the values its parse read.

GitHub issue #2761: built on its own octets and cut short, an extension header rebuilt
to the octets captured, but ``from_data(info).info`` differed from ``info``. The rebuild
was read from the header ``make()`` built, whose Reserved fields are zero-filled past the
cut and whose option area a ``PadN`` pads out to the length the header declares; the
parse read the octets captured. Each field the issue names is checked against those
octets, in the parse and in its rebuild from the data model and from the :obj:`dict`.
``IPv6_Ext``'s ``length`` is the width the parse was given where the header overruns
it, and the rebuild, read at the two octets ``make()`` packs, took that for its own;
``__short_width__`` now records the width, and the rebuild is read at it.

The octets are built here; this module is unit-tier and reads no capture file.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: A Type 2 Routing header (RFC 6275, section 6.4) with a Reserved field of 01020304
#: and a Home Address of ::1, the issue's own.
ROUTE = bytes([59, 2, 2, 1, 1, 2, 3, 4]) + bytes(15) + b'\x01'

#: A Fragment header (RFC 8200, section 4.5), its Reserved octet the second.
FRAG = bytes([17, 0, 0, 8, 0x12, 0x34, 0x56, 0x78])

#: A 16-octet Hop-by-Hop or Destination Options header: Router Alert, then a PadN of
#: eight, whose Option Type is its seventh octet.
OPTIONS = bytes([17, 1, 5, 2, 0, 0, 1, 8]) + bytes(8)

#: The cuts of :data:`OPTIONS` the issue names; cut inside its Opt Data Len, the Router
#: Alert is refused.
OPTION_CUTS = (1, 2, 4, 5, 6)

#: A generic extension header (RFC 6564, section 4) cut after its Next Header of UDP,
#: and the widths it is read at: none, the octet captured, and the eight octets its Hdr
#: Ext Len of zero declares. The data model's ``length`` is what each width holds of
#: those eight.
GENERIC = bytes([17])
GENERIC_WIDTHS = {None: 1, 1: 1, 8: 8}


class CutExtensionHeaderValuesTests(unittest.TestCase):
    """The issue's fields read the octets captured, parsed and rebuilt."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # a cut header warns that its length runs past the data, which is the point
        catcher = warnings.catch_warnings()
        catcher.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def rebuilds(self, layer: 'object', raw: bytes) -> 'list[object]':
        """``layer`` rebuilt from its data model and its dict, each giving ``raw`` and its info."""
        out = []
        for data in (layer.info, layer.info.to_dict()):  # type: ignore[attr-defined]
            rebuilt = type(layer).from_data(data)  # type: ignore[attr-defined]
            self.assertEqual(rebuilt.data, raw)
            self.assertEqual(rebuilt.info, layer.info)  # type: ignore[attr-defined]
            out.append(rebuilt)
        return out

    def test_ipv6_route_reserved(self) -> None:
        from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route

        for count in range(1, 8):
            with self.subTest(captured=count):
                raw = ROUTE[:count]
                layer = IPv6_Route(raw, count)
                self.assertEqual(layer.info.reserved, ROUTE[4:count])
                for rebuilt in self.rebuilds(layer, raw):
                    self.assertEqual(rebuilt.info.reserved, ROUTE[4:count])

    def test_ipv6_frag_reserved_octet(self) -> None:
        from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag

        for count in range(1, 3):
            with self.subTest(captured=count):
                raw = FRAG[:count]
                layer = IPv6_Frag(raw, count)
                self.assertEqual(layer.info.reserved_octet, FRAG[1:count])
                for rebuilt in self.rebuilds(layer, raw):
                    self.assertEqual(rebuilt.info.reserved_octet, FRAG[1:count])

    def test_ipv6_ext_length(self) -> None:
        # The width is recorded beside the cut, and the rebuild read at it holds the
        # length its parse read, not the two octets make() packs.
        from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext

        for width, length in GENERIC_WIDTHS.items():
            with self.subTest(width=width):
                layer = IPv6_Ext(GENERIC) if width is None else IPv6_Ext(GENERIC, width)
                self.assertEqual((layer.info.length, layer.info.get('__short_width__')), (length, length))
                self.assertEqual(layer.info.next, None if length < 8 else 17)
                self.assertIn('__short_width__', layer.info.to_dict())
                self.assertNotIn('__short_width__', repr(layer.info))
                for rebuilt in self.rebuilds(layer, GENERIC):
                    self.assertEqual(rebuilt.info.length, length)
        with self.subTest(width='whole'):
            # a header captured whole records no width, nor does its rebuild
            whole = IPv6_Ext(GENERIC + bytes(7))
            self.assertEqual(whole.info.length, 8)
            self.assertNotIn('__short_width__', whole.info.to_dict())
            self.assertNotIn('__short_width__', IPv6_Ext.from_data(whole.info.to_dict()).info.to_dict())

    def test_hopopt_and_ipv6_opts_options(self) -> None:
        # No octet before the seventh is a PadN, so neither parse nor rebuild holds one.
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts

        for klass in (HOPOPT, IPv6_Opts):
            for count in OPTION_CUTS:
                with self.subTest(protocol=klass.__name__, captured=count):
                    raw = OPTIONS[:count]
                    layer = klass(raw, count)
                    self.assertNotIn(Option.PadN, list(layer.info.options))
                    for rebuilt in self.rebuilds(layer, raw):
                        self.assertEqual(list(rebuilt.info.options), list(layer.info.options))


if __name__ == '__main__':
    unittest.main()
