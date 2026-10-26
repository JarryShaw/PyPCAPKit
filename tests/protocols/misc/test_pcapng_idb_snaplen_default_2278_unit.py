# -*- coding: utf-8 -*-
"""GitHub issue #2278: an Interface Description Block's snaplen fits its 32-bit field.

Without the fix, ``_make_block_idb`` defaults ``snaplen`` to ``2**64 - 1``, which
the 32-bit SnapLen field truncates to ``0xFFFFFFFF``, so the made info disagrees
with the octets it parses back to, and an explicit ``snaplen`` of ``2**32`` or
more, or below zero, is truncated the same way. The default is 0, which the
PCAP-NG specification reads as no limit, and a value the field cannot hold
raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any

H = bytes.fromhex


class TestPCAPNGIDBSnaplen(PCAPNGTestCase):
    """Pin the snaplen an Interface Description Block is made with."""

    def _make(self, **block: 'Any') -> 'Any':
        """Make an Ethernet Interface Description Block from ``block``."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=1, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                      block={'linktype': LinkType.ETHERNET, **block})

    def test_default_is_no_limit(self) -> None:
        """The issue's case: the default writes 0, and the info says 0."""
        made = self._make()
        self.assertEqual(made.data.hex(), H('01000000 14000000 0100 0000 00000000 14000000').hex())
        self.assertEqual(made.info.snaplen, 0)  # type: ignore[attr-defined]

    def test_made_info_matches_the_octets(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for snaplen in (None, 0, 1, 0x40000, 0xFFFF_FFFF):
            with self.subTest(snaplen=snaplen):
                made = self._make() if snaplen is None else self._make(snaplen=snaplen)
                parsed = PCAPNG(made.data, len(made.data), num=1, sct=1, ctx=self._context())
                self.assertEqual(made.info.snaplen, parsed.info.snaplen)  # type: ignore[attr-defined]
                self.assertEqual(made.info, parsed.info)
                self.assertRebuilds(made.data)

    def test_out_of_range_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for snaplen in (-1, 0x1_0000_0000, 0xFFFF_FFFF_FFFF_FFFF):
            with self.subTest(snaplen=snaplen):
                with self.assertRaises(ProtocolError) as context:
                    self._make(snaplen=snaplen)
                self.assertTrue(str(context.exception).endswith(f': {snaplen!r}'),
                                str(context.exception))


if __name__ == '__main__':
    unittest.main()
