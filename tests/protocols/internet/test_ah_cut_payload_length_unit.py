# -*- coding: utf-8 -*-
"""An AH header cut on its own before its Payload Length rebuilds as captured.

Parsed on its own, a cut is a short read (#2880), so an AH header cut before Payload
Length reads that field as the zero the cut left, with an empty ICV. ``_make_data``
handed the zero to ``make`` as a declared length, which #2886 holds to describe the ICV
exactly (RFC 4302, sections 2.6 and 3.3.3.2.1), so the rebuild raised. A read Payload
Length below the 12 fixed octets (RFC 4302, section 2.2) is refused on its own, as in a
whole header, rather than parsed and then not rebuilt.

The octets are built here; this module is unit-tier and reads no capture file.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked parse -> rebuild round trips.
__tier__ = 'ALL'

#: Octets of the fixed fields ahead of the ICV (RFC 4302, section 2).
FIXED = 12


def ah_header(size: int, length: 'int | None' = None) -> bytes:
    """A captured AH header of ``size`` octets, its ICV patterned, its Payload Length ``length``."""
    icv = bytes(index % 251 + 1 for index in range(size - FIXED))
    words = size // 4 - 2 if length is None else length
    return struct.pack('!BBHII', 59, words, 0x0a0b, 0x1234, 1) + icv


class AHCutPayloadLengthTests(unittest.TestCase):
    """A cut on its own rebuilds from the data model and the dict, byte for byte."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, raw: bytes, **kwargs: object) -> 'object':
        """``raw`` parsed on its own as AH, given its length."""
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.utilities.exceptions import CaughtByCaller, ProtocolError

        with warnings.catch_warnings(), CaughtByCaller(ProtocolError):
            warnings.simplefilter('ignore')
            return AH(raw, len(raw), **kwargs)

    def assertRebuilds(self, layer: 'object', raw: bytes) -> None:  # pylint: disable=invalid-name
        """``layer`` rebuilt from its data model and its dict gives ``raw`` and its info."""
        for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):  # type: ignore[attr-defined]
            with self.subTest(path=path):
                rebuilt = type(layer).from_data(data)  # type: ignore[attr-defined]
                self.assertEqual(rebuilt.data.hex(), raw.hex())
                self.assertEqual(rebuilt.info, layer.info)  # type: ignore[attr-defined]

    def test_a_cut_before_payload_length_rebuilds(self) -> None:
        # the zero the cut left describes no ICV, and is not handed on as a declared length
        for size in (12, 24):
            for count, record in ((0, ('next', 0)), (1, ('len', 0))):
                raw = ah_header(size)[:count]
                with self.subTest(size=size, captured=count):
                    layer = self.parse(raw)
                    self.assertEqual(layer.info.get('__short_read__'), record)  # type: ignore[attr-defined]
                    self.assertEqual(layer.info.icv, b'')  # type: ignore[attr-defined]
                    self.assertRebuilds(layer, raw)

    def test_every_cut_rebuilds(self) -> None:
        # 32-bit and 64-bit aligned, and 20 octets, aligned for IPv4 alone
        for size in (12, 20, 24):
            whole = ah_header(size)
            for kwargs in ({}, {'version': 6}, {'version': 6, 'extension': True}):
                for count in range(size + 1):
                    raw = whole[:count]
                    with self.subTest(size=size, **kwargs, captured=count):
                        self.assertRebuilds(self.parse(raw, **kwargs), raw)

    def test_a_payload_length_read_below_the_fixed_fields_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        whole = ah_header(FIXED, length=0)
        for count in range(2, FIXED):
            with self.subTest(captured=count):
                with self.assertRaisesRegex(ProtocolError, r'^AH: invalid payload length: 0$'):
                    self.parse(whole[:count])

    def test_a_given_payload_length_is_still_held_to_the_icv(self) -> None:
        from pcapkit.protocols.internet.ah.protocol import AH
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r'^AH: invalid payload length: must describe the '
                                                   r'0-octet ICV exactly, not 0$'):
            AH(icv=b'', payload_length=0)


if __name__ == '__main__':
    unittest.main()
