from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

BIG = b'\xa1\xb2\xc3\xd4'
LITTLE = b'\xd4\xc3\xb2\xa1'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPHeaderLoneEndianFlagUnitTests(unittest.TestCase):
    """A single ``lilendian``/``bigendian`` flag selects the byte order (GH-1144)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_lone_flag_overrides_byteorder(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header

        # ``byteorder`` is set to the opposite order, so a flag that is ignored
        # shows up regardless of the host's own byte order
        cases = (
            ({'bigendian': True, 'byteorder': 'little'}, BIG, 'big'),
            ({'bigendian': False, 'byteorder': 'big'}, LITTLE, 'little'),
            ({'lilendian': True, 'byteorder': 'big'}, LITTLE, 'little'),
            ({'lilendian': False, 'byteorder': 'little'}, BIG, 'big'),
        )
        for kwargs, magic, byteorder in cases:
            with self.subTest(**kwargs):
                header = Header(**kwargs)
                self.assertEqual(header.data[:4], magic)
                self.assertEqual(header.info.magic_number.byteorder, byteorder)

    def test_conflicting_flags_are_rejected(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import EndianError

        for flag in (True, False):
            with self.subTest(flag=flag):
                with self.assertRaises(EndianError):
                    Header(lilendian=flag, bigendian=flag)


if __name__ == '__main__':
    unittest.main()
