from __future__ import annotations

import importlib.util
import io
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PCAPHeaderMagicProtosUnitTests(unittest.TestCase):
    """``Header._make_magic`` and ``Header._read_protos`` (GH-1096)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_magic_endian_flags_honour_nanosecond(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header

        header = object.__new__(Header)
        cases = [
            ((True, False, False), (b'\xd4\xc3\xb2\xa1', True)),
            ((True, False, True), (b'\x4d\x3c\xb2\xa1', True)),
            ((False, True, False), (b'\xa1\xb2\xc3\xd4', False)),
            ((False, True, True), (b'\xa1\xb2\x3c\x4d', False)),
        ]
        for (lilendian, bigendian, nanosecond), expected in cases:
            with self.subTest(lilendian=lilendian, bigendian=bigendian, nanosecond=nanosecond):
                self.assertEqual(header._make_magic(lilendian=lilendian, bigendian=bigendian,
                                                    nanosecond=nanosecond), expected)

    def test_make_magic_byteorder_matches_endian_flags(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header

        header = object.__new__(Header)
        for byteorder in ('little', 'big'):
            for nanosecond in (False, True):
                with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                    self.assertEqual(
                        header._make_magic(byteorder, nanosecond=nanosecond),
                        header._make_magic(lilendian=byteorder == 'little',
                                           bigendian=byteorder == 'big', nanosecond=nanosecond),
                    )

    def test_read_protos_reads_size_bytes(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcap.header import Header

        header = object.__new__(Header)
        for size in (1, 2, 4):
            with self.subTest(size=size):
                header._file = io.BytesIO(int(LinkType.ETHERNET).to_bytes(size, 'little') + b'\xff' * 4)
                self.assertEqual(header._read_protos(size), LinkType.ETHERNET)
                self.assertEqual(header._file.tell(), size)


if __name__ == '__main__':
    unittest.main()
