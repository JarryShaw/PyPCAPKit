# -*- coding: utf-8 -*-
"""The PCAP dumper takes its link type as a name, a member or a code (GitHub issue #2594).

``Header.make`` takes a member or an :class:`int` code for ``network`` and refuses a
name (#2594). :class:`~pcapkit.dumpkit.pcap.PCAPIO`'s ``protocol`` takes a name as
well, which ``PCAPIO._dump_header`` resolves with ``Header.resolve_index`` before it
reaches ``Header.make``: a known name writes its link type, and an unknown one raises
:exc:`~pcapkit.utilities.exceptions.ProtocolNotImplemented`, not the
:exc:`~pcapkit.utilities.exceptions.ProtocolError` ``Header.make`` raises for a name.

Every case writes its own header into a temporary directory and reads no capture.
Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import os
import struct
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class TestPCAPIOLinkType(unittest.TestCase):
    """``PCAPIO(path, protocol=...)`` writes the link type it names."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory(prefix='pcapkit-pcapio-linktype-')
        self.addCleanup(self.tmpdir.cleanup)

    def _header(self, protocol: 'Any') -> 'bytes':
        from pcapkit.dumpkit.pcap import PCAPIO

        path = os.path.join(self.tmpdir.name, f'{len(os.listdir(self.tmpdir.name))}.pcap')
        PCAPIO(path, protocol=protocol, byteorder='little', nanosecond=False)
        with open(path, 'rb') as file:
            return file.read()

    def test_a_name_writes_its_link_type(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        header = self._header('ETHERNET')
        self.assertEqual(header, self._header(LinkType.ETHERNET))
        self.assertEqual(struct.unpack('<I', header[20:24])[0], 1)

    def test_a_member_and_a_code_write_the_same(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(self._header(1), self._header(LinkType.ETHERNET))
        # a code no member holds is written as given
        self.assertEqual(struct.unpack('<I', self._header(0xFFFF)[20:24])[0], 0xFFFF)

    def test_an_unknown_name_is_not_implemented(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError, ProtocolNotImplemented

        with self.assertRaises(ProtocolNotImplemented) as context:
            self._header('NO_SUCH_LINKTYPE')
        self.assertNotIsInstance(context.exception, ProtocolError)

    def test_a_code_the_field_cannot_carry_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for value in (True, -1, 1 << 32):
            with self.subTest(value=value):
                with self.assertRaises(ProtocolError):
                    self._header(value)


if __name__ == '__main__':
    unittest.main()
