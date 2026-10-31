# -*- coding: utf-8 -*-
"""GitHub issue #2438: the ``LinuxSLL`` family selector.

The versions share a family name, not a wire format, so they follow
:class:`~pcapkit.protocols.internet.ip.IP`: the family name selects either
version and each version's own name selects that version only. See
:ref:`linux-sll-labels`.

"""

import os
import struct
import tempfile
import unittest
import warnings

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))


def _header_v1(protocol_type: int = 0x0800) -> bytes:
    """Pack a minimal ``LINUX_SLL`` (v1) header."""
    link_addr = bytes.fromhex('001122334455').ljust(8, b'\x00')
    return struct.pack('>HHH', 0, 1, 6) + link_addr + struct.pack('>H', protocol_type)


def _header_v2(protocol_type: int = 0x0800) -> bytes:
    """Pack a minimal ``LINUX_SLL2`` header."""
    link_addr = bytes.fromhex('001122334455').ljust(8, b'\x00')
    return struct.pack('>HHIHBB', protocol_type, 0, 1, 1, 0, 6) + link_addr


def _pcap(records: 'list[bytes]', linktype: int) -> bytes:
    data = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, linktype)
    for record in records:
        data += struct.pack('<IIII', 1500000000, 0, len(record), len(record)) + record
    return data


def _extract(record: bytes, linktype: int, protocol: 'object' = None) -> 'str':
    """Build a one-frame capture and return its ``protochain.chain`` after extraction."""
    import pcapkit

    with tempfile.TemporaryDirectory() as tmp:
        path = os.path.join(tmp, 'x.pcap')
        with open(path, 'wb') as file:
            file.write(_pcap([record], linktype))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            kwargs = {} if protocol is None else {'protocol': protocol}
            extractor = pcapkit.extract(fin=path, nofile=True, store=True, **kwargs)
    return extractor.frame[0].protochain.chain


class TestLinuxSLLSelector(unittest.TestCase):
    """Pin :meth:`id` and :attr:`alias`, and the selectors they drive."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_id_and_alias_values(self) -> None:
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        self.assertEqual(LinuxSLL.id(), ('LinuxSLL1', 'LinuxSLL2'))
        self.assertEqual(LinuxSLL1.id(), ('LinuxSLL1',))
        self.assertEqual(LinuxSLL2.id(), ('LinuxSLL2',))

        self.assertEqual(LinuxSLL1(payload=b'').alias, 'LINUX_SLL1')
        self.assertEqual(LinuxSLL2(payload=b'').alias, 'LINUX_SLL2')

    def test_family_base_has_no_registry_index(self) -> None:
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.utilities.exceptions import UnsupportedCall

        with self.assertRaises(UnsupportedCall):
            LinuxSLL.__index__()

    def test_registered_in_the_name_registry(self) -> None:
        from pcapkit.protocols import __proto__ as registry
        from pcapkit.protocols.link.linux_sll import LinuxSLL

        self.assertIs(registry.get('LINUXSLL'), LinuxSLL)

    def test_family_name_selects_either_version(self) -> None:
        from pcapkit.protocols.link.linux_sll import LinuxSLL
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        v1 = LinuxSLL1(payload=b'')
        v2 = LinuxSLL2(payload=b'')

        self.assertIn('LinuxSLL', v1)
        self.assertIn('LinuxSLL', v2)
        self.assertIn(LinuxSLL, v1)
        self.assertIn(LinuxSLL, v2)

    def test_version_name_selects_only_that_version(self) -> None:
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        v1 = LinuxSLL1(payload=b'')
        v2 = LinuxSLL2(payload=b'')

        self.assertIn('LinuxSLL1', v1)
        self.assertNotIn('LinuxSLL1', v2)
        self.assertIn('LinuxSLL2', v2)
        self.assertNotIn('LinuxSLL2', v1)

    def test_class_selector_is_version_narrow(self) -> None:
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
        from pcapkit.protocols.link.linux_sll2 import LinuxSLL2

        v1 = LinuxSLL1(payload=b'')
        v2 = LinuxSLL2(payload=b'')

        self.assertIn(LinuxSLL1, v1)
        self.assertNotIn(LinuxSLL1, v2)
        self.assertIn(LinuxSLL2, v2)
        self.assertNotIn(LinuxSLL2, v1)

    def test_string_eq_is_narrower_than_in_for_the_family_name(self) -> None:
        """String ``==`` compares against ``(cls, *id())`` only, so a family name is not ``==``."""
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        v1 = LinuxSLL1(payload=b'')

        self.assertTrue(v1 == 'LinuxSLL1')
        self.assertFalse(v1 == 'LinuxSLL')
        self.assertIn('LinuxSLL', v1)

    def test_extract_family_name_stops_at_either_version(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        # A stopped layer's Raw payload is named after the EtherType it would
        # have dispatched on, as a stopped Ethernet frame's is.
        self.assertEqual(_extract(_header_v1() + IPV4, LinkType.LINUX_SLL, 'LinuxSLL'),
                         'LINUX_SLL1:Internet_Protocol_version_4')
        self.assertEqual(_extract(_header_v2() + IPV4, LinkType.LINUX_SLL2, 'LinuxSLL'),
                         'LINUX_SLL2:Internet_Protocol_version_4')

    def test_extract_version_name_stops_only_that_version(self) -> None:
        from pcapkit.const.reg.linktype import LinkType

        self.assertEqual(_extract(_header_v1() + IPV4, LinkType.LINUX_SLL, 'LinuxSLL1'),
                         'LINUX_SLL1:Internet_Protocol_version_4')
        self.assertEqual(_extract(_header_v2() + IPV4, LinkType.LINUX_SLL2, 'LinuxSLL1'),
                         'LINUX_SLL2:IPv4:UDP')

        self.assertEqual(_extract(_header_v2() + IPV4, LinkType.LINUX_SLL2, 'LinuxSLL2'),
                         'LINUX_SLL2:Internet_Protocol_version_4')
        self.assertEqual(_extract(_header_v1() + IPV4, LinkType.LINUX_SLL, 'LinuxSLL2'),
                         'LINUX_SLL1:IPv4:UDP')


if __name__ == '__main__':
    unittest.main()
