from __future__ import annotations

import importlib.util
import unittest
from unittest import mock

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6ReadIPHextetUnitTests(unittest.TestCase):
    """GitHub issue #1094: the traffic class and flow label exclude the version nibble."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_read_ip_hextet_splits_version_class_and_label(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        proto = object.__new__(IPv6)
        proto._read_fileng = mock.Mock(return_value=bytes.fromhex('6abcdef0'))

        self.assertEqual(proto._read_ip_hextet(), (6, 0xab, 0xcdef0))
        proto._read_fileng.assert_called_once_with(4)

    def test_read_ip_hextet_agrees_with_schema_packing(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv6 import IPv6

        proto = object.__new__(IPv6)
        header = proto.make(
            traffic_class=0xff,
            flow_label=0xfffff,
            next=TransType.UDP,
            hop_limit=64,
            src='2001:db8::1',
            dst='2001:db8::2',
            payload=b'',
        ).pack()

        proto._read_fileng = mock.Mock(return_value=header[:4])
        self.assertEqual(proto._read_ip_hextet(), (6, 0xff, 0xfffff))


if __name__ == '__main__':
    unittest.main()
