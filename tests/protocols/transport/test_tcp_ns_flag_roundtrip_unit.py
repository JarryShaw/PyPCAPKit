"""#1098 -- the TCP NS flag round-trips through read, ``make()`` and ``from_data``.

:meth:`TCP.make <pcapkit.protocols.transport.tcp.TCP.make>` accepts ``ns`` and
packs it into bit 103 (the low bit of byte 12), and
:class:`~pcapkit.protocols.schema.transport.tcp.OffsetFlag` declares the bit. The
reader and :meth:`TCP._make_data <pcapkit.protocols.transport.tcp.TCP._make_data>`
must carry it too, so a parsed segment exposes ``flags.ns`` and a
:meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data` rebuild keeps the bit
on the wire rather than clearing it silently.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TCPNSFlagRoundTripUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_make_sets_ns_on_the_wire(self) -> None:
        """``make(ns=True)`` sets the low bit of byte 12, next to a data offset of 5."""
        from pcapkit.protocols.transport.tcp import TCP

        self.assertEqual(TCP(srcport=1, dstport=2, ns=True).data[12], 0x51)
        self.assertEqual(TCP(srcport=1, dstport=2, ns=False).data[12], 0x50)

    def test_read_exposes_ns(self) -> None:
        """A parsed segment reports ``flags.ns`` as read from bit 103."""
        from pcapkit.protocols.transport.tcp import TCP

        for ns in (True, False):
            with self.subTest(ns=ns):
                raw = TCP(srcport=1, dstport=2, ns=ns).data
                self.assertIs(TCP(raw).info.flags.ns, ns)

    def test_from_data_keeps_ns(self) -> None:
        """A ``from_data`` rebuild of a parsed segment reproduces its bytes, NS included."""
        from pcapkit.protocols.transport.tcp import TCP

        for ns in (True, False):
            with self.subTest(ns=ns):
                raw = TCP(srcport=1, dstport=2, ns=ns, ack=True).data
                rebuilt = TCP.from_data(TCP(raw).info)
                self.assertEqual(rebuilt.data, raw)
                self.assertIs(rebuilt.info.flags.ns, ns)

    def test_flags_field_order(self) -> None:
        """``ns`` leads the flags, in wire order, ahead of ``cwr``."""
        from pcapkit.protocols.transport.tcp import TCP

        flags = TCP(TCP(srcport=1, dstport=2).data).info.flags
        self.assertEqual(list(flags.keys()),
                         ['ns', 'cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'])


if __name__ == '__main__':
    unittest.main()
