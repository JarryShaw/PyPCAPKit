# -*- coding: utf-8 -*-
"""GitHub issue #2588: a next-layer refusal the parent's fallback handles is quiet.

When :func:`~pcapkit.corekit.decorators.beholder` keeps a refused next layer as
:class:`~pcapkit.protocols.misc.raw.Raw`, the refusal's
:exc:`~pcapkit.utilities.exceptions.ProtocolError` logs nothing on the
``pcapkit`` logger, at any level, and leaves :data:`sys.excepthook` and
:data:`threading.excepthook` as they were. The ``Raw`` layer's ``error`` still
records it, and the frame rebuilds byte for byte. Building the refused layer
directly, with no fallback to handle it, stays loud.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import sys
import threading
import unittest

from tests._support import reimport_once_per_class
from tests.utilities._harness import capture

#: Test tier (#1958): exercises threading, locking or warning and exception hooks, which
#: differ by interpreter.
__tier__ = 'ALL'

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: A GRE header of version 1, which :rfc:`2784` refuses, carrying :data:`IPV4`.
GRE_V1 = struct.pack('>HH', 1, 0x0800) + IPV4
#: A ``LINUX_SLL`` frame whose ``ARPHRD_IPGRE`` payload is :data:`GRE_V1`.
SLL_GRE_V1 = struct.pack('>HHH8sH', 0, 778, 0, b'', 0x0800) + GRE_V1
#: :data:`IPV4` with its version nibble set to 5.
IPV4_V5 = b'\x55' + IPV4[1:]
#: An Ethernet frame whose IPv4 payload is :data:`IPV4_V5`.
ETH_IPV4_V5 = bytes(12) + b'\x08\x00' + IPV4_V5
#: A TCP header whose data offset, 60 octets, runs past its 20.
TCP_LONG = struct.pack('>HHIIBBHHH', 1, 2, 0, 0, 0xF0, 0x02, 0, 0, 0)
#: An Ethernet frame carrying a valid IPv4 header whose TCP payload is :data:`TCP_LONG`.
ETH_IPV4_TCP_LONG = (bytes(12) + b'\x08\x00'
                     + bytes.fromhex('4500002800010000400600000a0000010a000002') + TCP_LONG)


class TestHandledRefusalIsQuiet(unittest.TestCase):
    """Pin that a refusal a next-layer fallback handles logs nothing and hooks nothing."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # NOTE: Imported before the sentinels go in, since importing pcapkit
        # outside development mode installs tbtrim's hook itself.
        import pcapkit  # pylint: disable=import-outside-toplevel,unused-import
        saved = sys.excepthook, threading.excepthook

        def restore() -> None:
            sys.excepthook, threading.excepthook = saved

        self.addCleanup(restore)

        def sentinel(*args: 'object') -> None:
            sys.__excepthook__(*args)  # type: ignore[arg-type]

        def thread_sentinel(args: 'object') -> None:
            pass

        self.sentinels = sentinel, thread_sentinel
        sys.excepthook, threading.excepthook = self.sentinels

    def assert_hooks_untouched(self) -> None:
        self.assertIs(sys.excepthook, self.sentinels[0])
        self.assertIs(threading.excepthook, self.sentinels[1])

    def assert_quiet_fallback(self, klass, frame: 'bytes', chain: 'str', depth: 'int',  # type: ignore[no-untyped-def]
                              error: 'str') -> None:
        """``frame`` parses, keeping the layer ``depth`` down as ``Raw`` with ``error``, quietly."""
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.logging import logger

        with capture(logger) as recorder:
            parsed = klass(frame, len(frame))
            rebuilt = [klass.from_data(data).data for data in (parsed.info, parsed.info.to_dict())]
        self.assertEqual(recorder.messages, [])
        self.assert_hooks_untouched()

        layer = parsed
        for _ in range(depth):
            layer = layer.payload
        self.assertIs(type(layer), Raw)
        self.assertEqual(layer.info.error, error)
        self.assertEqual(str(parsed.protochain), chain)
        self.assertEqual(parsed.data, frame)
        self.assertEqual(rebuilt, [frame, frame])

    def assert_direct_construction_is_loud(self, klass, data: 'bytes',  # type: ignore[no-untyped-def]
                                           error: 'str') -> None:
        """Building the refused layer itself raises, logs at ``CRITICAL`` and, outside devmode, hooks."""
        from pcapkit.utilities.exceptions import ProtocolError
        from pcapkit.utilities.logging import DEVMODE, logger

        with capture(logger) as recorder:
            with self.assertRaises(ProtocolError) as context:
                klass(data, len(data))
        self.assertEqual(str(context.exception), error)
        self.assertEqual(recorder.messages, [('CRITICAL', f'ProtocolError: {error}')])
        if not DEVMODE:
            self.assertIsNot(sys.excepthook, self.sentinels[0])
            self.assertIsNot(threading.excepthook, self.sentinels[1])

    def test_refused_gre_under_linux_sll_is_quiet(self) -> None:
        """GRE refuses version 1; LinuxSLL's fallback keeps it as ``Raw``, and ``GRE(...)`` stays loud."""
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.protocols.link.linux_sll1 import LinuxSLL1

        self.assert_quiet_fallback(LinuxSLL1, SLL_GRE_V1, 'LINUX_SLL1:Raw', 1,
                                   'GRE: invalid version: 1')
        self.assert_direct_construction_is_loud(GRE, GRE_V1, 'GRE: invalid version: 1')

    def test_refused_ipv4_under_ethernet_is_quiet(self) -> None:
        """IPv4 refuses version 5; Ethernet's fallback keeps it as ``Raw``, and ``IPv4(...)`` stays loud."""
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.link.ethernet import Ethernet

        self.assert_quiet_fallback(Ethernet, ETH_IPV4_V5, 'Ethernet:Internet_Protocol_version_4', 1,
                                   '[IPv4] invalid version: 5')
        self.assert_direct_construction_is_loud(IPv4, IPV4_V5, '[IPv4] invalid version: 5')

    def test_nested_refusal_is_quiet_and_the_block_ends_with_the_frame(self) -> None:
        """TCP refused under IPv4 under Ethernet is quiet; once the frame is parsed, nothing is quieted."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities import exceptions

        error = 'TCP: header length 60 runs past the end of the data (20 octets)'
        self.assert_quiet_fallback(Ethernet, ETH_IPV4_TCP_LONG, 'Ethernet:IPv4:TCP', 2, error)
        self.assertEqual(exceptions._caught_here.get(), ())  # pylint: disable=protected-access
        self.assert_direct_construction_is_loud(TCP, TCP_LONG, error)


if __name__ == '__main__':
    unittest.main()
