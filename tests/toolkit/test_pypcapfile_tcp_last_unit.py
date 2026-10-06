"""Regression tests for the TCP sequence range of
:func:`pcapkit.toolkit.pypcapfile.tcp_reassembly` (GH#1100).

:attr:`TCP_Packet.last <pcapkit.foundation.reassembly.data.tcp.Packet.last>` is
the *inclusive* sequence number of the segment's last payload octet, as every
other toolkit adapter computes it. `pypcapfile`_ is not needed: its TCP decoder
is replaced by a stand-in carrying only the attributes the adapter reads.

.. _pypcapfile: https://github.com/kisom/pypcapfile

"""

from __future__ import annotations

import importlib.util
import struct
import sys
import types
import unittest
import unittest.mock

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class FakeTCP:
    """Stand-in for :class:`pcapfile.protocols.transport.tcp.TCP`."""

    def __init__(self, segment: bytes) -> None:
        (self.src_port, self.dst_port, self.seqnum, self.acknum,
         offset, flags) = struct.unpack('!HHIIBB', segment[:14])
        self.data_offset = (offset >> 4) * 4
        self.fin = flags & 0x01
        self.syn = (flags >> 1) & 0x01
        self.rst = (flags >> 2) & 0x01


class FakeIP:
    """Stand-in for :class:`pcapfile.protocols.network.ip.IP`."""

    def __init__(self, payload: bytes) -> None:
        self.p = 6
        self.src = b'10.1.1.2'
        self.dst = b'10.1.1.3'
        self.payload = payload


# NOTE: the toolkit recognises a decoded network layer by its class name.
FakeIP.__name__ = FakeIP.__qualname__ = 'IP'


def make_tcp(payload: bytes, *, seq: int = 1000) -> bytes:
    """Build a raw TCP segment with no options."""
    return struct.pack('!HHIIBBHHH', 51000, 22, seq, 2000, 5 << 4, 0x18,
                       8192, 0xCAFE, 0) + payload


def make_packet(segment: bytes) -> types.SimpleNamespace:
    """Build a stand-in for :class:`pcapfile.structs.pcap_packet`."""
    return types.SimpleNamespace(
        header=[types.SimpleNamespace(ns_resolution=False)],
        timestamp=1511106545,
        timestamp_us=471719,
        packet=types.SimpleNamespace(payload=FakeIP(segment)),
    )


def fake_pcapfile() -> dict[str, types.ModuleType]:
    """Build the :mod:`pcapfile` module tree the adapter imports from."""
    modules = {name: types.ModuleType(name) for name in (
        'pcapfile', 'pcapfile.protocols', 'pcapfile.protocols.transport',
        'pcapfile.protocols.transport.tcp',
    )}
    modules['pcapfile.protocols.transport.tcp'].TCP = FakeTCP  # type: ignore[attr-defined]
    return modules


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PyPCAPFileTCPLastTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = unittest.mock.patch.dict(sys.modules, fake_pcapfile())
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_last_is_the_inclusive_sequence_number_of_the_last_octet(self) -> None:
        from pcapkit.toolkit.pypcapfile import tcp_reassembly

        payload = b'SSH-2.0-OpenSSH_9.3\r\n'
        data = tcp_reassembly(make_packet(make_tcp(payload, seq=1000)), count=1)
        self.assertIsNotNone(data)
        self.assertEqual(data.first, 1000)
        self.assertEqual(data.len, len(payload))
        self.assertEqual(data.last, 1000 + len(payload) - 1)
        self.assertEqual(data.last - data.first + 1, data.len)

    def test_an_empty_segment_has_last_one_below_first(self) -> None:
        from pcapkit.toolkit.pypcapfile import tcp_reassembly

        data = tcp_reassembly(make_packet(make_tcp(b'', seq=5000)), count=1)
        self.assertIsNotNone(data)
        self.assertEqual(data.len, 0)
        self.assertEqual(data.first, 5000)
        self.assertEqual(data.last, 4999)


if __name__ == '__main__':
    unittest.main()
