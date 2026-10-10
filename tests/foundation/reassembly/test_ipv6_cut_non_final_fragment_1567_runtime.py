# -*- coding: utf-8 -*-
"""A snaplen-cut first IPv6 fragment leaves a hole under every engine.

GitHub issue #1567. A 3-fragment IPv6 datagram of 64, 64 and 72 octets, its
first fragment captured to 60 octets, came out ``COMPLETE`` with octets 60-63
zero-filled under the default, dpkt and scapy engines, since every IPv6 adapter
passes ``tl`` as the captured length. The fix is in the reassembler they share,
so each engine is run over the same capture here and has to report the same
``PARTIAL`` datagram.

The captures are built in memory, through the engines, so the module belongs to
the fixture-dependent tier.

"""
from __future__ import annotations

import importlib.util
import os
import struct
import tempfile
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import close_extractor, reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
ENGINES = ('default',) + tuple(name for name in ('dpkt', 'scapy') if importlib.util.find_spec(name) is not None)

#: The datagram, with no zero octet in it, so a hole shows.
DATA = bytes((i * 7 + 3) % 251 + 1 for i in range(200))

#: Its three fragments, as ``(fragment offset, more fragments, payload)``.
FRAGMENTS = ((0, 1, DATA[0:64]), (64, 1, DATA[64:128]), (128, 0, DATA[128:200]))

#: Ethernet, IPv6 and Fragment header octets before a fragment's payload.
HEADERS = 14 + 40 + 8


def _frames() -> 'list[bytes]':
    """The three fragments as Ethernet frames, uncut."""
    frames = []
    for offset, more, payload in FRAGMENTS:
        # Next Header UDP; the offset field is (offset // 8) << 3, i.e. the offset in octets
        frag = struct.pack('!BBHI', 17, 0, offset | more, 9)
        ipv6 = struct.pack('!IHBB16s16s', 0x60000000, len(frag) + len(payload), 44, 64,
                           bytes.fromhex('20010db8000000000000000000000001'),
                           bytes.fromhex('20010db8000000000000000000000002'))
        frames.append(bytes.fromhex('020000000002 020000000001 86dd') + ipv6 + frag + payload)
    return frames


def _pcap(cut: 'int | None') -> 'bytes':
    """A libpcap capture of the fragments, the first captured to ``cut`` payload octets."""
    output = bytearray(struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
    for index, frame in enumerate(_frames()):
        data = frame if index or cut is None else frame[:HEADERS + cut]
        output += struct.pack('<IIII', 1000 + index, 0, len(data), len(frame)) + data
    return bytes(output)


def _pcapng(cut: 'int | None') -> 'bytes':
    """The same capture as PCAP-NG: one section, one Ethernet interface."""
    def block(block_type: 'int', body: 'bytes') -> 'bytes':
        body += b'\x00' * (-len(body) % 4)
        return struct.pack('<II', block_type, 12 + len(body)) + body + struct.pack('<I', 12 + len(body))

    output = block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
    output += block(0x00000001, struct.pack('<HHI', 1, 0, 65535))
    for index, frame in enumerate(_frames()):
        data = frame if index or cut is None else frame[:HEADERS + cut]
        output += block(0x00000006, struct.pack('<IIIII', 0, 0, index, len(data), len(frame)) + data)
    return output


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv6CutFragmentEngineTests(unittest.TestCase):
    """Every engine reports a cut non-final IPv6 fragment as a hole."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp = tmp.name

    def _datagrams(self, name: 'str', octets: 'bytes', engine: 'str', strict: 'bool') -> 'Any':
        from pcapkit import extract

        path = os.path.join(self.tmp, name)
        with open(path, 'wb') as file:
            file.write(octets)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = extract(fin=path, nofile=True, engine=engine, ipv6=True,
                                reassembly=True, reasm_strict=strict)
        self.addCleanup(close_extractor, extractor)
        return extractor.reassembly.ipv6

    def _cases(self):
        for fmt, build in (('pcap', _pcap), ('pcapng', _pcapng)):
            for engine in ENGINES if fmt == 'pcap' else ('default',):
                for strict in (True, False):
                    yield fmt, build, engine, strict

    def test_a_cut_first_fragment_leaves_a_hole(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for cut in (60, 52):
            for fmt, build, engine, strict in self._cases():
                with self.subTest(cut=cut, fmt=fmt, engine=engine, strict=strict):
                    datagram, = self._datagrams(f'cut-{cut}.{fmt}', build(cut), engine, strict)
                    self.assertIs(datagram.completed, Completion.PARTIAL)
                    self.assertEqual(datagram.index, (1, 2, 3))
                    self.assertEqual(datagram.payload,
                                     (DATA[:cut // 8 * 8], DATA[64:]) if strict
                                     else DATA[:cut] + bytes(64 - cut) + DATA[64:])

    def test_an_uncut_capture_completes_byte_exact(self) -> None:
        from pcapkit.foundation.reassembly.data.data import Completion

        for fmt, build, engine, strict in self._cases():
            with self.subTest(fmt=fmt, engine=engine, strict=strict):
                datagram, = self._datagrams(f'whole.{fmt}', build(None), engine, strict)
                self.assertIs(datagram.completed, Completion.COMPLETE)
                self.assertEqual(datagram.payload, DATA)


if __name__ == '__main__':
    unittest.main()
