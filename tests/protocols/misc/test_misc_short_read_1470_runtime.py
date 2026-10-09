# -*- coding: utf-8 -*-
"""A PCAP global header or PCAP-NG block cut short rebuilds as captured.

GitHub issue #1470. The two classes under :mod:`pcapkit.protocols.misc` that
read a file's own framing do not inherit the layer base classes, so the short
read #1458 records did not reach them. ``Header(raw[:4])`` rebuilt from its
``info`` as all 24 octets, and a PCAP-NG block the capture ended inside rebuilt
at the length it declares, or raised -- :exc:`ProtocolError` on a rebuilt Block
Total Length that was not a multiple of four, and a bare :exc:`ValueError` on a
Decryption Secrets Block cut inside a TLS key log line.

Each header and each block type found in the sample captures is cut at every
offset. A PCAP header must be refused with an in-library exception, or rebuild
as the octets cut. A PCAP-NG block of fewer than the twelve octets any block
needs is end-of-stream; one of twelve or more must parse, and rebuild as the
octets cut. Every rebuild is checked from both ``info`` and ``info.to_dict()``.

The module reads generated captures, so it belongs to the fixture-dependent tier.
Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import importlib.util
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class, time_limit
from tests._tiers import SAMPLE_ROOT

if TYPE_CHECKING:
    from typing import Any, Iterator

RUNTIME_DEPS = ('aenum', 'chardet')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Whole seconds one sweep may take. Each takes well under a minute.
SWEEP_TIMEOUT = 300

#: Section Header Block type, the same read in either byte order.
SHB = b'\x0a\x0d\x0d\x0a'


def _captures(suffix: 'str') -> 'list[str]':
    """Every sample capture whose name ends in ``suffix``."""
    return sorted(path.name for path in SAMPLE_ROOT.iterdir() if path.name.endswith(suffix))


def _blocks(data: 'bytes') -> 'Iterator[tuple[int, bytes]]':
    """Every block of a PCAP-NG file, as its type and its octets."""
    offset, endian = 0, '<'
    while offset + 12 <= len(data):
        if data[offset:offset + 4] == SHB:
            endian = '<' if data[offset + 8:offset + 12] == b'\x4d\x3c\x2b\x1a' else '>'
        type_, length = struct.unpack(f'{endian}II', data[offset:offset + 8])
        yield type_, data[offset:offset + length]
        offset += length


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestMiscShortRead(unittest.TestCase):
    """Pin byte-exact rebuilds of PCAP headers and PCAP-NG blocks cut short."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        # a cut block warns that its length runs past the data, which is the point
        warnings.simplefilter('ignore')

    def test_pcap_header_cut_at_every_offset(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.exceptions import BaseError

        names = _captures('.pcap')
        self.assertGreater(len(names), 2, f'no generated captures under {SAMPLE_ROOT}')
        with time_limit(SWEEP_TIMEOUT):
            for name in names:
                raw = (SAMPLE_ROOT / name).read_bytes()[:24]
                for keep in range(1, 25):
                    cut = raw[:keep]
                    with self.subTest(capture=name, keep=keep):
                        try:
                            header = Header(cut)
                        except BaseError:
                            # no magic number to tell the file format by
                            self.assertLess(keep, 4)
                            continue
                        self.assertEqual(header.data, cut)
                        self.assertEqual(Header.from_data(header.info).data.hex(), cut.hex())
                        self.assertEqual(Header.from_data(header.info.to_dict()).data.hex(), cut.hex())

    def test_issue_1470_repro(self) -> None:
        from pcapkit.protocols.misc.pcap.header import Header

        raw = (SAMPLE_ROOT / _captures('.pcap')[0]).read_bytes()[:24]
        header = Header(raw[:4])
        self.assertEqual(len(header.data), 4)
        self.assertEqual(len(Header.from_data(header.info).data), 4)
        # a header captured whole is untouched
        self.assertEqual(Header.from_data(Header(raw).info).data, raw)

    def _each_block(self) -> 'Iterator[tuple[str, str, bytes, dict[str, Any]]]':
        """The first block of each type in each PCAP-NG capture, with its keywords."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        names = _captures('.pcapng')
        self.assertGreater(len(names), 2, f'no generated captures under {SAMPLE_ROOT}')
        for name in names:
            ctx, num, sct, seen = None, 0, 0, set()
            for type_, raw in _blocks((SAMPLE_ROOT / name).read_bytes()):
                if raw[:4] == SHB:
                    sct += 1
                    kwargs = {'num': 0, 'sct': sct, 'ctx': None}  # type: dict[str, Any]
                else:
                    num += 1
                    kwargs = {'num': num, 'sct': sct, 'ctx': ctx}
                whole = PCAPNG(raw, len(raw), **kwargs)
                if type_ not in seen:
                    seen.add(type_)
                    yield name, BlockType.get(type_).name, raw, kwargs
                if raw[:4] == SHB:
                    ctx = Context(whole.info)
                    whole._ctx = ctx  # pylint: disable=protected-access
                elif type_ == BlockType.Interface_Description_Block:
                    ctx.interfaces.append(whole.info)

    def test_pcapng_block_cut_at_every_offset(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import StreamEOFError

        types = set()
        with time_limit(SWEEP_TIMEOUT):
            for name, block, raw, kwargs in self._each_block():
                types.add(block)
                for keep in range(1, len(raw)):
                    cut = raw[:keep]
                    with self.subTest(capture=name, block=block, keep=keep):
                        if keep < 12:
                            with self.assertRaises(StreamEOFError):
                                PCAPNG(cut, len(cut), **kwargs)
                            continue
                        parsed = PCAPNG(cut, len(cut), **kwargs)
                        self.assertEqual(parsed.data, cut)
                        self.assertEqual(parsed.info.__truncated_raw__, cut)
                        self.assertEqual(PCAPNG.from_data(parsed.info, **kwargs).data.hex(), cut.hex())
                        self.assertEqual(PCAPNG.from_data(parsed.info.to_dict(), **kwargs).data.hex(), cut.hex())
        # every block type the samples hold was swept
        self.assertGreaterEqual(len(types), 8, sorted(types))

    def test_pcapng_whole_block_is_untouched(self) -> None:
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for name, block, raw, kwargs in self._each_block():
            with self.subTest(capture=name, block=block):
                parsed = PCAPNG(raw, len(raw), **kwargs)
                self.assertNotIn('__truncated_raw__', parsed.info)
                self.assertEqual(PCAPNG.from_data(parsed.info, **kwargs).data.hex(), raw.hex())

    def test_cut_block_keeps_its_fields(self) -> None:
        # the fields the capture holds still parse, so a cut packet keeps its packet
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        for name, block, raw, kwargs in self._each_block():
            if block != BlockType.Enhanced_Packet_Block.name:
                continue
            with self.subTest(capture=name):
                whole = PCAPNG(raw, len(raw), **kwargs).info
                cut = PCAPNG(raw[:40], 40, **kwargs).info
                self.assertEqual(cut.length, whole.length)
                self.assertEqual(cut.captured_len, whole.captured_len)
                self.assertEqual(cut.timestamp_epoch, whole.timestamp_epoch)
                self.assertEqual(bytes(cut.packet), raw[28:40])


class TestKeyLogLines(unittest.TestCase):
    """Pin how the TLS and WireGuard key logs treat a line that does not parse."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _unpack(self, schema: 'str', text: 'bytes', length: 'int') -> 'Any':
        import importlib

        cls = getattr(importlib.import_module('pcapkit.protocols.schema.misc.pcapng'), schema)
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            return cls.unpack(text, length)

    def test_cut_last_line_is_left_out_of_entries(self) -> None:
        line = b'CLIENT_RANDOM ' + b'ab' * 32 + b' ' + b'cd' * 48 + b'\n'
        text = line + line[:20]
        schema = self._unpack('TLSKeyLog', text, len(line) * 2)
        self.assertTrue(schema.data.startswith(text.decode()), schema.data)
        self.assertEqual(sum(len(value) for value in schema.entries.values()), 1)

        line = b'LOCAL_STATIC_PRIVATE_KEY = ' + b'QUFB' * 11 + b'QUE=\n'
        text = line + line[:10]
        schema = self._unpack('WireGuardKeyLog', text, len(line) * 2)
        self.assertTrue(schema.data.startswith(text.decode()), schema.data)
        self.assertEqual(len(schema.entries), 1)

    def test_malformed_line_of_a_whole_log_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        text = b'CLIENT_RANDOM abcd\n'
        with self.assertRaisesRegex(FieldValueError, r"^invalid TLS key log format: 'CLIENT_RANDOM abcd'$"):
            self._unpack('TLSKeyLog', text, len(text))

        text = b'LOCAL_STATIC_PRIVATE_KEY = Q\n'
        with self.assertRaisesRegex(FieldValueError,
                                    r"^invalid WireGuard key log format: 'LOCAL_STATIC_PRIVATE_KEY = Q'$"):
            self._unpack('WireGuardKeyLog', text, len(text))


if __name__ == '__main__':
    unittest.main()
