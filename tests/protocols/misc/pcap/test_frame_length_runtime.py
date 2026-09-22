# -*- coding: utf-8 -*-
"""``Frame.len`` is the on-wire length and ``Frame.cap_len`` the captured one.

Both readers that build a
:class:`~pcapkit.protocols.data.misc.pcap.frame.Frame` have to agree about which
of the two wire fields lands in which attribute, and until GitHub issue #618 they
did not: the classic-PCAP reader in
:mod:`pcapkit.protocols.misc.pcap.frame` wrote ``len=incl_len,
cap_len=orig_len`` while :func:`pcapkit.toolkit.pcapng.block2frame` wrote
``len=original_len, cap_len=captured_len``. Exactly inverted, so ``frame.len``
meant the *captured* length out of a ``.pcap`` and the *on-wire* length out of a
``.pcapng``.

The PCAP reader was the wrong one. The names are Wireshark's, and its
:file:`epan/dissectors/packet-frame.c` settles which way round they go:
``frame.len`` is registered as "Frame length on the wire" and ``frame.cap_len``
as "Frame length stored into the capture file", and the expert info
``frame.len_lt_caplen`` -- "Frame length is less than captured length",
``PI_MALFORMED``/``PI_ERROR`` -- fires on ``frame_len < cap_len``, which it
could not be if ``len`` were the smaller, captured one.
:mod:`pcapkit.toolkit.pyshark` reads those very field names off a tshark frame,
so the library already leant on that reading.

The underlying wire fields mean the same thing in both containers.
:manpage:`pcap-savefile(5)` gives ``incl_len`` as "the number of bytes of
captured data that follow the per-packet header" and ``orig_len`` as "the number
of bytes that would have been present had the packet not been truncated by the
snapshot length"; ``draft-ietf-opsawg-pcapng`` gives Captured Packet Length as
"the number of octets captured from the packet" against Original Packet Length's
"number of octets of packet data that would have been provided had the packet not
been truncated", which "SHOULD NOT be less than the Captured Packet Length". So
neither format is the odd one out -- only the reader was.

Why it survived so long: **the two lengths are equal unless the snapshot length
cut the frame short**, so a fixture without a truncated frame compares a value
against itself and cannot tell the two assignments apart. There was no such
fixture here until #614 added one. This module therefore leans on the two that
exist, and asserts that they really are truncated before asserting anything
about them -- a fixture regenerated into something untruncated fails
:meth:`PcapFrameLengthRuntimeTests.test_the_fixture_really_holds_a_truncated_frame`
loudly rather than making everything below vacuous:

======================= ==================== ==========================
Fixture                 Truncated frame      ``orig_len`` / ``incl_len``
======================= ==================== ==========================
``big_endian.pcap``     frame 3              1200 / 96
``little_endian.pcap``  frame 3              1200 / 96
``big_endian_nanosecond.pcap`` frame 3       1200 / 96
``test.pcapng``         the third packet      314 / 32
                        block
======================= ==================== ==========================

Expectations are taken from the files themselves with :mod:`struct` as well as
written down, deliberately without going through :mod:`pcapkit`, so that the
thing under test is not also the thing supplying the answer.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The classic-PCAP fixtures that carry a truncated frame, as ``(name, struct
#: byte-order prefix)``. All three come from :file:`examples/generators/endian.py`
#: and hold the same three records, the third of them captured short.
PCAP_FIXTURES = (
    ('big_endian.pcap', '>'),
    ('little_endian.pcap', '<'),
    ('big_endian_nanosecond.pcap', '>'),
)

#: ``(incl_len, orig_len)`` of the truncated record those fixtures carry: 1200
#: octets on the wire, cut to the 96-octet ``snaplen`` in the global header.
PCAP_TRUNCATED = (96, 1200)

#: ``(captured_len, original_len)`` of the truncated Enhanced Packet Block in
#: ``test.pcapng``, written by :file:`examples/generators/pcapng.py`.
PCAPNG_TRUNCATED = (32, 314)

#: PCAP-NG block type of an Enhanced Packet Block.
ENHANCED_PACKET_BLOCK = 0x0000_0006
#: PCAP-NG block type of a Section Header Block. Chosen by the format to read the
#: same in either byte order, so it can be recognised before the byte order is
#: known.
SECTION_HEADER_BLOCK = b'\x0a\x0d\x0d\x0a'
#: The Section Header Block's byte-order magic, keyed by the :mod:`struct` prefix
#: it selects.
BYTE_ORDER_MAGIC = {b'\x1a\x2b\x3c\x4d': '>', b'\x4d\x3c\x2b\x1a': '<'}


def pcap_record_lengths(raw: 'bytes', endian: 'str') -> 'list[tuple[int, int]]':
    """Walk a classic PCAP's record chain straight out of its octets.

    Deliberately independent of :mod:`pcapkit`, for the reason the module
    docstring gives. The same idiom as
    :file:`tests/protocols/misc/pcap/test_frame_endian_runtime.py`, narrowed to
    the two length fields this module is about.

    Args:
        raw: The whole file.
        endian: :mod:`struct` byte-order prefix, ``'>'`` or ``'<'``.

    Returns:
        One ``(incl_len, orig_len)`` pair per record, in file order.

    """
    lengths = []
    offset = 24  # the global header is 24 octets
    while offset < len(raw):
        incl_len, orig_len = struct.unpack_from(f'{endian}II', raw, offset + 8)
        lengths.append((incl_len, orig_len))
        offset += 16 + incl_len  # 16-octet record header, then incl_len octets
    return lengths


def pcapng_packet_lengths(raw: 'bytes') -> 'list[tuple[int, int]]':
    """Walk a PCAP-NG file's Enhanced Packet Blocks straight out of its octets.

    The byte order is re-read at every Section Header Block rather than once for
    the file: a PCAP-NG file may hold several sections and each declares its own,
    and ``test.pcapng`` does hold more than one. That the Section Header Block's
    type reads identically in both orders is what makes it recognisable before
    the order is known, which is why the format chose it.

    Simple Packet Blocks are skipped. They carry only an original length and
    derive the captured one from the interface's snapshot length, so they cannot
    exhibit the disagreement this module is about.

    Args:
        raw: The whole file.

    Returns:
        One ``(captured_len, original_len)`` pair per Enhanced Packet Block, in
        file order.

    Raises:
        ValueError: If a Section Header Block carries neither byte-order magic,
            or a block declares a length that does not fit the file. Raising
            beats returning a short list, which would silently weaken every
            assertion made against it.

    """
    lengths = []
    offset = 0
    endian = None  # type: str | None
    while offset + 12 <= len(raw):
        if raw[offset:offset + 4] == SECTION_HEADER_BLOCK:
            magic = raw[offset + 8:offset + 12]
            if magic not in BYTE_ORDER_MAGIC:
                raise ValueError(f'section header block at {offset} carries no '
                                 f'byte-order magic: {magic!r}')
            endian = BYTE_ORDER_MAGIC[magic]
        if endian is None:
            raise ValueError(f'block at {offset} precedes any section header block')

        block_type, total = struct.unpack_from(f'{endian}II', raw, offset)
        if total < 12 or offset + total > len(raw):
            raise ValueError(f'block at {offset} declares a total length of '
                             f'{total}, which does not fit {len(raw)} octets')

        if block_type == ENHANCED_PACKET_BLOCK:
            # interface id, timestamp high, timestamp low, then the two lengths
            captured, original = struct.unpack_from(f'{endian}II', raw, offset + 20)
            lengths.append((captured, original))

        offset += total
    return lengths


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapFrameLengthRuntimeTests(unittest.TestCase):
    """#618, on the classic-PCAP reader -- the one that was wrong."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def frames(self, name: 'str') -> 'tuple[bytes, list]':
        """Read a fixture's octets and the frames :mod:`pcapkit` parses from it.

        Args:
            name: Bare fixture file name.

        Returns:
            The file's octets, and the parsed frames.

        """
        from pcapkit.interface import extract

        path = sample_path(name)
        with open(path, 'rb') as stream:
            raw = stream.read()
        return raw, list(extract(fin=path, store=True, nofile=True).frame)

    def test_the_fixture_really_holds_a_truncated_frame(self) -> None:
        """The premise every other test here rests on.

        ``incl_len`` and ``orig_len`` are equal for a frame that was captured
        whole, so a fixture without a truncated frame cannot distinguish
        ``len=incl_len, cap_len=orig_len`` from ``len=orig_len,
        cap_len=incl_len``: both satisfy every assertion. This asserts the
        distinguishing frame is present, and by how much the two differ, so that
        a fixture regenerated without it fails here rather than turning the rest
        of the module green for the wrong reason.

        """
        for name, endian in PCAP_FIXTURES:
            with self.subTest(fixture=name):
                with open(sample_path(name), 'rb') as stream:
                    raw = stream.read()
                lengths = pcap_record_lengths(raw, endian)

                self.assertIn(PCAP_TRUNCATED, lengths)
                incl_len, orig_len = PCAP_TRUNCATED
                self.assertEqual(orig_len - incl_len, 1104)
                # and exactly one record is truncated, so "the truncated frame"
                # below names a single frame
                self.assertEqual([pair for pair in lengths if pair[0] != pair[1]],
                                 [PCAP_TRUNCATED])

    def test_len_is_the_on_wire_length_and_cap_len_the_captured_one(self) -> None:
        """#618: the PCAP reader had these two the other way round.

        On the unfixed tree the truncated frame comes back with ``len=96`` and
        ``cap_len=1200`` -- the captured length under the name that means
        on-wire, and vice versa -- so this fails on that frame in every fixture
        while passing on the two untruncated ones, which is exactly the shape of
        the defect.

        """
        for name, endian in PCAP_FIXTURES:
            raw, frames = self.frames(name)
            lengths = pcap_record_lengths(raw, endian)
            self.assertEqual(len(frames), len(lengths))

            for frame, (incl_len, orig_len) in zip(frames, lengths):
                with self.subTest(fixture=name, frame=frame.info.number):
                    info = frame.info

                    # the record's own fields, which were never in doubt
                    self.assertEqual(info.frame_info.incl_len, incl_len)
                    self.assertEqual(info.frame_info.orig_len, orig_len)

                    # and the two the caller reads, which were inverted
                    self.assertEqual(info.len, orig_len)
                    self.assertEqual(info.cap_len, incl_len)

    def test_cap_len_counts_the_octets_the_frame_actually_carries(self) -> None:
        """``cap_len`` is the length of the packet data, and ``len`` is not.

        The independent check on the previous test: whichever field holds the
        captured length must equal the number of octets the frame really has, and
        for the truncated frame the on-wire field must *not*. That makes the
        assertion self-evidencing rather than a comparison against numbers
        written down in this module.

        """
        for name, _ in PCAP_FIXTURES:
            _, frames = self.frames(name)
            truncated = [frame for frame in frames
                         if frame.info.len != frame.info.cap_len]
            self.assertEqual(len(truncated), 1)

            for frame in frames:
                with self.subTest(fixture=name, frame=frame.info.number):
                    info = frame.info
                    self.assertEqual(info.cap_len, len(info.packet))
                    self.assertEqual(len(bytes(frame)), 16 + info.cap_len)
                    # the on-wire length is never smaller than the captured one,
                    # which is the invariant Wireshark flags as malformed when
                    # a file violates it
                    self.assertGreaterEqual(info.len, info.cap_len)

            self.assertGreater(truncated[0].info.len, len(truncated[0].info.packet))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapngFrameLengthRuntimeTests(unittest.TestCase):
    """#618, on the PCAP-NG reader -- the one that was already right.

    This is the control. It passes on the unfixed tree too, and that is what it
    is for: it pins the convention the PCAP reader was brought into line with, so
    a later change that "fixes" the disagreement from the other end fails here.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def blocks(self) -> 'tuple[bytes, list]':
        """Read ``test.pcapng``'s octets and the packet blocks parsed from it.

        Returns:
            The file's octets, and the parsed blocks that carry both length
            fields -- Enhanced and Simple Packet Blocks alike, since
            :mod:`pcapkit` surfaces ``captured_len`` on both.

        """
        from pcapkit.interface import extract

        path = sample_path('test.pcapng')
        with open(path, 'rb') as stream:
            raw = stream.read()

        blocks = [frame.info for frame in extract(fin=path, store=True, nofile=True).frame
                  if hasattr(frame.info, 'captured_len')]
        return raw, blocks

    def test_the_fixture_really_holds_a_truncated_block(self) -> None:
        """The same premise as on the PCAP side, and for the same reason."""
        raw, _ = self.blocks()
        lengths = pcapng_packet_lengths(raw)

        self.assertIn(PCAPNG_TRUNCATED, lengths)
        captured, original = PCAPNG_TRUNCATED
        self.assertEqual(original - captured, 282)
        self.assertEqual([pair for pair in lengths if pair[0] != pair[1]],
                         [PCAPNG_TRUNCATED])

    def test_block2frame_puts_the_on_wire_length_in_len(self) -> None:
        """:func:`~pcapkit.toolkit.pcapng.block2frame` is the reference reading.

        Asserted against the blocks' own fields rather than against a list of
        numbers, so the test says "whatever the file holds, it lands here" -- the
        property #618 is about -- instead of restating the fixture.

        """
        from pcapkit.toolkit.pcapng import block2frame

        _, blocks = self.blocks()
        self.assertGreater(len(blocks), 0)

        truncated = 0
        for block in blocks:
            with self.subTest(block=block.number):
                frame = block2frame(block)

                self.assertEqual(frame.len, block.original_len)
                self.assertEqual(frame.cap_len, block.captured_len)
                # and the nested record fields, which a PCAP dumper writes out
                self.assertEqual(frame.frame_info.incl_len, block.captured_len)
                self.assertEqual(frame.frame_info.orig_len, block.original_len)

                self.assertGreaterEqual(frame.len, frame.cap_len)
                # NOTE: no assertion that ``cap_len == len(frame.packet)`` here,
                # which is the PCAP side's independent check. The PCAP-NG
                # reader leaves the block's own ``packet`` field empty -- every
                # block in ``test.pcapng`` comes back with ``packet == b''``
                # while carrying a ``captured_len`` in the hundreds -- so
                # ``block2frame`` hands on nothing to measure. That is a separate
                # defect from #618 and is not fixed here; asserting it would pin
                # the wrong reading of the two.

                if block.captured_len != block.original_len:
                    truncated += 1
                    self.assertEqual((frame.cap_len, frame.len), PCAPNG_TRUNCATED)

        # the distinguishing block was actually reached, rather than the loop
        # having run only over blocks where the two lengths coincide
        self.assertEqual(truncated, 1)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class ReadersAgreeRuntimeTests(unittest.TestCase):
    """The defect #618 actually reports: the two readers disagreed.

    Neither class above states this on its own -- each pins one reader against
    its own container -- and it is the disagreement rather than either reading
    that made ``frame.len`` mean two different things to one caller. So it is
    asserted directly, across the two formats, on the only frames that can show
    it.

    """

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_a_truncated_frame_reads_alike_whichever_container_it_came_from(self) -> None:
        """One caller, two capture formats, one meaning per attribute.

        On the unfixed tree the PCAP side reports ``len < cap_len`` and the
        PCAP-NG side ``len > cap_len`` for the same kind of frame, and this fails
        on the first assertion of the pair.

        """
        from pcapkit.interface import extract
        from pcapkit.toolkit.pcapng import block2frame

        pcap = [frame.info for frame
                in extract(fin=sample_path('big_endian.pcap'),
                           store=True, nofile=True).frame]
        pcapng = [block2frame(frame.info) for frame
                  in extract(fin=sample_path('test.pcapng'),
                             store=True, nofile=True).frame
                  if hasattr(frame.info, 'captured_len')]

        truncated = [frame for frame in pcap + pcapng if frame.len != frame.cap_len]
        # one from each container, so the comparison below is between formats
        # rather than within one of them
        self.assertEqual(len(truncated), 2)
        self.assertEqual([frame.cap_len for frame in truncated],
                         [PCAP_TRUNCATED[0], PCAPNG_TRUNCATED[0]])
        self.assertEqual([frame.len for frame in truncated],
                         [PCAP_TRUNCATED[1], PCAPNG_TRUNCATED[1]])

        for frame in truncated:
            with self.subTest(cap_len=frame.cap_len):
                # the on-wire length is the larger of the two, in both formats.
                # This is the assertion #618 breaks: before the fix the PCAP
                # frame reports 96 against 1200 and fails here, while the
                # PCAP-NG one reports 314 against 32 and passes
                self.assertGreater(frame.len, frame.cap_len)
                # the nested record fields agree with the two flat ones, which is
                # what keeps a PCAP dump of either frame faithful
                self.assertEqual(frame.frame_info.incl_len, frame.cap_len)
                self.assertEqual(frame.frame_info.orig_len, frame.len)

        # and on the PCAP side the captured length is measurable against the
        # frame's own octets, which is what makes it more than a relabelling
        pcap_truncated, = [frame for frame in pcap if frame.len != frame.cap_len]
        self.assertEqual(pcap_truncated.cap_len, len(pcap_truncated.packet))


if __name__ == '__main__':
    unittest.main()
