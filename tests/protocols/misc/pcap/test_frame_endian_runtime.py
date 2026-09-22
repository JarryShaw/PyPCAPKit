# -*- coding: utf-8 -*-
"""A big-endian classic PCAP, read on a little-endian host.

Classic PCAP declares its byte order in the magic number of the global header,
and the four fields of every record header -- ``ts_sec``, ``ts_usec``,
``incl_len`` and ``orig_len`` -- are written in that order rather than in the
reading host's. Nothing in this suite read a big-endian ``.pcap`` before, because
no such capture existed here: every fixture was little-endian, so on a
little-endian runner a reader that ignored the file's declared order and used
:data:`sys.byteorder` produced exactly the right answer.

That is what GitHub issue #605 was.
:meth:`Frame.unpack <pcapkit.protocols.misc.pcap.frame.Frame.unpack>` seeded the
order under the key ``bytesorder``, while ``byteorder_callback`` in
:file:`pcapkit/protocols/schema/misc/pcap/frame.py` reads ``byteorder``, so the
``.get()`` never found the key and always fell back to the host's order -- the
sibling :meth:`Frame.pack <pcapkit.protocols.misc.pcap.frame.Frame.pack>`
eleven lines earlier spelled it correctly, which is what marks it as a slip
rather than a second key. Measured on the unfixed tree against
``big_endian.pcap``, whose first record really holds ``ts_sec=1500000000``,
``ts_usec=123456`` and ``incl_len=74``: frame 1 came back with
``ts_sec=3106905``, ``ts_usec=1088553216`` and ``incl_len=1241513984``, i.e.
every field byte-swapped, dated 1970-02-05 rather than 2017-07-14. And because
``incl_len`` is the payload length, that first record swallowed the rest of the
file and the read that followed was handed a negative payload length, raising
``ValueError: read length must be non-negative or -1`` from
:file:`pcapkit/protocols/schema/schema.py`. So the defect was a wrong answer
first and a crash second.

The fixtures come from :file:`examples/generators/endian.py`, and the set is
built around one property: ``big_endian.pcap`` and ``little_endian.pcap`` carry
the *same three records* -- same timestamps, same lengths, byte-identical packet
data -- in the two containers. A test against the big-endian file alone can only
check it against numbers written down here; against its twin it can check that
the byte order of the container makes no difference to what is read out of it,
which is the property the byte-order branch exists to provide.

Expectations are taken from the files themselves with :mod:`struct` as well as
written down, so a fixture regenerated into something else fails here rather
than quietly moving the goalposts.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest
from decimal import Decimal

from tests._support import purge_modules, sample_path

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: The three records every fixture in :file:`examples/generators/endian.py`
#: carries, as ``(ts_sec, ts_usec, incl_len, orig_len)``. Frame 3 is captured
#: short -- 1200 octets on the wire, cut to the 96-octet ``snaplen`` -- so
#: ``incl_len`` and ``orig_len`` differ there, which frames 1 and 2 cannot show:
#: a reader that read one of the two fields and used it for both would satisfy
#: them and fail here.
MICROSECOND_RECORDS = (
    (1500000000, 123456, 74, 74),
    (1500000001, 654321, 66, 66),
    (1500000002, 456789, 96, 1200),
)

#: The same three records of ``big_endian_nanosecond.pcap``, whose magic number
#: (``a1 b2 3c 4d``) declares both big-endian *and* nanosecond timestamps, so
#: ``ts_usec`` counts nanoseconds.
NANOSECOND_RECORDS = (
    (1500000000, 123456789, 74, 74),
    (1500000001, 987654321, 66, 66),
    (1500000002, 456789123, 96, 1200),
)


def record_chain(raw: 'bytes', endian: 'str') -> 'list[tuple[int, tuple[int, int, int, int]]]':
    """Walk a classic PCAP's record chain straight out of its octets.

    This is deliberately independent of :mod:`pcapkit`: it is what the
    assertions below compare the library's answer against, so it must not share
    the code under test. The same idiom as
    :file:`tests/protocols/misc/pcap/test_frame_runtime.py`, widened to take the
    byte order and to return all four fields.

    Args:
        raw: The whole file.
        endian: :mod:`struct` byte-order prefix, ``'>'`` or ``'<'``.

    Returns:
        One entry per record, as ``(offset of the record, (ts_sec, ts_usec,
        incl_len, orig_len))``, where the offset is that of the record header's
        first octet.

    """
    chain = []
    offset = 24  # the global header is 24 octets
    while offset < len(raw):
        fields = struct.unpack_from(f'{endian}IIII', raw, offset)
        chain.append((offset, fields))
        offset += 16 + fields[2]  # 16-octet record header, then incl_len octets
    return chain


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class PcapFrameByteOrderRuntimeTests(unittest.TestCase):
    """#605, through :func:`pcapkit.interface.extract`."""

    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def read(self, name: 'str') -> 'tuple[bytes, list]':
        """Read a fixture's octets and its frames.

        Args:
            name: Bare fixture file name.

        Returns:
            The file's octets, and the frames
            :func:`pcapkit.interface.extract` parsed out of it.

        """
        from pcapkit.interface import extract

        path = sample_path(name)
        with open(path, 'rb') as stream:
            raw = stream.read()

        extractor = extract(fin=path, store=True, nofile=True)
        return raw, list(extractor.frame)

    def assertRecords(self, name: 'str', magic: 'bytes', endian: 'str',
                      expected: 'tuple[tuple[int, int, int, int], ...]',
                      divisor: 'int') -> 'None':
        """Assert a fixture parses to the record headers it actually holds.

        Args:
            name: Bare fixture file name.
            magic: Magic number the fixture must carry, so that a fixture
                regenerated into a different byte order fails loudly here
                instead of making the rest of the assertions vacuous.
            endian: :mod:`struct` byte-order prefix the file is written in.
            expected: The four record-header fields of each record.
            divisor: What ``ts_usec`` is a fraction of a second in -- 1000000
                for a microsecond capture, 1000000000 for a nanosecond one.

        """
        raw, frames = self.read(name)

        self.assertEqual(raw[:4], magic)
        chain = record_chain(raw, endian)
        # the fixture holds what this module says it holds
        self.assertEqual(tuple(fields for _, fields in chain), expected)
        # and reading it yields one frame per record, not one frame for the file
        self.assertEqual(len(frames), len(expected))

        for frame, (offset, fields) in zip(frames, chain):
            ts_sec, ts_usec, incl_len, orig_len = fields
            with self.subTest(frame=frame.info.number):
                info = frame.info.frame_info
                self.assertEqual(info.ts_sec, ts_sec)
                self.assertEqual(info.ts_usec, ts_usec)
                self.assertEqual(info.incl_len, incl_len)
                self.assertEqual(info.orig_len, orig_len)

                # the timestamp the caller actually reads, which is where a
                # swapped ts_sec shows up as an instant in 1970
                self.assertEqual(frame.info.time_epoch,
                                 ts_sec + Decimal(ts_usec) / divisor)
                self.assertEqual(frame.info.time.year, 2017)

                # and the payload boundary, which is what incl_len decides: a
                # swapped incl_len runs the first record to the end of the file
                self.assertEqual(frame.info.packet,
                                 raw[offset + 16:offset + 16 + incl_len])
                self.assertEqual(bytes(frame), raw[offset:offset + 16 + incl_len])

    def test_big_endian_record_headers_are_read_in_the_files_byte_order(self) -> None:
        """#605: ``a1 b2 c3 d4``, microsecond timestamps.

        On the unfixed tree this raises ``ValueError: read length must be
        non-negative or -1`` before reaching any assertion: frame 1's swapped
        ``incl_len`` of 1241513984 consumes the whole file, and the read that
        follows is handed a negative payload length.

        """
        self.assertRecords('big_endian.pcap', b'\xa1\xb2\xc3\xd4', '>',
                           MICROSECOND_RECORDS, 1_000_000)

    def test_big_endian_nanosecond_record_headers_are_read_in_the_files_byte_order(self) -> None:
        """#605 for ``a1 b2 3c 4d``, the big-endian nanosecond magic number.

        The nanosecond flag and the byte order come out of the same magic
        number, and both have to be honoured at once: ``ts_usec`` is read
        big-endian and then divided by a thousand million rather than by a
        million.

        """
        self.assertRecords('big_endian_nanosecond.pcap', b'\xa1\xb2\x3c\x4d', '>',
                           NANOSECOND_RECORDS, 1_000_000_000)

    def test_little_endian_twin_is_unaffected(self) -> None:
        """The control: the same three records in the little-endian container.

        This passes on the unfixed tree too, and that is what it is for. It
        pins the expectations of the big-endian tests to a file whose byte
        order was never in question, so a failure there cannot be blamed on the
        records themselves being wrong.

        """
        self.assertRecords('little_endian.pcap', b'\xd4\xc3\xb2\xa1', '<',
                           MICROSECOND_RECORDS, 1_000_000)

    def test_the_two_containers_are_read_alike(self) -> None:
        """The two byte orders are two spellings of the same three records.

        Asserted field by field rather than by comparing the parsed objects,
        which carry frame numbers and nested protocol instances that do not
        compare equal. The packet data is compared too: it is the one part of a
        record that is *not* byte-swapped between the two files, so if it ever
        differs, the fixtures have diverged and neither test above means what it
        says.

        """
        big_raw, big_frames = self.read('big_endian.pcap')
        little_raw, little_frames = self.read('little_endian.pcap')

        self.assertEqual(len(big_raw), len(little_raw))
        self.assertEqual(len(big_frames), len(little_frames))
        self.assertNotEqual(big_raw, little_raw)  # the containers do differ

        for big, little in zip(big_frames, little_frames):
            with self.subTest(frame=big.info.number):
                self.assertEqual(big.info.frame_info.ts_sec, little.info.frame_info.ts_sec)
                self.assertEqual(big.info.frame_info.ts_usec, little.info.frame_info.ts_usec)
                self.assertEqual(big.info.frame_info.incl_len, little.info.frame_info.incl_len)
                self.assertEqual(big.info.frame_info.orig_len, little.info.frame_info.orig_len)
                self.assertEqual(big.info.time_epoch, little.info.time_epoch)
                self.assertEqual(big.info.time, little.info.time)
                self.assertEqual(big.info.protocols, little.info.protocols)
                self.assertEqual(big.info.packet, little.info.packet)


if __name__ == '__main__':
    unittest.main()
