# -*- coding: utf-8 -*-
"""A declared length past :data:`sys.maxsize` is an overrun like any other. C.f. #1975.

On a build whose ``Py_ssize_t`` is 32 bits wide -- GraalPy, 32-bit CPython --
:data:`sys.maxsize` is ``2 ** 31 - 1``, and a read or seek asked to go past it
raises :exc:`OverflowError` instead of coming back short. A PCAP record whose
``incl_len`` reaches that far, or a PCAP-NG block whose lengths do, then crashed
the reader before the short-read handling could keep it as captured.

Each case runs such a build's limit on whatever build the suite runs on: the
streams raise :exc:`OverflowError` past :data:`sys.maxsize`, which reads as
``2 ** 31 - 1``, so the case parses as it would there and must match the result
of the same octets parsed without the limit.

A record the file really holds past the limit is read only as far as the limit,
but the next record still starts where it declares it ends. Those cases lower the
limit to :data:`LONG_LIMIT`, so the record need not be gigabytes long, and serve
it from :class:`_SparseStream`, which holds only the octets that are not zero.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import io
import struct
import sys
import unittest
import unittest.mock
import warnings

from tests._support import close_extractor, reimport_once_per_class

#: Test tier (#1958): pins how the readers meet an interpreter's read and seek
#: limit, which differs between interpreters and builds.
__tier__ = 'ALL'

#: ``sys.maxsize`` where ``Py_ssize_t`` is 32 bits wide.
NARROW_MAXSIZE = 2 ** 31 - 1
#: A narrow limit for the records a file really holds past it, cheap to exceed and
#: still past a ``SeekableReader`` buffer, as the real limit is.
LONG_LIMIT = 2 ** 20 - 1
#: How far those records run past :data:`LONG_LIMIT`: more than one discarding
#: read or relative seek's worth, and not a whole number of either.
LONG_EXCESS = 2 * LONG_LIMIT + 4097

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')
#: Sixty octets of packet data, none of them zero.
PACKET = bytes(range(1, 61))
#: Captured lengths at and past the narrow limit: the first one the record header
#: and the claim together overrun, the limit itself, one past it, and the largest.
CLAIMS = (NARROW_MAXSIZE - 15, NARROW_MAXSIZE, NARROW_MAXSIZE + 1, 0xFFFF_FFFF)


def _check(value: 'int | None') -> 'None':
    """Refuse a read or seek size that ``Py_ssize_t`` cannot hold on the simulated build."""
    if value is not None and value > sys.maxsize:
        raise OverflowError('Python int too large to convert to C ssize_t')


class _NarrowBytesIO(io.BytesIO):
    """:class:`io.BytesIO` whose reads and seeks refuse what ``Py_ssize_t`` cannot hold."""

    def read(self, size: 'int | None' = -1, /) -> 'bytes':
        _check(size)
        return super().read(size)

    def read1(self, size: 'int | None' = -1, /) -> 'bytes':
        _check(size)
        return super().read1(size)

    def seek(self, pos: 'int', whence: 'int' = io.SEEK_SET, /) -> 'int':
        _check(pos)
        return super().seek(pos, whence)


class _SparseStream(io.RawIOBase):
    """A file of ``size`` octets, zero but for ``pieces``, that allocates only what is read.

    Its reads refuse what ``Py_ssize_t`` cannot hold. Its seeks do not, as a file's
    do not on GraalPy; built with ``seekable=False`` it cannot seek at all, and an
    extractor reads it through a ``SeekableReader``.

    """

    def __init__(self, pieces: 'dict[int, bytes]', size: 'int', *, seekable: 'bool' = True) -> 'None':
        super().__init__()
        self._pieces = pieces
        self._size = size
        self._seekable = seekable
        self._pos = 0

    def readable(self) -> 'bool':
        return True

    def seekable(self) -> 'bool':
        return self._seekable

    def tell(self) -> 'int':
        if not self._seekable:
            raise io.UnsupportedOperation('tell')
        return self._pos

    def seek(self, pos: 'int', whence: 'int' = io.SEEK_SET, /) -> 'int':
        if not self._seekable:
            raise io.UnsupportedOperation('seek')
        base = {io.SEEK_SET: 0, io.SEEK_CUR: self._pos, io.SEEK_END: self._size}[whence]
        self._pos = max(base + pos, 0)
        return self._pos

    def read(self, size: 'int | None' = -1, /) -> 'bytes':
        _check(size)
        start = self._pos
        stop = self._size if size is None or size < 0 else min(self._size, start + size)
        if stop <= start:
            return b''
        out = bytearray(stop - start)
        for offset, piece in self._pieces.items():
            low, high = max(offset, start), min(offset + len(piece), stop)
            if low < high:
                out[low - start:high - start] = piece[low - offset:high - offset]
        self._pos = stop
        return bytes(out)

    read1 = read


def _pipe(data: 'bytes') -> '_SparseStream':
    """A non-seekable stream holding exactly ``data``."""
    return _SparseStream({0: data}, len(data), seekable=False)


@contextlib.contextmanager
def narrow_build(limit: 'int' = NARROW_MAXSIZE):
    """Run the block as a build whose one read or seek goes no further than ``limit``."""
    with unittest.mock.patch.object(sys, 'maxsize', limit), \
            unittest.mock.patch.object(io, 'BytesIO', _NarrowBytesIO):
        yield


def _record(claim: 'int', packet: 'bytes' = PACKET) -> 'bytes':
    """A record whose header claims ``claim`` octets, followed by ``packet``."""
    return struct.pack('<IIII', 1_500_000_000, 7, claim, 86) + packet


def _block(block_type: 'int', body: 'bytes') -> 'bytes':
    """A little-endian PCAP-NG block holding ``body``, padded to 32 bits."""
    body += bytes(-len(body) % 4)
    total = 12 + len(body)
    return struct.pack('<II', block_type, total) + body + struct.pack('<I', total)


#: A section header block and an Ethernet interface, little-endian.
SECTION = (_block(0x0A0D0D0A, struct.pack('<IHHq', 0x1A2B3C4D, 1, 0, -1))
           + _block(1, struct.pack('<HHI', 1, 0, 0)))


def _epb(captured: 'int') -> 'bytes':
    """An EPB over :data:`PACKET` whose captured length reads ``captured``."""
    return _block(6, struct.pack('<IIIII', 0, 0, 0, captured, len(PACKET)) + PACKET)


def _epb_total(total: 'int') -> 'bytes':
    """A whole EPB over :data:`PACKET` whose leading Block Total Length reads ``total``."""
    block = _epb(len(PACKET))
    return block[:4] + struct.pack('<I', total) + block[8:]


class TestDeclaredLengthPastMaxsize(unittest.TestCase):
    """Pin that a length no read can take is kept as captured, as any overrun is."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_the_simulated_build_refuses_what_a_narrow_build_does(self) -> None:
        """The streams this module reads overflow where a 32-bit build's do."""
        for stream in (_NarrowBytesIO(PACKET), _pipe(PACKET)):
            with self.subTest(stream=type(stream).__name__), narrow_build():
                self.assertEqual(stream.read(NARROW_MAXSIZE), PACKET)
                with self.assertRaises(OverflowError):
                    stream.read(NARROW_MAXSIZE + 1)

    def test_the_sparse_stream_serves_its_pieces_among_zeros(self) -> None:
        stream = _SparseStream({2: b'ab', 6: b'cd'}, 9)
        self.assertEqual(stream.read(4), b'\x00\x00ab')
        self.assertEqual(stream.seek(1, io.SEEK_CUR), 5)
        self.assertEqual(stream.read(), b'\x00cd\x00')
        self.assertEqual(stream.read(1), b'')

    def test_a_frame_claiming_past_maxsize_is_kept_as_captured(self) -> None:
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header

        header = Header(GLOBAL).info
        for claim in CLAIMS:
            with self.subTest(claim=claim):
                octets = _record(claim)
                with narrow_build(), warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    frame = Frame(io.BytesIO(octets), num=4, header=header)
                self.assertIn(f'PCAP: [Frame 4] captured length {claim} runs past the data, '
                              f'which holds {len(PACKET)} octet(s); kept as captured',
                              [str(item.message) for item in caught])

                info = frame.info  # type: ignore[attr-defined]
                self.assertEqual((info.frame_info.incl_len, info.cap_len), (claim, claim))
                self.assertEqual(bytes(info.packet), PACKET)
                self.assertEqual(frame.data, octets)  # type: ignore[attr-defined]

    def extract_frames(self, fin: 'object', limit: 'int' = NARROW_MAXSIZE,
                       **kwargs: 'object') -> 'tuple[list[object], list[str]]':
        """The frames the default engine extracts from ``fin``, and the warnings raised."""
        import pcapkit

        with narrow_build(limit), warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = pcapkit.extract(fin=fin, nofile=True, store=True, engine='default', **kwargs)
        close_extractor(extractor)
        return list(extractor.frame), [str(item.message) for item in caught]

    def extract(self, fin: 'object', limit: 'int' = NARROW_MAXSIZE, **kwargs: 'object') -> 'list[bytes]':
        """The packets the default engine extracts from ``fin``, on the narrow build."""
        frames, _ = self.extract_frames(fin, limit, **kwargs)
        return [bytes(frame.info.packet) for frame in frames]  # type: ignore[attr-defined]

    def test_extraction_keeps_a_pcap_record_claiming_past_maxsize(self) -> None:
        for claim in CLAIMS:
            with self.subTest(claim=claim):
                octets = GLOBAL + _record(len(PACKET)) + _record(claim)
                self.assertEqual(self.extract(_NarrowBytesIO(octets)), [PACKET, PACKET])

    def test_extraction_keeps_a_pcapng_block_declaring_past_maxsize(self) -> None:
        cases = {
            'captured length': _epb(0xFFFF_FFFF),
            'block total length': _epb_total(0xFFFF_FFFC),
        }
        for name, block in cases.items():
            with self.subTest(length=name):
                octets = SECTION + _epb(len(PACKET)) + block
                self.assertEqual(self.extract(_NarrowBytesIO(octets)), [PACKET, PACKET])

    def test_a_non_seekable_input_with_no_read_chunk_limit(self) -> None:
        """The ``SeekableReader`` a pipe is wrapped in bounds its reads as well."""
        from pcapkit.utilities import config

        octets = GLOBAL + _record(len(PACKET)) + _record(0xFFFF_FFFF)
        for chunk in (config.READ_CHUNK, -1):
            with self.subTest(read_chunk=chunk), unittest.mock.patch.object(config, 'READ_CHUNK', chunk):
                self.assertEqual(self.extract(_pipe(octets)), [PACKET, PACKET])

    def check_moved_past(self, frames: 'list[object]', messages: 'list[str]', warning: 'str') -> 'None':
        """The long record is bounded and warned of, and the next one parses where it is."""
        packets = [bytes(frame.info.packet) for frame in frames]  # type: ignore[attr-defined]
        self.assertEqual(len(packets), 3, [len(packet) for packet in packets])
        self.assertEqual((packets[0], packets[2]), (PACKET, PACKET))
        self.assertLessEqual(len(packets[1]), LONG_LIMIT)
        self.assertTrue([text for text in messages if text.startswith(warning)], messages)

    def test_a_pcap_record_really_past_maxsize_is_moved_past_whole(self) -> None:
        """The record after it parses where it is, past a seek or a read over the rest."""
        from pcapkit.utilities import config

        claim = LONG_LIMIT + LONG_EXCESS
        head = GLOBAL + _record(len(PACKET)) + _record(claim, b'')
        pieces = {0: head, len(head) + claim: _record(len(PACKET))}
        size = len(head) + claim + len(_record(len(PACKET)))
        cases = (('seekable', True, config.READ_CHUNK), ('pipe', False, config.READ_CHUNK),
                 ('pipe, no read chunk limit', False, -1))
        for name, seekable, chunk in cases:
            with self.subTest(stream=name), unittest.mock.patch.object(config, 'READ_CHUNK', chunk):
                frames, messages = self.extract_frames(_SparseStream(pieces, size, seekable=seekable),
                                                       LONG_LIMIT)
                self.check_moved_past(frames, messages, f'PCAP: [Frame 2] captured length {claim} runs past')
                self.assertEqual(frames[1].info.frame_info.incl_len, claim)  # type: ignore[attr-defined]

    def test_a_pcapng_block_really_past_maxsize_is_moved_past_whole(self) -> None:
        """So does the block after a PCAP-NG block holding more than the limit."""
        total = (LONG_LIMIT + LONG_EXCESS) // 4 * 4
        head = SECTION + _epb(len(PACKET))
        start = struct.pack('<IIIIIII', 6, total, 0, 0, 0, total - 32, total - 32)
        end = struct.pack('<I', total) + _epb(len(PACKET))
        pieces = {0: head + start, len(head) + total - 4: end}
        size = len(head) + total - 4 + len(end)
        for seekable in (True, False):
            with self.subTest(seekable=seekable):
                frames, messages = self.extract_frames(_SparseStream(pieces, size, seekable=seekable),
                                                       LONG_LIMIT)
                self.check_moved_past(frames, messages, f'PCAP-NG: [Block 6] block length {total} exceeds')


if __name__ == '__main__':
    unittest.main()
