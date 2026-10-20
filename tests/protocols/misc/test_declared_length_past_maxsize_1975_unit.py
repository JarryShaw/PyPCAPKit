# -*- coding: utf-8 -*-
"""A declared length past :data:`sys.maxsize` is an overrun like any other. C.f. #1975.

On a build whose ``Py_ssize_t`` is 32 bits wide -- GraalPy, 32-bit CPython --
:data:`sys.maxsize` is ``2 ** 31 - 1``, and a read or seek asked to go past it
raises :exc:`OverflowError` instead of coming back short. A PCAP record whose
``incl_len`` reaches that far, or a PCAP-NG block whose lengths do, then crashed
the reader before the short-read handling could keep it as captured.

Each case runs such a build's limit on whatever build the suite runs on: the
in-memory streams raise :exc:`OverflowError` past ``2 ** 31 - 1``, and
:data:`sys.maxsize` reads as that value, so the case parses as it would there and
must match the result of the same octets parsed without the limit.

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

#: Little-endian global header: v2.4, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')
#: Sixty octets of packet data, none of them zero.
PACKET = bytes(range(1, 61))
#: Captured lengths at and past the narrow limit: the first one the record header
#: and the claim together overrun, the limit itself, one past it, and the largest.
CLAIMS = (NARROW_MAXSIZE - 15, NARROW_MAXSIZE, NARROW_MAXSIZE + 1, 0xFFFF_FFFF)


class _NarrowBytesIO(io.BytesIO):
    """:class:`io.BytesIO` whose reads and seeks refuse what a 32-bit ``Py_ssize_t`` cannot hold."""

    @staticmethod
    def _check(value: 'int | None') -> 'None':
        if value is not None and value > NARROW_MAXSIZE:
            raise OverflowError('Python int too large to convert to C ssize_t')

    def read(self, size: 'int | None' = -1, /) -> 'bytes':
        self._check(size)
        return super().read(size)

    def read1(self, size: 'int | None' = -1, /) -> 'bytes':
        self._check(size)
        return super().read1(size)

    def seek(self, pos: 'int', whence: 'int' = io.SEEK_SET, /) -> 'int':
        self._check(pos)
        return super().seek(pos, whence)


class _NarrowPipe(io.RawIOBase):
    """A non-seekable stream with the same limit, read through a ``SeekableReader``."""

    def __init__(self, data: 'bytes') -> 'None':
        super().__init__()
        self._data = data
        self._pos = 0

    def readable(self) -> 'bool':
        return True

    def seekable(self) -> 'bool':
        return False

    def read(self, size: 'int | None' = -1, /) -> 'bytes':
        _NarrowBytesIO._check(size)  # pylint: disable=protected-access
        if size is None or size < 0:
            size = len(self._data) - self._pos
        chunk = self._data[self._pos:self._pos + size]
        self._pos += len(chunk)
        return chunk

    read1 = read


@contextlib.contextmanager
def narrow_build():
    """Run the block as a build whose ``Py_ssize_t`` is 32 bits wide would."""
    with unittest.mock.patch.object(sys, 'maxsize', NARROW_MAXSIZE), \
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
        for stream in (_NarrowBytesIO(PACKET), _NarrowPipe(PACKET)):
            with self.subTest(stream=type(stream).__name__):
                self.assertEqual(stream.read(NARROW_MAXSIZE), PACKET)
                with self.assertRaises(OverflowError):
                    stream.read(NARROW_MAXSIZE + 1)

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

    def extract(self, fin: 'object', **kwargs: 'object') -> 'list[bytes]':
        """The packets the default engine extracts from ``fin``, on the narrow build."""
        import pcapkit

        with narrow_build(), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            extractor = pcapkit.extract(fin=fin, nofile=True, store=True, engine='default', **kwargs)
        close_extractor(extractor)
        return [bytes(frame.info.packet) for frame in extractor.frame]

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
                self.assertEqual(self.extract(_NarrowPipe(octets)), [PACKET, PACKET])


if __name__ == '__main__':
    unittest.main()
