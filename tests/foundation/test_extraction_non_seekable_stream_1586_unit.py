# -*- coding: utf-8 -*-
"""Extracting from a pipe or another non-seekable stream drops no frame (#1586).

``examples/captures/http.pcap`` holds 1,117 frames. Read by path the default
engine gets all of them; piped in -- ``cat http.pcap | ...`` with ``fin`` set to
``sys.stdin.buffer``, an :func:`os.pipe` written in 4,096-octet chunks, or a raw
stream answering short -- it got 870, silently, with ``no_eof`` or without.
Frame 870 is the first to end past the window
:class:`~pcapkit.corekit.io.SeekableReader` keeps over such a stream, 131,072
octets on CPython 3.14. Cut into seven-octet reads it got none at all, and
one-octet reads failed on the magic number.

The frame readers measure what is left with ``seek(0, SEEK_END)``, and the
reader answered that with its window's far edge -- once the window has filled,
exactly how far the stream has been read, so the next record measured nothing
left. ``read`` and a forward ``seek`` took one short answer from the stream as
all there was, and ``Extractor`` took a short ``peek`` for a short file. See
:mod:`tests.corekit.test_io_seekable_reader_short_reads_1586_unit` for the
reader itself. Reading a buffer's worth ahead to measure each record then held a
live capture's frames back until that much more had arrived, so the engines read
ahead only as far as the record they are about to parse.

The captures here are built in memory, past two windows of the default buffer,
so the window fills and slides whatever :data:`io.DEFAULT_BUFFER_SIZE` the
interpreter has. Each case compares the stream's frames, octet for octet and
warning for warning, with the same capture read by path. Each fails on
``e9f3340f7``, the parent of the fix.

"""

from __future__ import annotations

import importlib.util
import io
import os
import pathlib
import struct
import subprocess  # nosec: B404
import sys
import tempfile
import threading
import unittest
import warnings

from tests._support import reimport_once_per_class, scale_timeout
from tests._tiers import ROOT

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)
HAS_DPKT = importlib.util.find_spec('dpkt') is not None

#: The chunkings the stream is cut into: single octets, an odd size that splits
#: every header, a pipe's page, and more than a pipe holds.
CHUNKS = (1, 7, 4096, 65536)

#: Size of each built capture: past two windows of the default buffer.
SIZE = 2 * io.DEFAULT_BUFFER_SIZE + 3000

#: Seconds allowed to a CLI run, which takes about one.
TIMEOUT = 120


def packet(index: 'int') -> 'bytes':
    """An Ethernet frame of 60 to 1,514 octets, with an experimental EtherType."""
    size = 60 + (index * 397) % 1455
    body = bytes((index + offset) & 0xFF for offset in range(size - 14))
    return b'\x02\x00\x00\x00\x00\x01\x02\x00\x00\x00\x00\x02\x88\xb5' + body


def make_pcap(size: 'int' = SIZE) -> 'bytes':
    """A little-endian PCAP capture of at least ``size`` octets."""
    out = [struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)]
    length = 24
    index = 0
    while length < size:
        data = packet(index)
        out.append(struct.pack('<IIII', 1_700_000_000 + index, index, len(data), len(data)) + data)
        length += 16 + len(data)
        index += 1
    return b''.join(out)


def epb(index: 'int', order: 'str' = '<') -> 'bytes':
    """An enhanced packet block on interface 0, in byte order ``order``."""
    data = packet(index)
    pad = -len(data) % 4
    block = 32 + len(data) + pad
    stamp = (1_700_000_000 + index) * 1_000_000
    return (struct.pack(f'{order}IIIIIII', 6, block, 0, stamp >> 32, stamp & 0xFFFFFFFF,
                        len(data), len(data))
            + data + bytes(pad) + struct.pack(f'{order}I', block))


def make_pcapng(size: 'int' = SIZE, order: 'str' = '<') -> 'bytes':
    """A PCAP-NG section of a header, an interface, and enhanced packet blocks."""
    out = [
        struct.pack(f'{order}IIIHHqI', 0x0A0D0D0A, 28, 0x1A2B3C4D, 1, 0, -1, 28),
        struct.pack(f'{order}IIHHII', 1, 20, 1, 0, 65535, 20),
    ]
    length = 48
    index = 0
    while length < size:
        out.append(epb(index, order))
        length += len(out[-1])
        index += 1
    return b''.join(out)


def two_sections() -> 'tuple[bytes, bytes]':
    """A little-endian section and a big-endian one, and their packet blocks."""
    first, second = make_pcapng(SIZE // 2), make_pcapng(SIZE // 2, '>')
    return first + second, first[48:] + second[48:]


#: Length of a record longer than the default buffer, so it cannot be held in one.
OVERSIZE = io.DEFAULT_BUFFER_SIZE + 9000


def oversize(kind: 'str') -> 'bytes':
    """A capture whose second record, or whose section header, is :data:`OVERSIZE` long.

    Args:
        kind: ``'pcap'`` for a PCAP record, ``'epb'`` for a PCAP-NG enhanced packet
            block, ``'shb'`` for a PCAP-NG section header block, made long by comments.

    """
    long = packet(0)[:14] + bytes(range(256)) * (OVERSIZE // 256) + bytes(OVERSIZE % 256 - 14)
    if kind == 'pcap':
        out = [struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 262144, 1)]
        for index, data in enumerate((packet(0), long, packet(1))):
            out.append(struct.pack('<IIII', 1_700_000_000, index, len(data), len(data)) + data)
        return b''.join(out)

    options = b''
    if kind == 'shb':
        for offset in range(0, OVERSIZE, 60000):
            text = bytes(range(97, 123)) * 2400
            text = text[:min(60000, OVERSIZE - offset)]
            options += struct.pack('<HH', 1, len(text)) + text + bytes(-len(text) % 4)
        options += struct.pack('<HH', 0, 0)
    shb = (struct.pack('<IIIHHq', 0x0A0D0D0A, 28 + len(options), 0x1A2B3C4D, 1, 0, -1)
           + options + struct.pack('<I', 28 + len(options)))
    idb = struct.pack('<IIHHII', 1, 20, 1, 0, 0, 20)
    if kind == 'shb':
        return shb + idb + epb(0) + epb(1)
    block = 32 + len(long) + -len(long) % 4
    big = (struct.pack('<IIIIIII', 6, block, 0, 0, 1, len(long), len(long))
           + long + bytes(-len(long) % 4) + struct.pack('<I', block))
    return shb + idb + epb(0) + big + epb(1)


class ShortReads(io.RawIOBase):
    """A non-seekable raw stream answering at most ``chunk`` octets per read."""

    def __init__(self, data: 'bytes', chunk: 'int') -> None:
        super().__init__()
        self._data = data
        self._pos = 0
        self._chunk = chunk

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return False

    def readinto(self, buffer: 'bytearray | memoryview') -> int:  # type: ignore[override]
        size = min(len(buffer), self._chunk, len(self._data) - self._pos)
        buffer[:size] = self._data[self._pos:self._pos + size]
        self._pos += size
        return size


def feed(fd: 'int', data: 'bytes', chunk: 'int') -> 'threading.Thread':
    """Write ``data`` to ``fd`` in ``chunk``-octet writes, then close it, from a thread."""
    def write() -> None:
        try:
            with os.fdopen(fd, 'wb', buffering=0) as stream:
                for offset in range(0, len(data), chunk):
                    stream.write(data[offset:offset + chunk])
        except OSError:  # the reader stopped early and closed its end
            pass

    thread = threading.Thread(target=write, daemon=True)
    thread.start()
    return thread


@unittest.skipUnless(HAS_RUNTIME, 'pcapkit runtime dependencies are not installed')
class TestNonSeekableStream(unittest.TestCase):
    """Every frame from a pipe or a short-answering stream, as from a path."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        tmp = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(tmp.cleanup)
        self.tmp_path = pathlib.Path(tmp.name)

    def extract(self, fin: 'object', **kwargs: 'object') -> 'tuple[list[bytes], set[tuple[str, str]]]':
        """The frames' octets, and the warnings raised on the way."""
        import pcapkit  # pylint: disable=import-outside-toplevel

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = pcapkit.extract(fin=fin, nofile=True, **kwargs)
        return ([bytes(frame) for frame in extractor.frame],  # type: ignore[attr-defined]
                {(w.category.__name__, str(w.message)) for w in caught})

    def by_path(self, data: 'bytes', **kwargs: 'object') -> 'tuple[list[bytes], set[tuple[str, str]]]':
        path = self.tmp_path / 'capture.pcap'
        path.write_bytes(data)
        return self.extract(str(path), **kwargs)

    def by_pipe(self, data: 'bytes', chunk: 'int', **kwargs: 'object') -> 'tuple[list[bytes], set[tuple[str, str]]]':
        read_fd, write_fd = os.pipe()
        thread = feed(write_fd, data, chunk)
        with os.fdopen(read_fd, 'rb', buffering=0) as stream:
            result = self.extract(stream, **kwargs)
        thread.join(scale_timeout(30))
        return result

    def streams(self, data: 'bytes', chunk: 'int') -> 'dict[str, object]':
        return {
            'raw': ShortReads(data, chunk),
            'buffered': io.BufferedReader(ShortReads(data, chunk)),
        }

    def assert_every_chunking(self, data: 'bytes', body: 'bytes', **kwargs: 'object') -> None:
        """Every chunking and stream kind, with ``no_eof`` and without, against the path."""
        for no_eof in (False, True):
            expected, expected_warnings = self.by_path(data, no_eof=no_eof, **kwargs)
            self.assertEqual(b''.join(expected), body, 'the path read is the reference')

            for chunk in CHUNKS:
                with self.subTest(stream='pipe', chunk=chunk, no_eof=no_eof):
                    self.assertEqual(self.by_pipe(data, chunk, no_eof=no_eof, **kwargs),
                                     (expected, expected_warnings))
                for name, stream in self.streams(data, chunk).items():
                    with self.subTest(stream=name, chunk=chunk, no_eof=no_eof):
                        self.assertEqual(self.extract(stream, no_eof=no_eof, **kwargs),
                                         (expected, expected_warnings))

    def test_pcap_every_chunking(self) -> None:
        data = make_pcap()
        self.assert_every_chunking(data, data[24:])

    def test_pcapng_every_chunking(self) -> None:
        """Two sections, the second big-endian, as its Byte-Order Magic declares."""
        self.assert_every_chunking(*two_sections())

    @unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
    def test_dpkt_engine_every_chunking(self) -> None:
        """The dpkt engine reads the same wrapped stream, through ``read``."""
        for name, data in (('pcap', make_pcap()), ('pcapng', make_pcapng())):
            with self.subTest(format=name):
                expected = self.by_path(data, engine='dpkt')
                for chunk in (7, 4096):
                    with self.subTest(chunk=chunk):
                        self.assertEqual(self.extract(ShortReads(data, chunk), engine='dpkt'), expected)

    def test_no_eof_over_a_pipe_whose_writer_closed(self) -> None:
        """The ``pcapkit -`` case, which sets ``no_eof``: every frame, and it returns."""
        data = make_pcap()
        expected = self.by_path(data, no_eof=True)
        self.assertEqual(self.by_pipe(data, 4096, no_eof=True), expected)

    def test_a_live_pipe_hands_over_each_frame_as_it_arrives(self) -> None:
        """A frame does not wait for the stream to go on past it.

        ``pcapkit -`` reads a live capture. Measuring a record by reading a buffer's
        worth past it held each frame back until that much more had arrived; and
        before the fix, the second measurement of each record waited for at least one
        more octet. The writer here sends one record, then waits for the reader to
        have it before sending the rest.

        """
        for name, data, first in (
            ('pcap', make_pcap(), 24 + 16 + len(packet(0))),
            ('pcapng', make_pcapng(), 48 + len(epb(0))),
        ):
            with self.subTest(format=name):
                frames, early = self.live(data, first)
                self.assertTrue(early, 'the first frame waited for the rest of the capture')
                self.assertEqual(frames, self.by_path(data)[0])

    def live(self, data: 'bytes', first: 'int') -> 'tuple[list[bytes], bool]':
        """Read ``data`` off a pipe whose writer holds back all but ``first`` octets.

        Returns:
            The frames, and whether the first arrived while the writer was holding.

        """
        import pcapkit  # pylint: disable=import-outside-toplevel

        received = threading.Event()
        resumed = threading.Event()
        read_fd, write_fd = os.pipe()

        def write() -> None:
            with os.fdopen(write_fd, 'wb', buffering=0) as stream:
                stream.write(data[:first])
                received.wait(scale_timeout(10))
                resumed.set()
                stream.write(data[first:])

        thread = threading.Thread(target=write, daemon=True)
        thread.start()
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with os.fdopen(read_fd, 'rb', buffering=0) as stream:
                extractor = pcapkit.extract(fin=stream, nofile=True, auto=False, no_eof=True)
                frames = [bytes(next(extractor))]
                early = not resumed.is_set()
                received.set()
                frames.extend(bytes(frame) for frame in extractor)
        thread.join(scale_timeout(30))
        return frames, early

    def test_a_record_longer_than_the_buffer_reads_as_from_a_file(self) -> None:
        """A record the buffer cannot hold is read whole, as it is from a file.

        The read-ahead was capped at the buffer, so a PCAP-NG block longer than it was
        measured short and parsed as cut, and a PCAP record slid out of the buffer
        before its reader sought back to it, which failed with ``cannot seek before
        the beginning of the buffer``.

        """
        for kind in ('pcap', 'epb', 'shb'):
            data = oversize(kind)
            with self.subTest(record=kind):
                expected = self.by_path(data)
                self.assertEqual(self.by_pipe(data, 65536), expected)
                self.assertEqual(self.extract(ShortReads(data, 7)), expected)

    @unittest.skipUnless(HAS_DPKT, 'dpkt is not installed')
    def test_dpkt_reads_a_section_header_longer_than_the_buffer(self) -> None:
        """The dpkt engine seeks back to the first octet once the section header is read.

        That is :meth:`Extractor.record_header
        <pcapkit.foundation.extraction.Extractor.record_header>`, which failed with
        ``cannot seek before the beginning of the buffer: 0`` once the section header
        had slid out of it.

        """
        data = oversize('shb')
        expected = self.by_path(data, engine='dpkt')
        self.assertEqual(self.by_pipe(data, 65536, engine='dpkt'), expected)

    def test_pcapng_blocks_parsed_past_their_end_read_as_from_a_file(self) -> None:
        """A block whose parse runs past its Total Length sees what a file read sees.

        The PCAP-NG engine reads a stream ahead only as far as the next block, but two
        kinds of block are parsed past that: one shorter than its own fixed fields,
        and a Decryption Secrets Block whose Secrets Length runs past it. Read only as
        far as the block, the first warned ``packet length < 0`` where the file did
        not, and the second was kept as cut where the file read the blocks after it
        as secrets and failed.

        """
        import pcapkit.utilities.exceptions as errors  # pylint: disable=import-outside-toplevel

        data = make_pcapng()
        middle = 48 + sum(len(epb(index)) for index in range(100))
        short = struct.pack('<IIII', 6, 16, 0, 16)
        dsb_block = struct.pack('<IIII', 10, 36, 0x544C534B, 500) + bytes(16) + struct.pack('<I', 36)
        for name, block in (('short EPB', short), ('DSB', dsb_block)):
            capture = data[:middle] + block + data[middle:]
            with self.subTest(block=name):
                try:
                    expected = self.by_path(capture)
                except errors.BaseError as error:
                    expected = (type(error), str(error))
                for chunk in (7, 4096):
                    try:
                        got = self.extract(ShortReads(capture, chunk))
                    except errors.BaseError as error:
                        got = (type(error), str(error))
                    self.assertEqual(got, expected)

    def test_a_packet_block_before_any_interface_fails_as_from_a_file(self) -> None:
        """The engine's look at the next block type was a ``peek``, short on a pipe."""
        import pcapkit.utilities.exceptions as errors  # pylint: disable=import-outside-toplevel

        data = make_pcapng()
        capture = data[:28] + data[48:]          # the interface description dropped
        with self.assertRaises(errors.FormatError) as path:
            self.by_path(capture)
        with self.assertRaises(errors.FormatError) as stream:
            self.extract(ShortReads(capture, 1))
        self.assertEqual(str(stream.exception), str(path.exception))

    def test_a_truncated_stream_ends_as_the_truncated_file_does(self) -> None:
        """Cut inside a record past the first window: same frames, same warnings, no others.

        For PCAP-NG, inside a block's header too, where its Total Length cannot be read.

        """
        pcap, (pcapng, _) = make_pcap(), two_sections()
        header = 48 + len(epb(0)) + 6
        for name, data, cut in (('pcap', pcap, len(pcap) - 5), ('pcap', pcap, len(pcap) - 1000),
                                ('pcapng', pcapng, len(pcapng) - 5), ('pcapng', pcapng, header)):
            with self.subTest(format=name, cut=cut):
                expected, expected_warnings = self.by_path(data[:cut])
                self.assertIn(('ExtractionWarning', 'EOF reached'), expected_warnings)
                self.assertNotIn('SeekWarning', {category for category, _ in expected_warnings})
                for chunk in (7, 4096):
                    self.assertEqual(self.extract(ShortReads(data[:cut], chunk)),
                                     (expected, expected_warnings))

    def test_cli_reads_every_frame_from_stdin(self) -> None:
        """``pcapkit -`` writes the same report from a pipe as from the file.

        A PCAP capture to a PCAP report, which is the capture again, and a PCAP-NG one,
        two sections of it, to JSON, which has a key per frame.

        """
        pcapng, _ = two_sections()
        for name, data, fmt in (('pcap', make_pcap(), 'pcap'), ('pcapng', pcapng, 'json')):
            with self.subTest(format=name):
                from_path, from_stdin = self.cli(data, name, fmt)
                self.assertEqual(from_stdin, from_path)
                if fmt == 'pcap':
                    self.assertEqual(from_path, data)
                else:
                    frames = self.by_path(data)[0]
                    self.assertIn(f'"Frame {len(frames)}"'.encode(), from_path)
                    self.assertNotIn(f'"Frame {len(frames) + 1}"'.encode(), from_path)

    def cli(self, data: 'bytes', name: 'str', fmt: 'str') -> 'tuple[bytes, bytes]':
        """Run ``pcapkit`` on ``data`` from a file and from stdin, and return both reports."""
        capture = self.tmp_path / f'capture.{name}'
        capture.write_bytes(data)
        script = (
            'import sys\n'
            f'sys.path.insert(0, {str(ROOT)!r})\n'
            'import pcapkit\n'
            f'assert pcapkit.__file__.startswith({str(ROOT)!r}), pcapkit.__file__\n'
            'from pcapkit.__main__ import main\n'
            "sys.argv[0] = 'pcapkit-cli'\n"
            'sys.exit(main())\n'
        )

        def run(fin: 'str', out: 'str', stdin: 'int | None' = None) -> 'bytes':
            report = self.tmp_path / f'{out}.{fmt}'
            completed = subprocess.run(  # nosec: B603
                [sys.executable, '-c', script, fin, '-o', str(report), '-f', fmt],
                stdin=stdin, cwd=str(self.tmp_path), capture_output=True,
                timeout=scale_timeout(TIMEOUT), check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode(errors='replace'))
            return report.read_bytes()

        from_path = run(str(capture), f'{name}-path')
        read_fd, write_fd = os.pipe()
        thread = feed(write_fd, data, 4096)
        try:
            from_stdin = run('-', f'{name}-stdin', stdin=read_fd)
        finally:
            os.close(read_fd)
            thread.join(scale_timeout(30))
        return from_path, from_stdin


if __name__ == '__main__':
    unittest.main()
