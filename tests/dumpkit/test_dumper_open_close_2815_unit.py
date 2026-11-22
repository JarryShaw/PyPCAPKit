# -*- coding: utf-8 -*-
"""A dumper can keep its output file open across calls. C.f. #2815.

:class:`~pcapkit.dumpkit.pcap.PCAPIO` and every :mod:`dictdumper` writer
:func:`~pcapkit.dumpkit.common.make_dumper` builds reopened the file on each
call, which a flow tracer pays once per frame. ``open()`` keeps it open until
``close()``. The octets on disk must be those of a per-call reopen after
*every* call, not only after ``close()``, since a reader may open an unfinished
flow's file; and a call after ``close()`` reopens the file as before.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import builtins
import importlib.util
import os
import struct
import tempfile
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any, Callable

#: Test tier (#1958): file handles held open across calls and their flushing,
#: stream and buffer semantics that differ by interpreter.
__tier__ = 'ALL'

HAS_RUNTIME = all(importlib.util.find_spec(name) is not None
                  for name in ('tbtrim', 'aenum', 'chardet', 'dictdumper'))

#: Blocks written to each dumper, as ``(seconds, packet)``.
BLOCKS = ((7, b'abc'), (8, b''), (9, b'\x00\xff' * 40))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DumperOpenCloseTests(unittest.TestCase):
    """``open()`` and ``close()`` on each dumper kind."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        self.tmpdir = tempfile.TemporaryDirectory()  # pylint: disable=consider-using-with
        self.addCleanup(self.tmpdir.cleanup)

    def frames(self) -> 'list[Any]':
        """A PCAP frame per :data:`BLOCKS` entry."""
        from pcapkit.protocols.misc.pcap.frame.data import Frame, FrameInfo

        frames = []
        for second, packet in BLOCKS:
            frame = Frame(frame_info=FrameInfo(ts_sec=second, ts_usec=0, incl_len=len(packet),
                                               orig_len=len(packet)),
                          time='time', number=1, time_epoch=second, len=len(packet), cap_len=len(packet))
            frame.__update__(packet=packet)
            frames.append(frame)
        return frames

    def factories(self) -> 'dict[str, tuple[Callable[[str], Any], list[Any]]]':
        """Each dumper kind, as a factory of a path, and the values it is given."""
        import dictdumper

        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.common import make_dumper
        from pcapkit.dumpkit.pcap import PCAPIO

        def pcapio(cls: 'Any') -> 'Callable[[str], Any]':
            return lambda path: cls(path, protocol=LinkType.ETHERNET, byteorder='little')

        mappings = [{'second': second, 'packet': packet} for second, packet in BLOCKS]
        return {
            'PCAPIO': (pcapio(PCAPIO), self.frames()),
            'make_dumper(PCAPIO)': (pcapio(make_dumper(PCAPIO)), self.frames()),
            'json': (make_dumper(dictdumper.JSON), mappings),
            'plist': (make_dumper(dictdumper.PLIST), mappings),
            'tree': (make_dumper(dictdumper.Tree), mappings),
        }

    def read(self, path: 'str') -> 'bytes':
        with open(path, 'rb') as file:
            return file.read()

    def test_a_kept_file_holds_the_octets_of_a_reopen_after_every_call(self) -> None:
        """#2815: written through the open file and flushed, block by block."""
        for kind, (factory, values) in self.factories().items():
            with self.subTest(kind=kind):
                reopen = factory(os.path.join(self.tmpdir.name, f'{kind}.reopen'))
                kept = factory(os.path.join(self.tmpdir.name, f'{kind}.kept'))
                kept.open()
                for number, value in enumerate(values):
                    reopen(value, name=f'Frame {number}')
                    kept(value, name=f'Frame {number}')
                    self.assertEqual(self.read(kept.filename), self.read(reopen.filename))
                kept.close()
                self.assertEqual(self.read(kept.filename), self.read(reopen.filename))

    def test_the_pcap_octets_are_the_records(self) -> None:
        """#2815: not only equal to a reopen's, but the records of the frames given."""
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO

        dumper = PCAPIO(os.path.join(self.tmpdir.name, 'out.pcap'), protocol=LinkType.ETHERNET,
                        byteorder='little')
        dumper.open()
        for frame in self.frames():
            dumper(frame)
        dumper.close()
        records = b''.join(struct.pack('<IIII', second, 0, len(packet), len(packet)) + packet
                           for second, packet in BLOCKS)
        self.assertEqual(self.read(dumper.filename)[24:], records)

    def test_open_opens_the_file_once_until_close(self) -> None:
        """#2815: one handle for every call between ``open()`` and ``close()``."""
        real = builtins.open
        for kind, (factory, values) in self.factories().items():
            path = os.path.join(self.tmpdir.name, f'{kind}.once')
            dumper = factory(path)
            handles = []

            def record(file: 'Any', *args: 'Any', **kwargs: 'Any') -> 'Any':
                handle = real(file, *args, **kwargs)
                if file == path:  # pylint: disable=cell-var-from-loop
                    handles.append(handle)  # pylint: disable=cell-var-from-loop
                return handle

            with self.subTest(kind=kind), mock.patch('builtins.open', record):
                dumper.open()
                dumper.open()
                for number, value in enumerate(values):
                    dumper(value, name=f'Frame {number}')
                self.assertEqual(len(handles), 1)
                self.assertFalse(handles[0].closed)
                dumper.close()
                dumper.close()
                self.assertTrue(handles[0].closed)
                # NOTE: closed, each call reopens the file, as without open().
                dumper(values[0], name='again')
                self.assertEqual(len(handles), 2)
                self.assertTrue(handles[1].closed)

    def test_a_dumper_that_writes_no_file_keeps_nothing(self) -> None:
        """#2815: the null dumper, and a writer with a ``__call__`` of its own, have a no-op pair."""
        import dictdumper

        from pcapkit.dumpkit.common import Dumper, make_dumper
        from pcapkit.dumpkit.null import NotImplementedIO

        class OwnCall(dictdumper.JSON):
            def __call__(self, value: 'Any', name: 'Any' = None) -> 'Any':
                return self

        class OwnCallDumper(Dumper):
            @property
            def kind(self) -> 'str':
                return 'own'

            def __call__(self, value: 'Any', name: 'Any' = None) -> 'Any':
                return self

            def _append_value(self, value: 'Any', file: 'Any', name: 'Any') -> None:
                raise AssertionError('written')

        for output in (NotImplementedIO, OwnCall, OwnCallDumper):
            with self.subTest(output=output.__name__):
                path = os.path.join(self.tmpdir.name, f'{output.__name__}.out')
                dumper = make_dumper(output)(path)
                before = os.path.exists(path) and self.read(path)
                with mock.patch('builtins.open', side_effect=AssertionError('opened')):
                    dumper.open()
                    dumper({'x': 1}, name='x')
                    dumper.close()
                self.assertEqual(os.path.exists(path) and self.read(path), before)


if __name__ == '__main__':
    unittest.main()
