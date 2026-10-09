# -*- coding: utf-8 -*-
"""The PyShark engine reads packet records only, as the default engine does. C.f. #1515.

:program:`tshark` numbers every record wiretap hands it, and a PCAP-NG systemd
Journal Export Block, Custom Block or Sysdig Event Block is one. The default
engine counts Enhanced, Simple and obsolete Packet Blocks only, so a capture
holding a journal block read as one frame more through ``pyshark``, and every
later frame was off by one.

The same lookup serves the verbose handler. ``pyshark`` takes the second PDML
``<proto>`` as ``frame_info``, and on a packet that carries a comment that is
``pkt_comment``, which has no ``protocols``. So ``verbose=True`` raised
:exc:`AttributeError` on frame 1 of :file:`examples/captures/test.pcapng`.

The packets here are stand-ins shaped like what ``pyshark`` 0.6 builds from
:program:`tshark` 4.6.9's PDML. The field names are the ones measured on
:file:`examples/captures/test.pcapng` and on a capture holding a Custom Block and
a Sysdig Event Block. ``pyshark`` itself is never imported, so this runs where it
is absent or cannot run.

"""

import contextlib
import importlib.util
import io
import types
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: ``frame`` layer fields of a packet record; only these carry ``encap_type``.
PACKET_FRAME = ('section_number', 'interface_id', 'interface_name', 'encap_type', 'time',
                'time_epoch', 'number', 'len', 'cap_len', 'protocols')
#: ``frame`` layer fields of a systemd Journal Export or Sysdig Event record.
RECORD_FRAME = ('section_number', 'time', 'time_utc', 'time_epoch', 'number', 'len', 'cap_len',
                'protocols')
#: ``frame.protocols`` of frame 1 of :file:`examples/captures/test.pcapng`.
PROTOCOLS = 'eth:ethertype:ip:udp:dhcp'


def _layer(name: str, fields: 'tuple[str, ...]' = (), **values: str) -> types.SimpleNamespace:
    return types.SimpleNamespace(layer_name=name, field_names=list(fields), **values)


def _packet(number: int, comment: bool = False) -> types.SimpleNamespace:
    """A packet record; with a comment, ``pyshark`` takes ``pkt_comment`` as ``frame_info``."""
    frame = _layer('frame', PACKET_FRAME, protocols=PROTOCOLS)
    eth = _layer('eth', ('dst', 'src', 'type'))
    if comment:
        note = _layer('pkt_comment', ('frame_comment',))
        return types.SimpleNamespace(number=str(number), frame_info=note, layers=[frame, eth])
    return types.SimpleNamespace(number=str(number), frame_info=frame, layers=[eth])


def _record(number: int, frame: 'tuple[str, ...] | None', root: str) -> types.SimpleNamespace:
    """A non-packet record; ``frame=None`` for a root that is not ``frame`` at all."""
    head = _layer('frame', frame) if frame is not None else _layer(root, ('num',))
    layers = [_layer(root, ('message',))] if frame is not None else []
    return types.SimpleNamespace(number=str(number), frame_info=head, layers=layers)


#: Every non-packet record shape, and where it was seen.
RECORDS = {
    'systemd journal (4.6.9)': ('systemd_journal', RECORD_FRAME),
    'custom block (4.6.9)': ('DATA', ('section_number', 'interface_id', 'time', 'number', 'len')),
    'sysdig event (4.6.9)': ('sysdig', RECORD_FRAME),
    # 4.2.2 roots a Sysdig event at ``syscall`` and a Netflix custom block at
    # ``bblog`` instead of ``frame`` (epan/dissectors/packet-frame.c:858-869, :884-890).
    'sysdig event (4.2.2)': ('syscall', None),
    'black box log (4.2.2)': ('bblog', None),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class TestPySharkNonPacketRecords(unittest.TestCase):
    """:meth:`PyShark.read_frame` skips every record that is not a packet."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _engine(records: 'list[types.SimpleNamespace]') -> 'tuple[object, types.SimpleNamespace]':
        from pcapkit.foundation.engines.pyshark import PyShark

        stream = iter(records)
        extractor = types.SimpleNamespace(_frnum=0, _vfunc=lambda e, f: None, _flag_q=True,
                                          _flag_t=False, _flag_d=True, _frame=[])
        engine = PyShark.__new__(PyShark)  # skip __init__, which imports pyshark
        engine._extractor = extractor
        engine._extmp = types.SimpleNamespace(next=lambda: next(stream))
        return engine, extractor

    def test_a_journal_record_is_not_a_frame(self) -> None:
        first, last = _packet(1, comment=True), _packet(3)
        engine, ext = self._engine([first, _record(2, RECORD_FRAME, 'systemd_journal'), last])

        self.assertIs(engine.read_frame(), first)
        self.assertEqual(ext._frnum, 1)
        self.assertIs(engine.read_frame(), last)
        self.assertEqual(ext._frnum, 2, 'frames are numbered as the default engine numbers them')
        self.assertEqual(ext._frame, [first, last])
        with self.assertRaises(StopIteration):
            engine.read_frame()

    def test_every_record_without_an_encapsulation_is_skipped(self) -> None:
        for label, (root, frame) in RECORDS.items():
            with self.subTest(record=label):
                record = _record(2, frame, root)
                engine, ext = self._engine([_packet(1), record, _packet(3)])
                frames = [engine.read_frame(), engine.read_frame()]
                self.assertNotIn(record, frames)
                self.assertEqual([f.number for f in frames], ['1', '3'])
                self.assertEqual(ext._frnum, 2)

    def test_a_trailing_record_ends_the_capture(self) -> None:
        engine, ext = self._engine([_packet(1), _record(2, RECORD_FRAME, 'systemd_journal')])
        engine.read_frame()
        with self.assertRaises(StopIteration):
            engine.read_frame()
        self.assertEqual(ext._frnum, 1)

    def test_verbose_mode_prints_a_commented_packet(self) -> None:
        engine, ext = self._engine([_packet(1, comment=True), _packet(2)])
        vars(ext).update(_exlyr='none', _exptl='null', _exctx=None, _flag_r=False, _flag_v=True,
                         _ifnm='test.pcapng', record_header=lambda: None)
        stream = engine._extmp
        engine._expkg = types.SimpleNamespace(FileCapture=lambda *args, **kwargs: stream)
        engine.run()  # installs the verbose handler

        with contextlib.redirect_stdout(io.StringIO()) as out:
            engine.read_frame()
            engine.read_frame()
        self.assertEqual(out.getvalue().splitlines(),
                         [f'Frame   1: {PROTOCOLS}', f'Frame   2: {PROTOCOLS}'])


if __name__ == '__main__':
    unittest.main()
