# -*- coding: utf-8 -*-
"""A traced frame record is an ``Info``, not a ``dict`` subclass (#2726).

:class:`~pcapkit.foundation.traceflow.data.data.FrameRecord` is the engine's
dissection of a frame, as a mapping, with ``packet``, ``frame_info`` and
``time_epoch`` beside it as attributes the mapping does not show. It was a slotted
:class:`dict` subclass; the owner ruled on #2726 that no class subclass
:class:`dict` directly where an ``Info`` fits. These tests pin what the change
keeps -- the mapping, the attributes, what the dumpers write, and the dissection
``to_dict`` exports -- and that pickles load across it both ways, since a record
reduces to ``_frame_record`` as the 1.5 releases do.

"""

from __future__ import annotations

import decimal
import importlib.util
import ipaddress
import os
import pickle
import tempfile
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): pickling, whose protocols differ by interpreter.
__tier__ = 'ALL'

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Every pickle protocol, ``0`` and ``1`` included.
PROTOCOLS = tuple(range(pickle.HIGHEST_PROTOCOL + 1))

#: The engine's dissection; its ``packet`` differs from the record's on purpose.
MAPPING = {'packet': b'rebuilt', 'Ethernet': {'type': 2048, 'IPv4': {'ttl': 64}}}


def _record() -> 'Any':
    """A record whose mapping is :data:`MAPPING`, built after the per-class import."""
    from pcapkit.foundation.traceflow.data.data import FrameRecord
    from pcapkit.protocols.misc.pcap.frame.data import FrameInfo

    return FrameRecord(MAPPING, packet=b'captured',
                       frame_info=FrameInfo(ts_sec=1, ts_usec=2, incl_len=8, orig_len=9),
                       time_epoch=decimal.Decimal('1.000002'))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FrameRecordInfoTests(unittest.TestCase):
    """The record as an ``Info``: its mapping, its attributes and its exports."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_a_record_is_an_info_and_no_dict(self) -> None:
        from pcapkit.corekit.infoclass import Info

        record = _record()
        self.assertIsInstance(record, Info)
        self.assertNotIsInstance(record, dict)

    def test_the_mapping_is_the_dissection_and_the_attributes_stay_apart(self) -> None:
        record = _record()
        self.assertEqual(list(record.items()), list(MAPPING.items()))
        self.assertEqual(len(record), len(MAPPING))
        self.assertEqual(record, MAPPING)
        self.assertEqual(record['packet'], b'rebuilt')
        self.assertEqual(record.packet, b'captured')
        self.assertEqual((record.frame_info.ts_sec, record.time_epoch), (1, decimal.Decimal('1.000002')))
        self.assertNotIn('frame_info', record)
        self.assertNotIn('time_epoch', record)
        self.assertNotIn('captured', repr(record))

    def test_a_record_is_immutable(self) -> None:
        from pcapkit.utilities.exceptions import UnsupportedCall

        record = _record()
        with self.assertRaises(TypeError):
            record['packet'] = b''  # type: ignore[index]
        with self.assertRaises(UnsupportedCall):
            record.packet = b''  # type: ignore[misc]
        self.assertEqual((record['packet'], record.packet), (b'rebuilt', b'captured'))

    def test_to_dict_exports_the_dissection_alone(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.foundation.traceflow.data.tcp import Packet

        record = _record()
        traced = Packet(LinkType.ETHERNET, 1, record, True, False, False,
                        ipaddress.ip_address('192.0.2.1'), ipaddress.ip_address('198.51.100.2'),
                        1, 2, 1.0, 7, 8, b'header', bytearray(b'payload'))
        for export in (record.to_dict(), traced.to_dict()['frame']):
            self.assertIsInstance(export, OrderedMultiDict)
            self.assertEqual(list(export.items(multi=True)), list(MAPPING.items()))

    def test_every_dumper_writes_the_dissection_unchanged(self) -> None:
        import dictdumper

        from pcapkit.dumpkit.common import make_dumper

        record = _record()
        for kind in (dictdumper.JSON, dictdumper.PLIST, dictdumper.Tree):
            with self.subTest(dumper=kind.__name__), tempfile.TemporaryDirectory() as tmp:
                texts = []
                for name, value in (('record', record), ('dict', dict(MAPPING))):
                    path = os.path.join(tmp, name)
                    dumper = make_dumper(kind)(path)
                    dumper(value, name='Frame 1')
                    del dumper
                    with open(path, encoding='utf-8') as file:
                        texts.append(file.read())
                self.assertEqual(texts[0], texts[1])


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class FrameRecordPickleTests(unittest.TestCase):
    """Pickles load across the change, both ways, under every protocol."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_restored(self, clone: 'Any', record: 'Any') -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.foundation.traceflow.data.data import FrameRecord

        self.assertIs(type(clone), FrameRecord)
        self.assertIsInstance(clone, Info)
        self.assertEqual(clone, record)
        self.assertEqual((clone.packet, clone.frame_info, clone.time_epoch),
                         (record.packet, record.frame_info, record.time_epoch))

    def test_a_record_reduces_to_frame_record_under_every_protocol(self) -> None:
        # NOTE: the 1.5 releases reduce a record to ``_frame_record`` too, so a
        # pickle written here loads in them.
        from pcapkit.foundation.traceflow.data.data import _frame_record

        record = _record()
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                rebuild, args = record.__reduce_ex__(protocol)
                self.assertIs(rebuild, _frame_record)
                self.assertIs(type(args[0]), dict)
                self.assertEqual(args, (MAPPING, b'captured', record.frame_info, decimal.Decimal('1.000002')))
                self._assert_restored(pickle.loads(pickle.dumps(record, protocol=protocol)), record)

    def test_a_pickle_of_a_1_5_release_loads_as_the_info(self) -> None:
        # NOTE: the slotted dict subclass of the 1.5 releases, whose __reduce__
        # called _frame_record on its mapping and its slots.
        from pcapkit.foundation.traceflow.data.data import _frame_record

        class FrameRecord(dict):
            __slots__ = ('packet', 'frame_info', 'time_epoch')

            def __reduce__(self) -> 'Any':
                return _frame_record, (dict(self), self.packet, self.frame_info, self.time_epoch)

        record = _record()
        old = FrameRecord(MAPPING)
        old.packet, old.frame_info, old.time_epoch = record.packet, record.frame_info, record.time_epoch
        for protocol in PROTOCOLS:
            with self.subTest(protocol=protocol):
                self._assert_restored(pickle.loads(pickle.dumps(old, protocol=protocol)), record)

    def test_copies_keep_the_attributes_and_stay_immutable(self) -> None:
        import copy

        from pcapkit.utilities.exceptions import UnsupportedCall

        record = _record()
        for kind, clone in (('copy', copy.copy(record)), ('deepcopy', copy.deepcopy(record))):
            with self.subTest(kind=kind):
                self._assert_restored(clone, record)
                with self.assertRaises(UnsupportedCall):
                    clone.packet = b''


if __name__ == '__main__':
    unittest.main()
