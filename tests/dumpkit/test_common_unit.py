from __future__ import annotations

import datetime
import decimal
import enum
import importlib.util
import io
from ipaddress import ip_address
import pathlib
import struct
import tempfile
import types
import unittest
from unittest import mock
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


class PlainEnum(enum.Enum):
    VALUE = 1


class RichEnum(enum.Enum):
    VALUE = 2

    def __init__(self, value: int) -> None:
        self.label = f'value-{value}'


class BaseDumper:
    def object_hook(self, value):
        return {'base': value}

    def _encode_func(self, value):
        def encode(encoded_value, file):
            file.write(repr(encoded_value))

        return encode


class SlotObject:
    __slots__ = ('name',)

    def __init__(self) -> None:
        self.name = 'slot'


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DumpkitCommonTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_dumper_subclass_registration_is_opt_in(self) -> None:
        """Registration happens if and only if ``fmt`` is given.

        This is the #514 opt-in contract, extended to the fifth pair. Before it,
        an absent ``fmt`` was *inferred* from the subclass'
        :attr:`~dictdumper.dumper.Dumper.kind` property -- which is an instance
        property, so the old code constructed an instance against a
        :func:`tempfile.NamedTemporaryFile` while the ``class`` statement was
        still executing. A class definition no longer touches the filesystem.

        """
        from pcapkit.dumpkit.common import Dumper

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class ExplicitDumper(Dumper, fmt='CUSTOM', ext='.custom'):
                    pass

        extractor.assert_called_once_with('custom', ExplicitDumper, '.custom')
        traceflow.assert_called_once_with('custom', ExplicitDumper, '.custom')

        # ``ext`` is still inferred from ``fmt`` -- that is a default for a format
        # that *was* given, not a decision to register.
        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class FormatOnlyDumper(Dumper, fmt='FMTONLY'):
                    pass

        extractor.assert_called_once_with('fmtonly', FormatOnlyDumper, '.fmtonly')
        traceflow.assert_called_once_with('fmtonly', FormatOnlyDumper, '.fmtonly')

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                with mock.patch('tempfile.NamedTemporaryFile') as named_temp:
                    class InferredDumper(Dumper):
                        @property
                        def kind(self):
                            return 'AUTO'

        extractor.assert_not_called()
        traceflow.assert_not_called()
        # the old inference path is gone, not merely unused
        named_temp.assert_not_called()

    def test_dumper_subclass_rejects_ext_without_fmt(self) -> None:
        """``ext`` alone cannot register anything, so it raises rather than no-op.

        With registration keyed on ``fmt``, an ``ext`` on its own has no format
        to attach to. Accepting it would silently discard the caller's intent.

        """
        from pcapkit.dumpkit.common import Dumper
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with self.assertRaises(UnsupportedCall) as caught:
                class ExtOnly(Dumper, ext='.lonely'):
                    pass

        extractor.assert_not_called()
        self.assertIn('.lonely', str(caught.exception))

    def test_dumper_subclass_rejects_unrecognised_keyword(self) -> None:
        """A misspelled class keyword raises instead of being swallowed."""
        from pcapkit.dumpkit.common import Dumper
        from pcapkit.utilities.exceptions import UnsupportedCall

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with self.assertRaises(UnsupportedCall) as caught:
                class Typo(Dumper, format='wrong-keyword-for-dumper'):
                    pass

        extractor.assert_not_called()
        self.assertIn('format', str(caught.exception))

    def test_make_dumper_object_hook_conversions_and_fallbacks(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.dumpkit.common import make_dumper

        Dumper = make_dumper(BaseDumper)
        dumper = Dumper()

        self.assertEqual(dumper.object_hook(decimal.Decimal('1.25')), '1.25')
        self.assertEqual(dumper.object_hook(datetime.timedelta(seconds=2.5)), 2.5)
        plain_dict = {'plain': 'dict'}
        self.assertIs(dumper.object_hook(plain_dict), plain_dict)
        self.assertEqual(dumper.object_hook(Info(answer=42)), {'answer': 42})
        self.assertEqual(dumper.object_hook(ip_address('192.0.2.1')), '192.0.2.1')

        multidict = MultiDict()
        multidict.add(PlainEnum.VALUE, 'enum-value')
        multidict.add('plain', 'value')
        converted = dumper.object_hook(multidict)
        self.assertEqual(converted['PlainEnum::VALUE [1]'], ['enum-value'])
        self.assertEqual(converted['plain'], ['value'])

        ordered = OrderedMultiDict([('first', 1), ('first', 2)])
        self.assertEqual(dumper.object_hook(ordered)['first'], [1, 2])

        self.assertEqual(dumper.object_hook(PlainEnum.VALUE), 'PlainEnum::VALUE [1]')
        rich = dumper.object_hook(RichEnum.VALUE)
        self.assertEqual(rich['enum'], 'RichEnum::VALUE [2]')
        self.assertEqual(rich['label'], 'value-2')
        self.assertEqual(dumper.object_hook(object())['base'].__class__, object)
        self.assertEqual(dumper.default(object()), 'fallback')

        file = io.StringIO()
        dumper._append_fallback(SlotObject(), file)
        self.assertEqual(file.getvalue(), "{'name': 'slot'}")

        file = io.StringIO()
        dumper._append_fallback(types.SimpleNamespace(name='dict'), file)
        self.assertEqual(file.getvalue(), "{'name': 'dict'}")

        file = io.StringIO()
        dumper._append_fallback(123, file)
        self.assertEqual(file.getvalue(), "'123'")


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class DumpkitIOTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_null_dumper_noops_and_pcap_dumper_writes_file(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.null import NotImplementedIO
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        with tempfile.TemporaryDirectory() as tempdir:
            null_path = pathlib.Path(tempdir) / 'null.out'
            null = NotImplementedIO(str(null_path))
            self.assertEqual(null.kind, 'null')
            self.assertIs(null({'ignored': True}), null)
            null._append_value({'ignored': True}, io.StringIO(), '')

            pcap_path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(pcap_path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            self.assertEqual(dumper.kind, 'pcap')
            header_size = pcap_path.stat().st_size
            frame = Frame(
                frame_info=FrameInfo(ts_sec=1, ts_usec=250000,
                                     incl_len=4, orig_len=4),
                time='time',
                number=1,
                time_epoch=1.25,
                len=4,
                cap_len=4,
            )
            frame.__update__(packet=b'abcd')
            self.assertIs(dumper(frame), dumper)
            self.assertGreater(pcap_path.stat().st_size, header_size)

    def test_pcap_dumper_writes_the_record_header_in_the_global_header_byte_order(self) -> None:
        # The dumper writes the 16-octet record header itself instead of building a
        # Frame to pack it, so the byte order of those four uint32 fields is now this
        # module's responsibility rather than the schema's. It has to match the magic
        # number in front of them, and 'big' has to keep working on a little-endian
        # host -- which is exactly what a struct format hardcoded to one endianness
        # would silently get wrong.
        #
        # Values are chosen to be byte-order-visible: every field is asymmetric, so a
        # wrong endianness cannot coincide with a right one.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        payload = bytes(range(6))
        for byteorder, endian in (('little', '<'), ('big', '>')):
            for nanosecond in (False, True):
                with self.subTest(byteorder=byteorder, nanosecond=nanosecond):
                    with tempfile.TemporaryDirectory() as tempdir:
                        path = pathlib.Path(tempdir) / 'sample.pcap'
                        dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                                        byteorder=byteorder, nanosecond=nanosecond)
                        header_size = path.stat().st_size

                        frame = Frame(
                            frame_info=FrameInfo(ts_sec=0x01020304, ts_usec=0x05060708,
                                                 incl_len=len(payload), orig_len=0x0A0B0C0D),
                            time='time', number=1, time_epoch=1.25,
                            len=len(payload), cap_len=0x0A0B0C0D,
                        )
                        frame.__update__(packet=payload)
                        dumper(frame)

                        self.assertEqual(
                            path.read_bytes()[header_size:],
                            struct.pack(f'{endian}IIII', 0x01020304, 0x05060708,
                                        len(payload), 0x0A0B0C0D) + payload,
                        )

    def test_pcap_dumper_truncates_an_out_of_range_record_field(self) -> None:
        # UInt32Field, which used to pack these four fields, masks to the field width
        # in NumberField.pre_process instead of rejecting an out-of-range value, so
        # the dumper silently wrote a wrapped one. struct.pack raises on the same
        # input, so writing the header directly would have turned a written -- if
        # wrong -- record into a struct.error. Pinned so the mask is not mistaken for
        # dead defensiveness and dropped: this is behaviour being preserved, not
        # behaviour being chosen.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            header_size = path.stat().st_size

            frame = Frame(
                frame_info=FrameInfo(ts_sec=2 ** 32 + 5, ts_usec=7,
                                     incl_len=2, orig_len=2),
                time='time', number=1, time_epoch=1.0, len=2, cap_len=2,
            )
            frame.__update__(packet=b'ab')
            dumper(frame)

            self.assertEqual(path.read_bytes()[header_size:],
                             struct.pack('<IIII', 5, 7, 2, 2) + b'ab')

    def test_pcap_dumper_appends_each_frame_without_reparsing_it(self) -> None:
        # Successive frames have to accumulate, and each record has to be the caller's
        # own octets verbatim -- the dumper no longer round-trips them through a Frame
        # construction, which packed the record and then dissected it again through
        # the whole protocol stack to reach bytes it had just been handed.
        #
        # The payload here is deliberately not a valid Ethernet frame: under the old
        # rebuild it was dissected anyway, so a dumper that reparses is not merely
        # slower but is doing work that can warn or raise on data it only had to copy.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO
        from pcapkit.protocols.data.misc.pcap.frame import Frame, FrameInfo

        def make(number: int, packet: bytes) -> Frame:
            frame = Frame(
                frame_info=FrameInfo(ts_sec=number, ts_usec=0, incl_len=len(packet),
                                     orig_len=len(packet)),
                time='time', number=number, time_epoch=float(number),
                len=len(packet), cap_len=len(packet),
            )
            frame.__update__(packet=packet)
            return frame

        with tempfile.TemporaryDirectory() as tempdir:
            path = pathlib.Path(tempdir) / 'sample.pcap'
            dumper = PCAPIO(str(path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)
            header_size = path.stat().st_size

            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                self.assertIs(dumper(make(1, b'\xff' * 3)), dumper)
                self.assertIs(dumper(make(2, b'\xfe' * 5)), dumper)

            self.assertEqual(
                path.read_bytes()[header_size:],
                struct.pack('<IIII', 1, 0, 3, 3) + b'\xff' * 3
                + struct.pack('<IIII', 2, 0, 5, 5) + b'\xfe' * 5,
            )
            # The frame counter still advances once per frame, and nothing was parsed.
            self.assertEqual(dumper._fnum, 3)
            self.assertEqual([str(entry.message) for entry in caught], [])

    def test_pcap_dumper_cannot_serialise_a_mapping_frame(self) -> None:
        # Why Extractor substitutes a dict-capable trace format for the DPKT, Scapy,
        # PyShark and PyPCAPFile engines: their flow-tracing adapters report each
        # frame as a plain dict from ``packet2dict``, and this dumper reads
        # ``value.packet`` and ``value.frame_info`` off a dissected Frame. Pinned
        # here so the guard's justification is checked rather than asserted in a
        # comment -- if this dumper ever learns to take a mapping, the guard is what
        # should be revisited.
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.dumpkit.pcap import PCAPIO

        with tempfile.TemporaryDirectory() as tempdir:
            pcap_path = pathlib.Path(tempdir) / 'mapping.pcap'
            dumper = PCAPIO(str(pcap_path), protocol=LinkType.ETHERNET,
                            byteorder='little', nanosecond=False)

            # The shape ``packet2dict`` produces: keys, not attributes.
            with self.assertRaises(AttributeError) as caught:
                dumper({'frame_info': {'ts_sec': 1}, 'packet': b'abcd'}, name='Frame 1')
            self.assertIn('packet', str(caught.exception))


if __name__ == '__main__':
    unittest.main()
