from __future__ import annotations

import datetime
import decimal
import enum
import importlib.util
import io
from ipaddress import ip_address
import pathlib
import tempfile
import types
import unittest
from unittest import mock

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

    def test_dumper_subclass_registration_explicit_and_inferred(self) -> None:
        from pcapkit.dumpkit.common import Dumper

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class ExplicitDumper(Dumper, fmt='CUSTOM', ext='.custom'):
                    pass

        extractor.assert_called_once_with('custom', ExplicitDumper, '.custom')
        traceflow.assert_called_once_with('custom', ExplicitDumper, '.custom')

        with mock.patch('pcapkit.foundation.extraction.Extractor.register_dumper') as extractor:
            with mock.patch('pcapkit.foundation.traceflow.traceflow.TraceFlow.register_dumper') as traceflow:
                class InferredDumper(Dumper):
                    @property
                    def kind(self):
                        return 'AUTO'

        extractor.assert_called_once_with('auto', InferredDumper, '.auto')
        traceflow.assert_called_once_with('auto', InferredDumper, '.auto')

    def test_make_dumper_object_hook_conversions_and_fallbacks(self) -> None:
        from pcapkit.corekit.infoclass import Info
        from pcapkit.corekit.multidict import MultiDict, OrderedMultiDict
        from pcapkit.dumpkit.common import make_dumper

        Dumper = make_dumper(BaseDumper)
        dumper = Dumper()

        self.assertEqual(dumper.object_hook(decimal.Decimal('1.25')), '1.25')
        self.assertEqual(dumper.object_hook(datetime.timedelta(seconds=2.5)), 2.5)
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


if __name__ == '__main__':
    unittest.main()
