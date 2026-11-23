# -*- coding: utf-8 -*-
"""A reassembly adapter registered on PyShark, PyPCAP or pcap-ct is fed.

GitHub issue #2893. None of the three ships a ``__reassembly__`` entry, so
``_setup_reassembly`` turns reassembly off with a warning. Once a caller registers
an adapter on one, ``_setup_reassembly`` keeps reassembly on, but none of the three
called ``EngineBase._reassemble``, so the reassembler received nothing and nothing
warned. Each now feeds a registered adapter, in the calling convention its
``__reassembly__`` documents, and advances every reassembler to the frame's
timestamp; for PyShark that is :func:`pcapkit.toolkit.pyshark.packet2timestamp`.

Neither ``pyshark`` nor ``pcap`` need be usable here: each ``read_frame`` is
driven on an engine built with ``__new__``, over fake packets or frames. Classes are
imported inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import ast
import inspect
import textwrap
import types
import unittest
import warnings
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: The name the dummy reassembler is registered under.
NAME = 'dummy'

#: Capture timestamps of the frames every case reads, as tshark prints them.
EPOCHS = ('1000.000000000', '1000.500000000', '1061.000000000')

#: The same timestamps, as the engines hand them on.
TIMES = (1000.0, 1000.5, 1061.0)


def engines() -> 'list[type]':
    """Every engine class: the default engine's readers, then each registered engine."""
    from pcapkit.corekit.module import ModuleDescriptor
    from pcapkit.foundation.engines.pcap import PCAP
    from pcapkit.foundation.engines.pcapng import PCAPNG
    from pcapkit.foundation.extraction import Extractor

    found = [PCAP, PCAPNG]
    for entry in Extractor.__engine__.values():
        found.append(entry.klass if isinstance(entry, ModuleDescriptor) else entry)
    return found


def frame_layer(**fields: 'Any') -> 'types.SimpleNamespace':
    """A fake PyShark ``frame`` layer carrying ``fields``."""
    return types.SimpleNamespace(layer_name='frame', field_names=list(fields), **fields)


def pyshark_packet(frame: 'types.SimpleNamespace', *, sniff_timestamp: str = '0.000000000',
                   comment: bool = False) -> 'types.SimpleNamespace':
    """A fake PyShark packet whose ``frame`` layer is ``frame``.

    A commented packet's ``frame_info`` is its ``pkt_comment`` layer, and its frame
    layer is ``layers[0]``, as PyShark reports one.

    """
    if comment:
        note = types.SimpleNamespace(layer_name='pkt_comment', field_names=['comment'], comment='note')
        return types.SimpleNamespace(frame_info=note, layers=[frame], number='1',
                                     sniff_timestamp=sniff_timestamp)
    return types.SimpleNamespace(frame_info=frame, layers=[frame], number='1',
                                 sniff_timestamp=sniff_timestamp)


class ReassemblyFeedTestCase(unittest.TestCase):
    """Import once per class, and build engines over fake extractors."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _extractor(self, exnam: str, reasm: 'Any') -> 'types.SimpleNamespace':
        """A fake extractor holding ``reasm`` as the dummy reassembler, and nothing else on."""
        from pcapkit.foundation.reassembly import ReassemblyManager

        return types.SimpleNamespace(_flag_r=True, _exnam=exnam, _reasm=ReassemblyManager(**{NAME: reasm}),
                                     _flag_t=False, _flag_q=True, _flag_d=False, _frnum=0, _vfunc=mock.Mock())

    def _engine(self, base: type, extractor: 'Any', adapter: 'Any') -> 'Any':
        """An engine of a subclass of ``base`` with ``adapter`` registered, not yet run."""
        class Derived(base):  # type: ignore[valid-type,misc]
            pass

        Derived.register_reassembly(NAME.upper(), adapter)
        engine = Derived.__new__(Derived)
        engine._extractor = extractor

        # the shipped engine is left as it was
        self.assertEqual(base.__reassembly__, {})
        return engine

    def _setup(self, engine: 'Any') -> None:
        """Run ``_setup_reassembly``, which must keep the dummy and warn nothing."""
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            engine._setup_reassembly()
        self.assertTrue(engine._extractor._flag_r)
        self.assertEqual(list(engine._extractor._reasm), [NAME])

    def _assert_fed(self, reasm: 'Any', times: 'tuple[float, ...]') -> None:
        """``reasm`` was advanced to each of ``times``, and fed each record but the declined one."""
        self.assertEqual([call.args for call in reasm.advance.call_args_list], [(time,) for time in times])
        # each of a tuple is fed, and None feeds nothing
        self.assertEqual([call.args for call in reasm.call_args_list], [('first',), ('second',), ('third',)])


class LibpcapFeedTests(ReassemblyFeedTestCase):
    """PyPCAP and pcap-ct feed a registered adapter the frame's octets, timestamp and link type."""

    def test_a_registered_adapter_is_fed(self) -> None:
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.foundation.engines.pcap_ct import PCAP_CT
        from pcapkit.foundation.engines.pypcap import PyPCAP

        for (base, exnam) in ((PyPCAP, 'pypcap'), (PCAP_CT, 'pcap_ct')):
            with self.subTest(engine=base.__name__):
                reasm = mock.Mock()
                adapter = mock.Mock(side_effect=[('first', 'second'), None, 'third'])
                engine = self._engine(base, self._extractor(exnam, reasm), adapter)
                frames = [(time, f'raw {number}'.encode()) for (number, time) in enumerate(TIMES, 1)]
                engine._extmp = iter(frames)
                engine._dlink = LinkType.ETHERNET
                self._setup(engine)

                self.assertEqual([engine.read_frame() for _ in frames], frames)
                # the arguments the engine's flow tracing adapters take
                self.assertEqual(adapter.call_args_list,
                                 [mock.call(packet, time, data_link=LinkType.ETHERNET, count=number)
                                  for (number, (time, packet)) in enumerate(frames, 1)])
                self._assert_fed(reasm, TIMES)


class PySharkFeedTests(ReassemblyFeedTestCase):
    """PyShark feeds a registered adapter the packet, clocked by its capture timestamp."""

    def test_a_registered_adapter_is_fed(self) -> None:
        from pcapkit.foundation.engines.pyshark import PyShark

        reasm = mock.Mock()
        adapter = mock.Mock(side_effect=[('first', 'second'), None, 'third'])
        engine = self._engine(PyShark, self._extractor('pyshark', reasm), adapter)
        packets = [
            pyshark_packet(frame_layer(encap_type='1', time_epoch=EPOCHS[0])),
            # a commented packet's frame layer is not its frame_info
            pyshark_packet(frame_layer(encap_type='1', time_epoch=EPOCHS[1]), comment=True),
            # a Simple Packet Block has no frame.time_epoch, only the geninfo timestamp
            pyshark_packet(frame_layer(encap_type='1'), sniff_timestamp=EPOCHS[2]),
        ]
        engine._extmp = types.SimpleNamespace(next=iter(packets).__next__)
        self._setup(engine)

        self.assertEqual([engine.read_frame() for _ in packets], packets)
        self.assertEqual(adapter.call_args_list,
                         [mock.call(packet, count=number) for (number, packet) in enumerate(packets, 1)])
        self._assert_fed(reasm, TIMES)


class EveryEngineTests(ReassemblyFeedTestCase):
    """Every engine's ``read_frame`` feeds both of its adapter maps."""

    def _calls(self, engine: type) -> 'set[str]':
        """The methods of ``self`` that ``engine.read_frame`` calls."""
        tree = ast.parse(textwrap.dedent(inspect.getsource(engine.read_frame)))
        return {node.func.attr for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name) and node.func.value.id == 'self'}

    def test_read_frame_feeds_reassembly_and_flow_tracing(self) -> None:
        for engine in engines():
            with self.subTest(engine=engine.__name__):
                self.assertLessEqual({'_reassemble', '_traceflow'}, self._calls(engine))

    def test_each_engine_documents_its_calling_conventions(self) -> None:
        # an engine shipping no adapter still says how a registered one is called
        for engine in engines():
            with self.subTest(engine=engine.__name__):
                self.assertLessEqual({'__reassembly__', '__traceflow__'}, set(engine.__dict__))


class Packet2TimestampTests(ReassemblyFeedTestCase):
    """:func:`~pcapkit.toolkit.pyshark.packet2timestamp` reads the time ``tcp_traceflow`` records."""

    def test_frame_time_epoch_wins(self) -> None:
        from pcapkit.toolkit.pyshark import packet2timestamp

        packet = pyshark_packet(frame_layer(time_epoch='1500000000.000638000'), sniff_timestamp='1.0')
        self.assertEqual(packet2timestamp(packet), 1500000000.000638)
        self.assertEqual(packet2timestamp(pyshark_packet(frame_layer(time_epoch=EPOCHS[1]), comment=True)),
                         TIMES[1])

    def test_sniff_timestamp_stands_in(self) -> None:
        from pcapkit.toolkit.pyshark import packet2timestamp

        # a Simple Packet Block, whose geninfo timestamp is the UNIX epoch
        self.assertEqual(packet2timestamp(pyshark_packet(frame_layer())), 0.0)
        # and a record with no frame layer at all
        record = types.SimpleNamespace(frame_info=types.SimpleNamespace(layer_name='syscall'), layers=[],
                                       sniff_timestamp=EPOCHS[2])
        self.assertEqual(packet2timestamp(record), TIMES[2])

    def test_non_decimal_text_is_refused(self) -> None:
        from pcapkit.toolkit.pyshark import packet2timestamp
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, 'invalid frame.time_epoch'):
            packet2timestamp(pyshark_packet(frame_layer(time_epoch='Jan  1, 1970')))

    def test_exported(self) -> None:
        from pcapkit.toolkit import pyshark

        self.assertIn('packet2timestamp', pyshark.__all__)


if __name__ == '__main__':
    unittest.main()
