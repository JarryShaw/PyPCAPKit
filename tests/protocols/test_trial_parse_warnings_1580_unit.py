# -*- coding: utf-8 -*-
"""GitHub issue #1580: a next layer replaced by ``Raw`` reports no warnings.

:meth:`~pcapkit.protocols.protocol.ProtocolBase._parse_next_layer` parses a next
layer on trial and keeps it as :class:`~pcapkit.protocols.misc.raw.Raw` when
fewer octets were captured than its header needs (#1170). The trial's warnings
were reported anyway, for a layer the result does not have. A PCAP-NG Simple
Packet Block cut to 10 octets by its interface's snaplen warned ``packet length
< 0: -2`` and ``-4`` from the Ethernet header it then dropped, on parse, on both
``from_data`` rebuilds and on ``make``. Nothing in it is PCAP-NG's: an Enhanced
Packet Block, an obsolete Packet Block and a PCAP record cut the same way warned
the same, in either byte order.

A next layer captured shorter than its length hint is now parsed under
:class:`~pcapkit.utilities.warnings.hold_warnings`, and its warnings are dropped
with the layer. A layer that is kept reports them from the caller's line when its
trial ends, inside the same guard -- so under an ``error`` filter every chain is
the one parsed holding nothing -- and a cut header that stays in the chain still
warns (#1470). Any other layer is parsed holding nothing. Holding leaves the
warnings filters and every ``__warningregistry__`` alone, lets a
:exc:`BaseException` through untouched, and survives a block left out of order.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import contextvars
import inspect
import struct
import unittest
import unittest.mock
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class
from tests.utilities import _unrelated_warning
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any

#: Snaplen of the capture's interface, and so the octets each packet keeps.
SNAPLEN = 10
#: Original length of each packet, longer than the Ethernet header.
ORIGINAL = 57
#: The packet data captured.
DATA = bytes(range(SNAPLEN))

#: Ethernet destination and source addresses.
MACS = bytes(6) + bytes.fromhex('020000000001')
#: An IPv4 header of total length 30, carrying TCP.
IPV4_TCP = bytes.fromhex('4500001e00000000400600007f0000017f000001')

#: Messages for a 10-octet TCP header kept in the chain, measured unchanged against
#: the tree before the fix: the data offset is cut off, so its length reads as 0.
TCP_CUT_MESSAGES = ['packet length < 0: -2', 'packet length < 0: -3', 'packet length < 0: -4',
                    'packet length < 0: -6', 'packet length < 0: -8', 'packet length < 0: -10']


#: Whole frames cut at every length by the chain comparison: Ethernet, IPv4 with
#: an option and TCP with an MSS option; IPv6 and UDP; a VLAN tag, IPv4 and UDP;
#: and ARP.
FRAMES = (
    MACS + b'\x08\x00' + bytes.fromhex('46000034000000004006000' '07f0000017f000002' '01010100')
    + bytes.fromhex('30390050000000010000000060020' 'fff000000' '020405b4') + b'abcd',
    MACS + b'\x86\xdd' + bytes.fromhex('60000000000c1140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
    + bytes.fromhex('00350035000c0000') + b'abcd',
    MACS + b'\x81\x00' + bytes.fromhex('00010800') + bytes.fromhex('45000020000000004011000' '07f0000017f000002')
    + bytes.fromhex('00350035000c0000') + b'abcd',
    MACS + b'\x08\x06' + bytes.fromhex('0001080006040001') + bytes(6) + bytes.fromhex('7f000001')
    + bytes(6) + bytes.fromhex('7f000002'),
)


class _HoldNothing:
    """A stand-in for :class:`hold_warnings` that holds nothing, as before #1580."""

    discard = False

    def __init__(self, hold: 'bool' = True) -> None:
        del hold

    def __enter__(self) -> '_HoldNothing':
        return self

    def __exit__(self, *exc_info: 'object') -> None:
        return None


def _block(endian: 'str', type_: 'int', body: 'bytes') -> 'bytes':
    """A PCAP-NG block of ``type_`` around ``body``."""
    length = len(body) + 12
    return struct.pack(f'{endian}II', type_, length) + body + struct.pack(f'{endian}I', length)


def _pcapng(endian: 'str', type_: 'int') -> 'tuple[bytes, bytes]':
    """A one-packet capture over a snaplen of 10, and its packet block."""
    shb = _block(endian, 0x0A0D0D0A, struct.pack(f'{endian}IHHq', 0x1A2B3C4D, 1, 0, -1))
    idb = _block(endian, 1, struct.pack(f'{endian}HHI', 1, 0, SNAPLEN))  # Ethernet
    data = DATA + bytes(-len(DATA) % 4)
    body = {
        3: struct.pack(f'{endian}I', ORIGINAL) + data,
        6: struct.pack(f'{endian}IIIII', 0, 0, 0, SNAPLEN, ORIGINAL) + data,
        2: struct.pack(f'{endian}HHIIII', 0, 0, 0, 0, SNAPLEN, ORIGINAL) + data,
    }[type_]
    block = _block(endian, type_, body)
    return shb + idb + block, block


class TestTrialParseWarnings(unittest.TestCase):
    """Pin that a next layer replaced by ``Raw`` reports nothing, and a kept one does."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _schema(self, caught: 'list[warnings.WarningMessage]') -> 'list[str]':
        """Messages of the :class:`SchemaWarning` among ``caught``."""
        from pcapkit.utilities.warnings import SchemaWarning

        return [str(item.message) for item in caught if issubclass(item.category, SchemaWarning)]

    def _extract(self, octets: 'bytes', name: 'str') -> 'tuple[Any, list[warnings.WarningMessage]]':
        """Extract ``octets`` in memory, with the warnings it reports."""
        from pcapkit.foundation.extraction import Extractor
        from tests.protocols.misc.test_pcapng_unit import NamedBuffer

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            extractor = Extractor(NamedBuffer(octets, name), nofile=True, store=True)
        return extractor, caught

    def test_cut_packet_blocks_warn_nothing(self) -> None:
        """SPB, EPB and Packet Block cut to 10 octets, in both byte orders, on every path."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.protocols.misc.raw import Raw

        for endian in '<>':
            for type_ in (BlockType.Simple_Packet_Block, BlockType.Enhanced_Packet_Block,
                          BlockType.Packet_Block):
                with self.subTest(endian=endian, type=type_):
                    octets, block = _pcapng(endian, int(type_))
                    extractor, caught = self._extract(octets, 'truncated.pcapng')
                    self.assertEqual(self._schema(caught), [])

                    frame, = extractor.frame
                    self.assertEqual(frame.info.captured_len, SNAPLEN)
                    self.assertEqual(frame.info.original_len, ORIGINAL)
                    self.assertIsInstance(frame.payload, Raw)
                    self.assertEqual(frame.payload.data, DATA)

                    context = extractor.engine._ctx_list[0]  # pylint: disable=protected-access
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        rebuilt = [PCAPNG.from_data(info, num=1, sct=1, ctx=context).data
                                   for info in (frame.info, frame.info.to_dict())]
                        made = PCAPNG(num=1, sct=1, ctx=context, type=type_,
                                      block={'packet_data': bytes(range(ORIGINAL)), 'timestamp': 0})
                    self.assertEqual(self._schema(caught), [])
                    self.assertEqual(rebuilt, [block, block])
                    self.assertEqual(made.data, block)

    def test_cut_pcap_record_warns_nothing(self) -> None:
        """A PCAP record of 10 octets: the Ethernet header was not PCAP-NG's to drop."""
        from pcapkit.protocols.misc.raw import Raw

        header = struct.pack('<IHHiIII', 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # Ethernet
        record = struct.pack('<IIII', 0, 0, SNAPLEN, ORIGINAL) + DATA
        extractor, caught = self._extract(header + record, 'truncated.pcap')
        self.assertEqual(self._schema(caught), [])

        frame, = extractor.frame
        self.assertIsInstance(frame.payload, Raw)
        self.assertEqual(frame.payload.data, DATA)

    def test_ethernet_asked_for_still_warns(self) -> None:
        """``Ethernet(bytes(10))`` is not on trial: it is built directly, kept, and warns."""
        from pcapkit.protocols.link.ethernet import Ethernet

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = Ethernet(bytes(10))
        self.assertIsInstance(parsed, Ethernet)
        self.assertEqual(self._schema(caught), ['packet length < 0: -2', 'packet length < 0: -4'])

    def test_kept_cut_layers_still_warn_from_the_callers_line(self) -> None:
        """Held layers that are kept, or that raise, report as they did, on both channels."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.utilities.logging import logger
        from pcapkit.utilities.warnings import SchemaWarning

        # TCP cut to 10 octets is held, inside IPv4 and Ethernet, which are not;
        # IPv4 cut to 18 octets is held and raises, and the error path keeps it.
        cases = ((MACS + b'\x08\x00' + IPV4_TCP + bytes(10), 'Ethernet:IPv4:TCP', TCP_CUT_MESSAGES),
                 (MACS + b'\x08\x00' + IPV4_TCP[:18], 'Ethernet:Internet_Protocol_version_4',
                  ['packet length < 0: -2'] * 2))
        for frame, chain, messages in cases:
            with self.subTest(chain=chain):
                with capture(logger) as recorder:
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        line = inspect.currentframe().f_lineno + 1  # type: ignore[union-attr]
                        parsed = Ethernet(frame, len(frame))
                self.assertEqual(str(parsed.protochain), chain)
                self.assertEqual(self._schema(caught), messages)
                self.assertEqual({(item.category, item.filename, item.lineno) for item in caught},
                                 {(SchemaWarning, __file__, line)})
                # the error path also logs the error itself, which is not a warning
                self.assertEqual([(record.getMessage(), record.pathname, record.lineno)
                                  for record in recorder.records
                                  if record.getMessage().startswith('packet length')],
                                 [(message, __file__, line) for message in messages])

    def test_cut_layer_logs_nothing(self) -> None:
        """The logger channel drops a discarded trial's warnings too."""
        from pcapkit.utilities.logging import logger

        octets, _ = _pcapng('<', 3)
        with capture(logger) as recorder:
            self._extract(octets, 'truncated.pcapng')
        self.assertFalse([record for record in recorder.records
                          if record.getMessage().startswith('packet length')], recorder.messages)

    def test_holds_nest(self) -> None:
        """Each block reports what it keeps when it is left; a discarded one drops its own."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import ProtocolBase
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings():
                warn('outer, before', SchemaWarning)
                with hold_warnings() as inner:
                    warn('inner, discarded', SchemaWarning)
                    inner.discard = True
                trial = ProtocolBase._parse_next_layer(Ethernet, bytes(10), 10)  # pylint: disable=protected-access
                with hold_warnings():
                    warn('inner, kept', SchemaWarning)
                with hold_warnings(False):
                    warn('held by nothing', SchemaWarning)
                self.assertEqual(self._schema(caught), ['inner, kept', 'held by nothing'])
                warn('outer, after', SchemaWarning)
            with hold_warnings() as outer:
                with hold_warnings():
                    warn('kept where the inner block is left', SchemaWarning)
                warn('dropped with the outer block', SchemaWarning)
                outer.discard = True
        self.assertIsInstance(trial, Raw)
        self.assertEqual(self._schema(caught), ['inner, kept', 'held by nothing', 'outer, before',
                                                'outer, after', 'kept where the inner block is left'])
        self.assertEqual({item.filename for item in caught}, {__file__})

    def test_layer_that_cannot_be_replaced_holds_nothing(self) -> None:
        """Ethernet of 32 octets is past its hint, so even a discarding block cannot drop its warnings."""
        from pcapkit.protocols.link.ethernet import Ethernet
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import ProtocolBase, _short_of_hint
        from pcapkit.utilities.warnings import hold_warnings

        class NeedsAnInstance:
            """A hint that cannot be read from the class."""

            def __length_hint__(self) -> 'int':
                return len(self.__dict__)

        self.assertEqual([_short_of_hint(Ethernet, 13), _short_of_hint(Ethernet, 14),
                          _short_of_hint(Raw, 0), _short_of_hint(NeedsAnInstance, 10 ** 6)],  # type: ignore[arg-type]
                         [True, False, False, True])

        frame = MACS + b'\x08\x00' + IPV4_TCP[:18]
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings() as outer:
                parsed = ProtocolBase._parse_next_layer(Ethernet, frame, len(frame))  # pylint: disable=protected-access
                outer.discard = True
        self.assertEqual(str(parsed.protochain), 'Ethernet:Internet_Protocol_version_4')
        self.assertEqual(self._schema(caught), ['packet length < 0: -2'] * 2)

    def test_error_filter_chains_match_holding_nothing(self) -> None:
        """Under ``error``, every cut of four frames parses to the chain it has holding nothing.

        A warning made an error is raised where the trial that kept it ends,
        inside the guard it was raised in when nothing was held, so the same
        layer, and only it, becomes ``Raw``. Holding until the outermost trial
        ended instead turned the whole subtree into ``Raw``.

        """
        import pcapkit.protocols.protocol as protocol_module
        from pcapkit.protocols.link.ethernet import Ethernet

        def chains() -> 'list[str]':
            found = []
            with warnings.catch_warnings():
                warnings.simplefilter('error')
                for frame in FRAMES:
                    for cut in range(1, len(frame) + 1):
                        try:
                            found.append(str(Ethernet(frame[:cut], cut).protochain))
                        except Exception as exc:  # pylint: disable=broad-except
                            found.append(f'raised {type(exc).__name__}')
            return found

        held = chains()
        with unittest.mock.patch.object(protocol_module, 'hold_warnings', _HoldNothing):
            reference = chains()
        self.assertEqual(len(held), sum(map(len, FRAMES)))
        self.assertEqual(held, reference)
        self.assertGreater(len(set(held)), 8, set(held))

        frame = MACS + b'\x08\x00' + IPV4_TCP + bytes(10)
        with warnings.catch_warnings():
            warnings.simplefilter('error')
            self.assertEqual(str(Ethernet(frame, len(frame)).protochain), 'Ethernet:IPv4:TCP')

    def test_always_filter_only_drops_warnings(self) -> None:
        """Under ``always``, every cut reports the warnings it reports holding nothing, less some."""
        import pcapkit.protocols.protocol as protocol_module
        from pcapkit.protocols.link.ethernet import Ethernet

        def reports() -> 'list[list[tuple[Any, ...]]]':
            found = []
            for frame in FRAMES:
                for cut in range(1, len(frame) + 1):
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        try:
                            Ethernet(frame[:cut], cut)
                        except Exception:  # pylint: disable=broad-except
                            pass
                    found.append([(item.category, str(item.message), item.filename, item.lineno)
                                  for item in caught])
            return found

        held = reports()
        with unittest.mock.patch.object(protocol_module, 'hold_warnings', _HoldNothing):
            reference = reports()
        for kept, every in zip(held, reference):
            remaining = iter(every)
            self.assertTrue(all(item in remaining for item in kept), (kept, every))
        self.assertLess(sum(map(len, held)), sum(map(len, reference)))

    def test_base_exception_is_let_through(self) -> None:
        """A :exc:`BaseException` leaves a block as itself, its held warnings dropped."""
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        for error in (KeyboardInterrupt, SystemExit, GeneratorExit):
            for action in ('error', 'always'):
                with self.subTest(error=error.__name__, action=action):
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter(action)
                        with self.assertRaises(error):
                            with hold_warnings():
                                warn('held when the interrupt came', SchemaWarning)
                                raise error()
                    self.assertEqual(caught, [])

    def test_hold_left_by_an_error_reports(self) -> None:
        """A block left by an exception reports what it held, discarded or not."""
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with self.assertRaises(KeyError):
                with hold_warnings() as held:
                    warn('held, then an error', SchemaWarning)
                    held.discard = True
                    raise KeyError('mid-parse')
        self.assertEqual(self._schema(caught), ['held, then an error'])

    def test_held_frame_gone_is_reported_outside_pcapkit(self) -> None:
        """A level past the stack, with no frame to find again, still blames this file."""
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings():
                warn('past the outermost frame', SchemaWarning, stacklevel=10 ** 6)
        self.assertEqual([(str(item.message), item.filename) for item in caught],
                         [('past the outermost frame', __file__)])

    def test_hold_is_local_to_its_context(self) -> None:
        """A warning reported in another context is not held by this one's block."""
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings() as held:
                contextvars.Context().run(warn, 'another context', SchemaWarning)
                self.assertEqual(self._schema(caught), ['another context'])
                held.discard = True
        self.assertEqual(self._schema(caught), ['another context'])

    def test_hold_left_out_of_order(self) -> None:
        """A generator's block left out of order neither ends another block nor outlives itself."""
        import pcapkit.utilities.warnings as warnings_module
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        def generator() -> 'Any':
            with hold_warnings():
                warn('generator', SchemaWarning)
                yield

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')

            # the generator's block is left while the caller's, opened after it, is open
            suspended = generator()
            next(suspended)
            with hold_warnings() as caller:
                next(suspended, None)
                warn('caller, discarded', SchemaWarning)
                caller.discard = True
            warn('after both', SchemaWarning)

            # the caller's block is left while the generator's, opened inside it, is open
            with hold_warnings():
                suspended = generator()
                next(suspended)
            next(suspended, None)
            warn('after both again', SchemaWarning)
        self.assertEqual(self._schema(caught), ['generator', 'after both', 'generator', 'after both again'])
        self.assertIsNone(warnings_module._HELD.get())  # pylint: disable=protected-access

    def test_hold_left_in_a_copied_context(self) -> None:
        """A block left in a copy of its context unsets itself there, and is stepped over here."""
        import pcapkit.utilities.warnings as warnings_module
        from pcapkit.utilities.warnings import SchemaWarning, hold_warnings, warn

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            with hold_warnings() as outer:
                block = hold_warnings()
                block.__enter__()  # pylint: disable=unnecessary-dunder-call
                contextvars.copy_context().run(block.__exit__, None, None, None)
                warn('held by the outer block', SchemaWarning)
                outer.discard = True
            warn('after both', SchemaWarning)
        self.assertEqual(self._schema(caught), ['after both'])
        self.assertIsNone(warnings_module._HELD.get())  # pylint: disable=protected-access

    def test_filters_and_registries_are_untouched(self) -> None:
        """Holding and dropping changes no filter, so a once-only warning stays once.

        Any change to the filters invalidates every ``__warningregistry__``, and
        the unrelated module's second warning would then be reported again.

        """
        from pcapkit.foundation.extraction import Extractor
        from pcapkit.protocols.link.ethernet import Ethernet
        from tests.protocols.misc.test_pcapng_unit import NamedBuffer

        octets, _ = _pcapng('>', 3)
        with warnings.catch_warnings(record=True) as caught:
            warnings.resetwarnings()
            warnings.simplefilter('default')
            snapshot = warnings.filters[:]

            _unrelated_warning.emit()
            Extractor(NamedBuffer(octets, 'truncated.pcapng'), nofile=True, store=True)  # dropped
            Ethernet(MACS + b'\x08\x00' + IPV4_TCP + bytes(10))  # held and kept
            _unrelated_warning.emit()

            self.assertEqual(warnings.filters, snapshot)
        unrelated = [item for item in caught if item.category is _unrelated_warning.UnrelatedWarning]
        self.assertEqual(len(unrelated), 1)
        self.assertEqual(self._schema(caught), TCP_CUT_MESSAGES)

    def test_hold_warnings_is_exported(self) -> None:
        """``import *`` brings ``hold_warnings`` in, as it does ``warnings.catch_warnings`` (#1602)."""
        import pcapkit.utilities.warnings as warnings_module

        self.assertIn('hold_warnings', warnings_module.__all__)
        namespace = {}  # type: dict[str, Any]
        exec('from pcapkit.utilities.warnings import *', namespace)  # pylint: disable=exec-used
        self.assertIs(namespace['hold_warnings'], warnings_module.hold_warnings)


if __name__ == '__main__':
    unittest.main()
