# -*- coding: utf-8 -*-
"""GitHub issue #2362: a made PCAP-NG block defaults its timestamp to the clock.

Without the fix, :meth:`PCAPNG._make_timestamp
<pcapkit.protocols.misc.pcapng.PCAPNG._make_timestamp>` picks the clock a
defaulted timestamp is read to by reading :attr:`PCAPNG.nanosecond
<pcapkit.protocols.misc.pcapng.PCAPNG.nanosecond>`, which resolves its
interface through the parsed data model a block being made has not got, so
``make()`` without a ``timestamp`` raises
``AttributeError: 'PCAPNG' object has no attribute '_info'`` for every block
carrying one -- the Enhanced Packet Block, the obsolete Packet Block and the
Interface Statistics Block, the last through its ``isb_starttime`` and
``isb_endtime`` options as well as its own field. The resolution comes from the
interface ID the maker is given, so a defaulted timestamp is the current time,
read from the clock that interface's declared resolution calls for and scaled
to its units.

Every case builds its own blocks in memory and reads no capture.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import time
import unittest
import unittest.mock
import warnings
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any, Optional

#: Blocks whose maker defaults a timestamp, named rather than imported so that
#: this module loads without :mod:`pcapkit`.
TIMESTAMPED = ('Enhanced_Packet_Block', 'Packet_Block', 'Interface_Statistics_Block')

#: ``if_tsresol``'s own default, in units per second: a block whose interface
#: declares none counts microseconds.
DEFAULT_RESOLUTION = 1_000_000

#: ``if_tsresol`` of 9, in units per second: the resolution a block has to
#: declare for its default to be read from :func:`time.time_ns`.
NANOSECOND_RESOLUTION = 1_000_000_000

#: A :func:`time.time_ns` reading to pin, far enough from both the current time
#: and :data:`PINNED_SECOND` that the field it reaches names the clock it came
#: from.
PINNED_NANOSECOND = 1_700_000_000_123_456_789

#: A :func:`time.time` reading to pin, exactly representable so that scaling it
#: to :data:`DEFAULT_RESOLUTION` is exact.
PINNED_SECOND = 1_600_000_000.5

#: The raw timestamp field a defaulted timestamp is written to at each
#: resolution, with both clocks pinned and no ``if_tsoffset`` in play. The
#: nanosecond entry is :data:`PINNED_NANOSECOND` written in its own units; the
#: microsecond one is :data:`PINNED_SECOND` scaled, which is a value the
#: nanosecond clock cannot produce and vice versa.
PINNED_RAW = {
    NANOSECOND_RESOLUTION: PINNED_NANOSECOND,
    DEFAULT_RESOLUTION: int(PINNED_SECOND * DEFAULT_RESOLUTION),
}


class TestPCAPNGDefaultTimestamp(PCAPNGTestCase):
    """Pin the timestamp a block is made with when the caller names none."""

    def _timed_context(self, resolution: 'Optional[int]' = None,
                       offset: 'Optional[int]' = None) -> 'Any':
        """A one-interface context, optionally with ``if_tsresol``/``if_tsoffset``.

        Its own, rather than :meth:`PCAPNGTestCase._context
        <tests.protocols.misc.test_pcapng_roundtrip2_unit.PCAPNGTestCase._context>`,
        because the interface needs options the base helper does not take.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.foundation.engines.pcapng import Context
        from pcapkit.protocols.misc.pcapng import PCAPNG

        section = PCAPNG(num=0, sct=1, ctx=None, type=BlockType.Section_Header_Block, block={})
        context = Context(section.info)  # type: Any
        self._add_interface(context, resolution=resolution, offset=offset)
        return context

    def _add_interface(self, context: 'Any', resolution: 'Optional[int]' = None,
                       offset: 'Optional[int]' = None) -> 'Any':
        """Append one Ethernet interface to ``context``, and return its data model.

        Its index in the section is the ``interface_id`` a block names to be
        read at this interface's ``if_tsresol`` and ``if_tsoffset``.

        """
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        options = []  # type: list[Any]
        if resolution is not None:
            options.append((OptionType.if_tsresol, {'resolution': resolution}))
        if offset is not None:
            options.append((OptionType.if_tsoffset, {'offset': offset}))

        interface = PCAPNG(num=len(context.interfaces) + 1, sct=1, ctx=context,
                           type=BlockType.Interface_Description_Block,
                           block={'linktype': LinkType.ETHERNET, 'snaplen': 0,
                                  'options': options})
        context.interfaces.append(interface.info)
        return interface.info

    def assertIsNow(self, epoch: 'Any', before: 'float', after: 'float',  # pylint: disable=invalid-name
                    resolution: 'int' = DEFAULT_RESOLUTION) -> 'None':
        """Assert ``epoch`` is a clock read taken between ``before`` and ``after``.

        The field holds an integer count of ``resolution`` units, so the epoch
        it reads back as can sit up to one unit below ``before``, which is a
        full-precision :func:`time.time`.

        """
        self.assertGreaterEqual(float(epoch), before - 1 / resolution)
        self.assertLessEqual(float(epoch), after)

    def _raw_timestamp(self, made: 'Any') -> 'int':
        """The raw Timestamp (High)/(Low) pair of ``made``, in its own units."""
        block = made.schema.block
        return (block.timestamp_high << 32) | block.timestamp_low

    def _make(self, name: 'str', context: 'Any', **block: 'Any') -> 'Any':
        """Make the block named ``name`` over ``context``, with no ``timestamp``."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            return PCAPNG(num=2, sct=1, ctx=context, type=BlockType.get(name), block=block)

    def test_default_is_the_current_time(self) -> None:
        """The issue's case: no ``timestamp`` makes one, and it is now."""
        context = self._timed_context()
        for name in TIMESTAMPED:
            with self.subTest(block=name):
                before = time.time()
                made = self._make(name, context, packet_data=b'A' * 4)
                after = time.time()
                self.assertIsNow(made.info.timestamp_epoch, before, after)

    def test_default_survives_a_round_trip(self) -> None:
        """A defaulted timestamp parses back to the value the maker reported."""
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._timed_context()
        for name in TIMESTAMPED:
            with self.subTest(block=name):
                made = self._make(name, context, packet_data=b'A' * 4)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')  # the Packet Block is obsolete
                    parsed = PCAPNG(made.data, len(made.data), num=2, sct=1, ctx=context)
                    self.assertEqual(parsed.info.timestamp_epoch, made.info.timestamp_epoch)
                    self.assertRebuilds(made.data, context)

    def test_default_is_read_at_the_interface_resolution(self) -> None:
        """``if_tsresol`` of 9 scales the default to nanoseconds, not microseconds."""
        context = self._timed_context(resolution=NANOSECOND_RESOLUTION)
        for name in TIMESTAMPED:
            with self.subTest(block=name):
                before = time.time_ns()
                made = self._make(name, context, packet_data=b'A' * 4)
                after = time.time_ns()
                # The raw field counts nanoseconds, so it is of the order of
                # ``time.time_ns()``; read at microseconds it would be a
                # thousandth of that and fall below ``before``.
                raw = self._raw_timestamp(made)
                self.assertGreaterEqual(raw, before)
                self.assertLessEqual(raw, after)

    def _make_on_pinned_clocks(self, name: 'str', context: 'Any', **block: 'Any') -> 'Any':
        """Make the block named ``name`` with both clocks pinned.

        :func:`time.time_ns` reads :data:`PINNED_NANOSECOND` and
        :func:`time.time` reads :data:`PINNED_SECOND`, so the field a default
        reaches names the clock it was read from. Left to the real clocks the
        two are each about the current time, and the field cannot tell them
        apart.

        """
        with unittest.mock.patch('time.time_ns', return_value=PINNED_NANOSECOND), \
                unittest.mock.patch('time.time', return_value=PINNED_SECOND):
            return self._make(name, context, **block)

    def test_default_follows_the_interface_the_block_names(self) -> None:
        """A block reads its own ``interface_id``'s resolution, not interface 0's.

        The section carries two interfaces a thousandfold apart and every block
        names the second one, in both orders, with the clocks pinned: a lookup
        fixed at interface 0 therefore reads the wrong clock and scales by the
        wrong factor, whichever way round the section is written.

        """
        for first, second in ((None, NANOSECOND_RESOLUTION),
                              (NANOSECOND_RESOLUTION, None)):
            resolution = second or DEFAULT_RESOLUTION
            context = self._timed_context(resolution=first)
            self._add_interface(context, resolution=second)
            for name in TIMESTAMPED:
                with self.subTest(block=name, resolution=resolution):
                    made = self._make_on_pinned_clocks(name, context, interface_id=1,
                                                       packet_data=b'A' * 4)
                    self.assertEqual(made.info.interface_id, 1)
                    self.assertEqual(self._raw_timestamp(made), PINNED_RAW[resolution])

    def test_default_reads_the_clock_its_resolution_calls_for(self) -> None:
        """A sub-microsecond resolution reads :func:`time.time_ns`, a coarser one :func:`time.time`.

        ``None`` is an interface that declares no ``if_tsresol`` at all, which
        counts :data:`DEFAULT_RESOLUTION` units and so reads the coarse clock.

        """
        for declared in (NANOSECOND_RESOLUTION, None):
            resolution = declared or DEFAULT_RESOLUTION
            context = self._timed_context(resolution=declared)
            for name in TIMESTAMPED:
                with self.subTest(block=name, resolution=resolution):
                    made = self._make_on_pinned_clocks(name, context, packet_data=b'A' * 4)
                    self.assertEqual(self._raw_timestamp(made), PINNED_RAW[resolution])

    def test_default_is_shifted_by_the_interface_offset(self) -> None:
        """``if_tsoffset`` shifts the written field, not the epoch reported."""
        context = self._timed_context(offset=1_000)
        for name in TIMESTAMPED:
            with self.subTest(block=name):
                before = time.time()
                made = self._make(name, context, packet_data=b'A' * 4)
                after = time.time()
                self.assertIsNow(made.info.timestamp_epoch, before, after)
                raw = self._raw_timestamp(made)
                self.assertAlmostEqual(raw / 1_000_000 + 1_000, before, delta=1)

    def test_isb_start_and_end_times_default_too(self) -> None:
        """``isb_starttime``/``isb_endtime`` reach the same maker, so they default too."""
        from pcapkit.const.pcapng.option_type import OptionType

        context = self._timed_context()
        before = time.time()
        made = self._make('Interface_Statistics_Block', context,
                          options=[(OptionType.isb_starttime, {}),
                                   (OptionType.isb_endtime, {})])
        after = time.time()
        for option in (OptionType.isb_starttime, OptionType.isb_endtime):
            with self.subTest(option=option):
                self.assertIsNow(made.info.options[option].timestamp_epoch, before, after)

    def test_an_explicit_timestamp_is_unchanged(self) -> None:
        """The fix touches only the default: an explicit ``timestamp`` still writes 0."""
        context = self._timed_context()
        for name in TIMESTAMPED:
            with self.subTest(block=name):
                made = self._make(name, context, packet_data=b'A' * 4, timestamp=0)
                self.assertEqual(made.info.timestamp_epoch, 0)


if __name__ == '__main__':
    unittest.main()
