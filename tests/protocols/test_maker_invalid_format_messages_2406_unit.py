# -*- coding: utf-8 -*-
"""GitHub issue #2406: the makers outside #2296's checklist name their argument.

The ``_make_*`` guards below carry the house form established by #2232 and
#2257, ``<prefix>: <lowercase description>: must be X, not {value!r}``, which
names the keyword at fault and the value passed -- not the *reader's*
``<alias>: [... N] invalid format``, which describes wire data a maker has not
parsed. Each sits on the maker side, outside #2296's checklist:

* :meth:`HOPOPT._make_opt_pad
  <pcapkit.protocols.internet.hopopt.HOPOPT._make_opt_pad>` and
  :meth:`IPv6_Opts._make_opt_pad
  <pcapkit.protocols.internet.ipv6_opts.IPv6_Opts._make_opt_pad>`, the twins of
  the ``Pad1`` length warning on :class:`~pcapkit.protocols.internet.mh.MH` (#2296);
* :meth:`HTTP.make <pcapkit.protocols.application.httpv2.HTTP.make>` and
  :meth:`PCAPNG.make <pcapkit.protocols.misc.pcapng.PCAPNG.make>`, the
  dispatchers whose unsupported-``frame``/``block`` guard is the same shape as
  ``MH.make``'s.

Readers are deliberately exempt, as in #2296: ``invalid format`` is the right
thing for a reader to say. :class:`ReadersKeepInvalidFormat` below pins that
division on the one pair where the reader and the maker guard the very same
thing -- ``_read_opt_pad`` and ``_make_opt_pad`` guard a ``Pad1`` carrying a
non-zero length, though only the reader raises; the maker warns and makes a
``PadN`` instead.

Every message is pinned whole, and every maker's valid input is exercised in the
same class, so a guard that starts refusing good input regresses here too.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

from __future__ import annotations

import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any


class MakerMessageTestCase(unittest.TestCase):
    """Re-import :mod:`pcapkit` once per class, as the suite's convention asks."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def protocol(self, cls: 'Any') -> 'Any':
        """An uninitialised protocol instance, for calling a maker directly.

        The makers under test read nothing off ``self`` but ``alias``, so there
        is no packet to construct first -- and constructing one would route the
        bad argument through a schema that raises its own error instead.

        """
        return object.__new__(cls)


class IPv6ExtensionPadOptionWarnings(MakerMessageTestCase):
    """``_make_opt_pad`` warns about ``length``, not about a format.

    HOPOPT and IPv6-Opts carry byte-identical copies of the option machinery,
    down to the ``Pad1`` guard, so both are driven from one table: the only
    thing that differs in the message is the alias each protocol reports.

    """

    def protocols(self) -> 'list[tuple[Any, str]]':
        """Each padding-option maker, paired with the alias it names itself by."""
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        return [(HOPOPT, 'HOPOPT'), (IPv6_Opts, 'IPv6-Opts')]

    def test_pad1_with_a_length_warns_by_name(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.utilities.warnings import ProtocolWarning

        code = Option.Pad1
        for cls, alias in self.protocols():
            protocol = self.protocol(cls)
            for length in (1, 3):
                with self.subTest(protocol=alias, length=length):
                    with warnings.catch_warnings(record=True) as caught:
                        warnings.simplefilter('always')
                        schema = protocol._make_opt_pad(code, length=length)
                    messages = [str(w.message) for w in caught
                                if issubclass(w.category, ProtocolWarning)]
                    self.assertEqual(len(messages), 1, messages)
                    self.assertEqual(
                        messages[0],
                        f'{alias}: [OptNo {code}] invalid length: '
                        f'must be 0 for a Pad1 option, not {length!r}; making a PadN')
                    self.assertEqual(schema.type, Option.PadN)

    def test_pad1_with_no_length_does_not_warn(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.utilities.warnings import ProtocolWarning

        for cls, alias in self.protocols():
            protocol = self.protocol(cls)
            with self.subTest(protocol=alias):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    schema = protocol._make_opt_pad(Option.Pad1, length=0)
                self.assertEqual([str(w.message) for w in caught
                                  if issubclass(w.category, ProtocolWarning)], [])
                self.assertEqual(schema.type, Option.Pad1)

    def test_padn_with_a_length_still_builds(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.utilities.warnings import ProtocolWarning

        for cls, alias in self.protocols():
            protocol = self.protocol(cls)
            with self.subTest(protocol=alias):
                with warnings.catch_warnings(record=True) as caught:
                    warnings.simplefilter('always')
                    schema = protocol._make_opt_pad(Option.PadN, length=2, pad=b'\x00\x00')
                self.assertEqual([str(w.message) for w in caught
                                  if issubclass(w.category, ProtocolWarning)], [])
                self.assertEqual(schema.type, Option.PadN)
                self.assertEqual(schema.len, 2)
                self.assertEqual(schema.pad, b'\x00\x00')


class HTTPFrameMessage(MakerMessageTestCase):
    """``HTTP.make`` names ``frame`` and the forms it reads."""

    def test_unreadable_frame_names_the_argument(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP
        from pcapkit.utilities.exceptions import ProtocolError

        http = self.protocol(HTTP)
        code = Frame.DATA
        for frame in (5, 1.5, 'frame', []):
            with self.subTest(frame=frame):
                with self.assertRaises(ProtocolError) as context:
                    http.make(type=code, frame=frame)
                self.assertEqual(
                    str(context.exception),
                    f'HTTP/2: [Type {code}] invalid frame: must be bytes, a dict, '
                    f'an HTTP data model or a Schema, not {frame!r}')

    def test_raw_frame_still_builds(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP

        http = self.protocol(HTTP)
        schema = http.make(type=Frame.DATA, frame=b'\x01\x02')
        self.assertEqual(schema.frame, b'\x01\x02')
        self.assertEqual(schema.length, 2)

    def test_an_omitted_frame_is_not_rejected(self) -> None:
        from pcapkit.const.http.frame import Frame
        from pcapkit.protocols.application.httpv2 import HTTP

        # ``frame=None`` dispatches to the frame type's own constructor (#2274)
        # rather than reaching the guard, so the guard does not cover it.
        http = self.protocol(HTTP)
        self.assertEqual(http.make(type=Frame.DATA, frame=None).type, Frame.DATA)


class PCAPNGBlockMessage(MakerMessageTestCase):
    """``PCAPNG.make`` names ``block`` and the forms it reads."""

    def protocol(self, cls: 'Any') -> 'Any':
        """As the base helper, but with the section context the dispatcher reads.

        ``PCAPNG.make`` settles the byte order before handing the block over,
        and reads :attr:`PCAPNG._ctx` to do it. :data:`None` is what an
        out-of-capture construction carries, and sends it to the default
        ``__packet__`` byte order.

        """
        protocol = super().protocol(cls)
        protocol._ctx = None
        return protocol

    def test_unreadable_block_names_the_argument(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG
        from pcapkit.utilities.exceptions import ProtocolError

        pcapng = self.protocol(PCAPNG)
        code = BlockType.Enhanced_Packet_Block
        for block in (5, None, 1.5, 'block'):
            with self.subTest(block=block):
                with self.assertRaises(ProtocolError) as context:
                    pcapng.make(type=code, block=block)
                self.assertEqual(
                    str(context.exception),
                    f'PCAP-NG: [Type {code}] invalid block: must be bytes, a dict, '
                    f'a PCAPNG data model or a Schema, not {block!r}')

    def test_raw_block_still_builds(self) -> None:
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        pcapng = self.protocol(PCAPNG)
        schema = pcapng.make(type=BlockType.Enhanced_Packet_Block, block=b'\x00\x01')
        self.assertEqual(schema.type, BlockType.Enhanced_Packet_Block)
        self.assertEqual(schema.block, b'\x00\x01')


class ReadersKeepInvalidFormat(MakerMessageTestCase):
    """The parse side says ``invalid format``, as #2296 asks.

    ``_read_opt_pad`` and ``_make_opt_pad`` guard the same thing -- a ``Pad1``
    option carrying a non-zero length -- though only the reader raises; the
    maker warns and makes a ``PadN`` instead. The pair is where a sweep over
    the makers is most likely to catch a reader by accident.

    """

    def readers(self) -> 'list[tuple[Any, Any, str]]':
        """Each padding-option reader, its schema class and its alias."""
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.schema.internet.hopopt import PadOption as Schema_HOPOPTPad
        from pcapkit.protocols.schema.internet.ipv6_opts import PadOption as Schema_IPv6OptsPad

        return [(HOPOPT, Schema_HOPOPTPad, 'HOPOPT'),
                (IPv6_Opts, Schema_IPv6OptsPad, 'IPv6-Opts')]

    def test_the_reader_still_reports_an_invalid_format(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.utilities.exceptions import ProtocolError

        code = Option.Pad1
        for cls, schema_cls, alias in self.readers():
            protocol = self.protocol(cls)
            with self.subTest(protocol=alias):
                schema = schema_cls(type=code, len=3, pad=b'')
                with self.assertRaises(ProtocolError) as context:
                    protocol._read_opt_pad(schema, options=OrderedMultiDict())
                self.assertEqual(str(context.exception),
                                 f'{alias}: [OptNo {code}] invalid format')


if __name__ == '__main__':
    unittest.main()
