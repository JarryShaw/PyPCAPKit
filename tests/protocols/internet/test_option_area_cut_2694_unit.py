# -*- coding: utf-8 -*-
"""A capture cut inside an option area reads as a short read, quietly (#2694).

Under the #1325 guards, ``OptionField.unpack`` refused a capture cut that lands
before or inside an option area: an option the data ends inside "runs past the end
of the data", and one the data ends in front of "consumed no data", a
``FieldValueError`` that logged at CRITICAL, and again from ``beholder`` inside
IPv6. So an MH message cut inside its options raised on its own, as did an LRI or
UPA message cut inside its reserved octets, and a HOPOPT header cut to 2 or 3
octets logged inside IPv6.

Where the data ends inside the area, the list ends with the data, and an option
it ends inside stands if its fields fit the area, so ``Schema.unpack`` records the
cut as the short read #2682 extended to option areas. A HOPOPT or IPv6-Opts header
cut short reads as that short read too, rather than failing its check that its
options fill the area, and rebuilds with the ``Hdr Ext Len`` it declared. An option
whose maker would not write the octets captured back is refused, and so is an
option whose fields run past its area (#1325).

A header IPv6 hands every octet its Payload Length leaves, and which is longer
than that, runs past it: malformed, not cut by the capture, and kept as ``Raw``
as #2477 has it. IPv6 tells its option area so, and the area is refused.

The issue's second comment is malformed data rather than a cut: an MH Flow Summary
option of an odd length raised a ``FieldValueError`` from the list field reading its
16-bit identifiers, logged even inside IPv6. A list of fixed-width items that a
length leaves part of one is refused with a ``ProtocolError``, which a handled
refusal keeps quiet (#2588).

Every case builds its own octets and reads no capture. Classes are imported inside
each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import contextlib
import struct
import unittest
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class, time_limit
from tests.utilities._harness import capture

if TYPE_CHECKING:
    from typing import Any, Callable, Iterator, Optional

#: Test tier (#1958): a sweep that cuts every MH message type at every offset.
__tier__ = 'LATEST'

#: Header fields shared by every MH built here; Next Header is IPv6-NoNxt.
MH_BASE = {'next': 59, 'chksum': b'\x00\x00', 'payload': b''}

#: The octets of a Mobility Header IPv6 keeps as its own layer: its
#: ``__length_hint__``, under which it is kept as raw octets (#1170).
MH_HINT = 8

#: A Hop-by-Hop or Destination Options header of 16 octets: a Pad1, then a PadN of
#: four octets and one of five, so a cut lands in front of, and inside, each.
OPTIONS = bytes([59, 1]) + bytes([0]) + bytes([1, 4]) + bytes(4) + bytes([1, 5]) + bytes(5)

#: The octets of a HOPOPT or IPv6-Opts header IPv6 keeps as its own layer: its
#: ``__length_hint__``, under which it is kept as raw octets (#1170).
OPTIONS_HINT = 8

#: An options header carrying a Line Identification option (RFC 6788) of the line
#: ID ``line-1``, and a PadN.
LINE_ID = bytes.fromhex('1101' '8c07066c696e652d31' '0103000000')

#: A Binding Refresh Request carrying a Binding Refresh Advice and a PadN
#: (RFC 6275, sections 6.1.1 and 6.2.4).
BRR_BRA = bytes.fromhex('3b01000000000000' '02020007' '01020000')

#: A Binding Refresh Request carrying a Flow Identification option (RFC 6089,
#: section 4.2), whose one sub-option is a Flow Binding Action (RFC 7109), and a PadN.
FID = bytes.fromhex('3b02000000000000' '2d0a000100010000' '0402000b' '01020000')

#: The SchemaWarning a layer kept with its header cut short gives, which
#: ``Protocol._parse_next_layer`` documents and #2526 pins: the header's fields run
#: past the length it was handed. It is not a refusal.
CUT_HEADER_WARNING = 'packet length < 0'


def ipv6(code: int, body: bytes, length: 'Optional[int]' = None) -> bytes:
    """An IPv6 packet carrying ``body`` as next header ``code``, its Payload Length
    ``length``, or that of ``body`` if not given."""
    declared = len(body) if length is None else length
    return struct.pack('!IHBB', 6 << 28, declared, code, 64) + bytes(32) + body


def brr(option: bytes) -> bytes:
    """A Binding Refresh Request carrying ``option``, padded to a multiple of 8 octets."""
    body = bytes(2) + option
    pad = -(len(body) + 6) % 8
    if pad == 1:
        body += bytes(1)
    elif pad:
        body += bytes([1, pad - 2]) + bytes(pad - 2)
    return bytes([59, (len(body) + 6) // 8 - 1, 0, 0, 0, 0]) + body


@contextlib.contextmanager
def reported() -> 'Iterator[list[str]]':
    """What the block reports, on the ``pcapkit`` logger and on :mod:`warnings`."""
    from pcapkit.utilities.logging import logger

    messages = []  # type: list[str]
    with capture(logger) as logs, warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter('always')
        yield messages
    messages.extend(f'{level}: {text}' for level, text in logs.messages)
    messages.extend(f'warned: {item.message}' for item in caught)


def refusals(messages: 'list[str]') -> 'list[str]':
    """``messages`` but the warnings a header cut short gives."""
    return [text for text in messages if CUT_HEADER_WARNING not in text]


class OptionAreaCutTests(unittest.TestCase):
    """Pin a cut inside or in front of an option area as a quiet short read."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def messages(self) -> 'dict[str, bytes]':
        """Every registered MH message type, built with its defaults."""
        from pcapkit.protocols.internet.mh import MH

        return {getattr(code, 'name', str(code)): bytes(MH(type=code, data={}, **MH_BASE))
                for code in MH.__message__}

    def assertRebuildsQuietly(self, cls: 'Any', layer: 'Any', raw: bytes,  # pylint: disable=invalid-name
                              reparsed: bool = False) -> None:
        """``cls`` rebuilt from ``layer``'s info and its dict gives ``raw``, reporting nothing.

        A ``reparsed`` rebuild parses a header kept cut short again, as an IPv6
        packet does its extension headers, which then warns as its parse did.

        """
        for path, data in (('info', layer.info), ('dict', layer.info.to_dict())):
            with self.subTest(path=path):
                with reported() as messages:
                    rebuilt = cls.from_data(data)
                if reparsed:
                    messages = refusals(messages)
                self.assertEqual((rebuilt.data.hex(), messages), (raw.hex(), []))

    def parse(self, build: 'Callable[[], Any]') -> 'tuple[Any, list[str]]':
        """What ``build`` returns, and what it reported."""
        with time_limit(), reported() as messages:
            layer = build()
        return layer, messages

    def test_every_message_cut_at_every_offset_reads_short(self) -> None:
        from pcapkit.protocols.internet.mh import MH

        for name, whole in self.messages().items():
            for cut in range(1, len(whole)):
                raw = whole[:cut]
                with self.subTest(message=name, cut=cut):
                    mh, messages = self.parse(lambda: MH(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((mh.data, refusals(messages)), (raw, []))
                    self.assertIsNotNone(mh.info.get('__short_read__'))
                    self.assertRebuildsQuietly(MH, mh, raw)

    def test_every_message_cut_inside_ipv6_rebuilds_quietly(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        for name, whole in self.messages().items():
            for cut in range(1, len(whole)):
                raw = ipv6(135, whole)[:40 + cut]
                with self.subTest(message=name, cut=cut):
                    ip6, messages = self.parse(lambda: IPv6(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((ip6.data, refusals(messages)), (raw, []))
                    if cut < MH_HINT:
                        self.assertIs(type(ip6.payload), Raw)
                    else:
                        mh = ip6.extension_headers.get(ExtensionHeader.Mobility_Header)
                        self.assertIsNotNone(mh)
                        self.assertIsNotNone(mh.info.get('__short_read__'))
                    self.assertRebuildsQuietly(IPv6, ip6, raw, reparsed=True)

    def test_reserved_octets_cut_reads_short(self) -> None:
        # the LRI's two reserved octets follow its sequence number, and the UPA's
        # three its sequence number and status (RFC 6705, section 10.1; RFC 7077,
        # section 4.2), behind the six octets of the Mobility Header
        from pcapkit.const.mh.packet import Packet
        from pcapkit.protocols.internet.mh import MH

        for code, reserved in ((Packet.Localized_Routing_Initiation, range(8, 10)),
                               (Packet.Update_Notification_Acknowledgement, range(9, 12))):
            whole = bytes(MH(type=code, data={}, **MH_BASE))
            for cut in reserved:
                raw = whole[:cut]
                with self.subTest(message=code.name, cut=cut):
                    mh, messages = self.parse(lambda: MH(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(refusals(messages), [])
                    self.assertEqual(mh.__header__.data.__dict__['__short_read__'],
                                     ('reserved', cut - reserved.start))
                    self.assertEqual(mh.info.msg_reserved, raw[reserved.start:])
                    self.assertRebuildsQuietly(MH, mh, raw)

    def test_options_header_schema_cut_reads_short(self) -> None:
        from pcapkit.protocols.schema.internet.hopopt import HOPOPT
        from pcapkit.protocols.schema.internet.ipv6_opts import IPv6_Opts

        for schema in (HOPOPT, IPv6_Opts):
            for cut in range(1, len(OPTIONS)):
                raw = OPTIONS[:cut]
                with self.subTest(schema=schema.__name__, cut=cut):
                    with time_limit(), warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        header = schema.unpack(raw, len(raw))
                    self.assertEqual(header.__dict__['__short_read__'],
                                     ('len', 0) if cut == 1 else ('options', cut - 2))
                    self.assertEqual((bytes(header), header.pack()), (raw, raw))

    def test_options_header_cut_at_every_offset_reads_short(self) -> None:
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts

        for cls in (HOPOPT, IPv6_Opts):
            for cut in range(1, len(OPTIONS)):
                raw = OPTIONS[:cut]
                with self.subTest(header=cls.__name__, cut=cut):
                    header, messages = self.parse(lambda: cls(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((header.data, refusals(messages)), (raw, []))
                    self.assertIsNotNone(header.info.get('__short_read__'))
                    self.assertRebuildsQuietly(cls, header, raw)

    def test_options_header_cut_inside_ipv6_reads_short(self) -> None:
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        for code, key in ((0, ExtensionHeader.HOPOPT), (60, ExtensionHeader.IPv6_Opts)):
            for cut in range(1, len(OPTIONS)):
                raw = ipv6(code, OPTIONS)[:40 + cut]
                with self.subTest(next_header=code, cut=cut):
                    ip6, messages = self.parse(lambda: IPv6(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((ip6.data, refusals(messages)), (raw, []))
                    if cut < OPTIONS_HINT:
                        self.assertIs(type(ip6.payload), Raw)
                    else:
                        header = ip6.extension_headers.get(key)
                        self.assertIsNotNone(header)
                        self.assertIsNotNone(header.info.get('__short_read__'))
                    self.assertRebuildsQuietly(IPv6, ip6, raw, reparsed=True)

    def test_options_header_make_takes_the_length_a_cut_declared(self) -> None:
        # a whole header is made with the Hdr Ext Len its options fill, and one the
        # capture cut short with the one it declared
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.utilities.exceptions import ProtocolError

        # pylint: disable=protected-access
        for cls in (HOPOPT, IPv6_Opts):
            with self.subTest(header=cls.__name__):
                self.assertIsNone(cls._make_data(cls(OPTIONS).info)['len'])
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    self.assertEqual(cls._make_data(cls(OPTIONS[:5]).info)['len'], 1)
                self.assertEqual(bytes(cls(next=59, options=[], len=0)), bytes([59, 0, 1, 4]) + bytes(4))
                with reported():
                    for value in (-1, 256, True):
                        with self.assertRaises(ProtocolError):
                            cls(next=59, options=[], len=value)

    def test_options_header_cut_option_that_does_not_rebuild_is_refused_quietly(self) -> None:
        # a Router Alert cut after its type reads a length of zero, which its parser
        # refuses; a Line Identification cut before its line ID length is made with
        # a length that leaves the line ID out
        from pcapkit.protocols.internet.hopopt import HOPOPT
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        for cls, code in ((HOPOPT, 0), (IPv6_Opts, 60)):
            for raw, error in (
                (bytes([59, 1, 5]), r'option cut short: .*\[OptNo 5\] invalid format'),
                (LINE_ID[:4], 'option cut short does not rebuild as captured'),
            ):
                with self.subTest(header=cls.__name__, raw=raw.hex()):
                    with reported(), self.assertRaisesRegex(ProtocolError, error):
                        cls(raw)

                    packet = ipv6(code, raw)
                    ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                    self.assertEqual(messages, [])
                    self.assertIs(type(ip6.payload), Raw)
                    self.assertRebuildsQuietly(IPv6, ip6, packet)

    def test_option_past_its_area_is_still_refused(self) -> None:
        # #1325: a PadN declaring three octets past a whole header, and one
        # declaring twenty-two in an area of sixteen the data also ends inside
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        for raw in (bytes.fromhex('3b010000000000000104000000000103'),
                    bytes.fromhex('3b020000000000000114000000000000')):
            with self.subTest(raw=raw.hex()):
                with reported(), self.assertRaisesRegex(ProtocolError, 'runs past the end of the data'):
                    MH(raw)

    def test_cut_option_that_does_not_rebuild_is_refused_quietly(self) -> None:
        # a Binding Refresh Advice cut after its type reads a length of zero, which
        # its parser refuses; an IPv6 Address/Prefix cut before its code reads a
        # code of zero, which its closed enumeration refuses; a Flow Identification
        # cut where its sub-options start is made with a length that leaves them out
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        for raw, error in (
            (BRR_BRA[:9], r'option cut short: MH: \[Opt 2\] invalid format'),
            (bytes.fromhex('3b03000000000000' '2212'),
             'option cut short: 0 is not a valid IPv6AddressPrefixCode'),
            (FID[:16], 'option cut short does not rebuild as captured'),
        ):
            with self.subTest(raw=raw.hex()):
                with reported(), self.assertRaisesRegex(ProtocolError, error):
                    MH(raw)

                packet = ipv6(135, raw)
                ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                self.assertEqual(messages, [])
                self.assertIs(type(ip6.payload), Raw)
                self.assertRebuildsQuietly(IPv6, ip6, packet)

    def test_cut_option_that_rebuilds_stands(self) -> None:
        # the Binding Refresh Advice cut inside its interval, and the PadN after it
        # cut inside its padding
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH

        for cut in (10, 11, 13, 14, 15):
            raw = BRR_BRA[:cut]
            with self.subTest(cut=cut):
                mh, messages = self.parse(lambda: MH(raw))  # pylint: disable=cell-var-from-loop
                self.assertEqual(refusals(messages), [])
                self.assertEqual(list(mh.info.options),
                                 [Option.Binding_Refresh_Advice] + [Option.PadN] * (cut > 12))
                self.assertEqual(mh.__header__.data.__dict__['__short_read__'], ('options', cut - 8))
                self.assertRebuildsQuietly(MH, mh, raw)


    def test_list_short_of_an_item_is_refused_quietly(self) -> None:
        # a Flow Summary option, or a Flow Identification option's BID Reference
        # sub-option, of an odd length (RFC 6089, sections 4.2.2 and 4.2.1), and a
        # Multi-Prefix CGA extension a length leaves part of a prefix (RFC 5535);
        # a Load Information option of an odd length (RFC 6463, section 4.3) was
        # refused quietly, and is the control
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        cases = [(brr(bytes([44, n]) + bytes(range(1, n + 1))), 'OptNo 44') for n in (1, 3, 5)]
        cases += [(brr(bytes([45, 11]) + bytes([0, 1, 0, 1, 0, 0]) + bytes([2, 3, 0, 1, 2])), 'FID SubOpt 2')]
        cases += [(bytes.fromhex('3b060000000000000c2d086fca5e10b200c99c8ce00164277c0820010db8'
                                 '00000000003002aabb0012000b0000000020010db80000000100'), 'CGA Ext 18')]
        cases += [(brr(bytes([48, n]) + bytes(range(1, n + 1))), None) for n in (17, 19)]
        for raw, where in cases:
            with self.subTest(raw=raw.hex()):
                with reported(), self.assertRaises(ProtocolError) as refusal:
                    MH(raw)
                if where is not None:
                    self.assertRegex(str(refusal.exception), rf'\[{where}\] invalid length: \d+, '
                                                             r'not a whole number of \d+-octet items')

                packet = ipv6(135, raw)
                ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                self.assertEqual(refusals(messages), [])
                self.assertIs(type(ip6.payload), Raw)
                self.assertRebuildsQuietly(IPv6, ip6, packet, reparsed=True)

    def test_list_of_whole_items_reads(self) -> None:
        # the same option and extension, of a length the items fill
        from pcapkit.protocols.internet.mh import MH

        for raw in (brr(bytes([44, 4, 0, 1, 0, 2])),
                    bytes.fromhex('3b060000000000000c2d086fca5e10b200c99c8ce00164277c0820010db8'
                                  '00000000003002aabb0012000c0000000020010db80000000100')):
            with self.subTest(raw=raw.hex()):
                mh, messages = self.parse(lambda: MH(raw))  # pylint: disable=cell-var-from-loop
                self.assertEqual((mh.data, messages), (raw, []))
                self.assertRebuildsQuietly(MH, mh, raw)

    def test_header_past_the_payload_length_is_raw_quietly(self) -> None:
        # each header is handed every octet its Payload Length declares, short of
        # the header's own length: on the Payload Length's side of the line, where
        # a cut is handed fewer octets than it declares
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        headers = ((0, OPTIONS), (60, OPTIONS), (135, BRR_BRA),
                   (135, bytes(self.messages()['Localized_Routing_Initiation'])))
        for code, whole in headers:
            for length in range(1, len(whole)):
                raw = ipv6(code, whole[:length], length)
                with self.subTest(next_header=code, header=whole.hex(), payload_length=length):
                    ip6, messages = self.parse(lambda: IPv6(raw))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((ip6.data, messages), (raw, []))
                    self.assertEqual(list(ip6.extension_headers.items(multi=True)), [])
                    self.assertIs(type(ip6.payload), Raw)
                    self.assertRebuildsQuietly(IPv6, ip6, raw)

    def test_payload_length_tells_a_cut_from_an_overrun(self) -> None:
        # the review's case: a 16-octet header under a Payload Length of 8 with
        # those 8 octets, then the same header cut to 10 octets of the 16 declared
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.ipv6 import IPv6
        from pcapkit.protocols.misc.raw import Raw

        for code, key, whole in ((0, ExtensionHeader.HOPOPT, OPTIONS),
                                 (60, ExtensionHeader.IPv6_Opts, OPTIONS),
                                 (135, ExtensionHeader.Mobility_Header, BRR_BRA)):
            with self.subTest(next_header=code):
                ip6, _ = self.parse(lambda: IPv6(ipv6(code, whole[:8], 8)))  # pylint: disable=cell-var-from-loop
                self.assertIs(type(ip6.payload), Raw)
                self.assertIsNone(ip6.extension_headers.get(key))

                ip6, _ = self.parse(lambda: IPv6(ipv6(code, whole[:10], len(whole))))  # pylint: disable=cell-var-from-loop
                header = ip6.extension_headers.get(key)
                self.assertIsNotNone(header)
                self.assertIsNotNone(header.info.get('__short_read__'))

    def test_option_area_told_its_data_is_bounded_runs_past_it(self) -> None:
        # the field on its own: ``__capture_cut__`` false where the data ends
        # inside the area, at an option boundary and inside an option
        from pcapkit.protocols.schema.internet.hopopt import HOPOPT
        from pcapkit.utilities.exceptions import ProtocolError

        field = HOPOPT.__fields__['options']
        for raw, error in ((OPTIONS[2:3], 'option area that runs past the end of the data'),
                           (OPTIONS[2:5], 'option that runs past the end of the data')):
            with self.subTest(raw=raw.hex()):
                packet = {'len': 1, '__capture_cut__': False}
                with reported(), self.assertRaisesRegex(ProtocolError, error):
                    field(packet).unpack(raw, packet)
                packet = {'len': 1}
                self.assertEqual(sum(map(len, field(packet).unpack(raw, packet))), len(raw))

if __name__ == '__main__':
    unittest.main()
