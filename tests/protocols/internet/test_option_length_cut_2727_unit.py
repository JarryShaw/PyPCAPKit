# -*- coding: utf-8 -*-
"""A cut after an IPv6 option's type octet reads as a short read, quietly (#2727).

In HOPOPT and IPv6-Opts, a capture cut that leaves only the type octet of a
CALIPSO, SMF_DPD or MPL option logged ``FieldValueError: ... invalid <X> option
length: 0``, at CRITICAL and again from ``beholder`` inside IPv6. The callbacks
sizing those options from ``Opt Data Len`` refused the zero the cut left in place
of a length, before the short read #2694 extended to option areas could record
the cut. A cut one octet later was clean.

``Schema.unpack`` gives the fields after the one the data ends inside the short
read, as ``__short_read__`` in their packet, a forward match included. A callback
whose ``Opt Data Len`` the data ends before leaves the option to the short read,
and the option is then kept or refused by #2694's rule: kept if its parser takes
the zeros and its maker writes the octets captured back, else refused quietly.
CALIPSO and SMF_DPD are kept; MPL's parser refuses a length below two, as Router
Alert's does. A length on the wire too short is refused with a ``ProtocolError``,
which a handled refusal keeps quiet (#2588), where a ``FieldValueError`` logged.

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

#: Test tier (#1958): a sweep that cuts every IPv6 option at every offset.
__tier__ = 'LATEST'

#: The octets of a HOPOPT or IPv6-Opts header IPv6 keeps as its own layer: its
#: ``__length_hint__``, under which it is kept as raw octets (#1170).
OPTIONS_HINT = 8

#: The SchemaWarning a layer kept with its header cut short gives, which
#: ``Protocol._parse_next_layer`` documents and #2526 pins: the header's fields run
#: past the length it was handed. It is not a refusal.
CUT_HEADER_WARNING = 'packet length < 0'


def ipv6(code: int, body: bytes, length: 'Optional[int]' = None) -> bytes:
    """An IPv6 packet carrying ``body`` as next header ``code``, its Payload Length
    ``length``, or that of ``body`` if not given."""
    declared = len(body) if length is None else length
    return struct.pack('!IHBB', 6 << 28, declared, code, 64) + bytes(32) + body


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


def variants() -> 'list[tuple[Any, dict[str, Any]]]':
    """The options the issue names, with their defaults and with the fields their
    lengths count filled in."""
    import ipaddress

    from pcapkit.const.ipv6.option import Option
    from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode
    from pcapkit.const.ipv6.tagger_id import TaggerID

    return [
        (Option.CALIPSO, {}),
        (Option.CALIPSO, {'domain': 0x12345678, 'level': 5, 'checksum': b'\xab\xcd',
                          'bitmap': bytes([1, 2, 3, 4]), 'pad': b'\x01\x02'}),
        (Option.SMF_DPD, {}),
        (Option.SMF_DPD, {'tid_type': TaggerID.IPv4, 'tid': ipaddress.ip_address('192.0.2.1'),
                          'id': b'\x01\x02'}),
        (Option.SMF_DPD, {'tid_type': TaggerID.IPv6, 'tid': ipaddress.ip_address('2001:db8::1'),
                          'id': b'\x01'}),
        (Option.SMF_DPD, {'tid_type': TaggerID.DEFAULT, 'tid': b'\xaa\xbb', 'id': b'\x01'}),
        (Option.SMF_DPD, {'mode': SMFDPDMode.H_DPD, 'hav': b'\x81\x02\x03'}),
        (Option.MPL_Option, {}),
        (Option.MPL_Option, {'seed_type': 1, 'seed': 0x1234, 'seq': 7}),
        (Option.MPL_Option, {'seed_type': 2, 'seed': 0x0102030405060708}),
        (Option.MPL_Option, {'seed_type': 3, 'seed': 1 << 100}),
    ]


class OptionLengthCutTests(unittest.TestCase):
    """Pin a cut before an option's ``Opt Data Len`` as a quiet short read."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def headers(self) -> 'list[tuple[Any, int, Any]]':
        """HOPOPT and IPv6-Opts, with the next header code IPv6 gives each and the
        key IPv6 keeps each under."""
        from pcapkit.const.ipv6.extension_header import ExtensionHeader
        from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
        from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts

        return [(HOPOPT, 0, ExtensionHeader.HOPOPT), (IPv6_Opts, 60, ExtensionHeader.IPv6_Opts)]

    def build(self, cls: 'Any', code: 'Any', kwargs: 'dict[str, Any]', lead: bool) -> 'tuple[bytes, int]':
        """A whole ``cls`` header carrying option ``code``, after a PadN of six octets
        if ``lead``, and the offset the option starts at."""
        from pcapkit.const.ipv6.option import Option

        options = [(Option.PadN, {'length': 4})] * lead + [(code, kwargs)]
        whole = bytes(cls(next=59, options=options, payload=b''))
        start = 2
        for key, option in cls(whole).info.options.items(multi=True):
            if key == code:
                break
            start += option.length
        return whole, start

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

    def test_every_option_at_every_cut_reads_short_or_is_refused_quietly(self) -> None:
        # every registered option, first in its header and after a PadN, cut at
        # every offset: on its own, a short read that rebuilds or a ProtocolError;
        # inside IPv6, nothing reported, and the packet rebuilds
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.utilities.exceptions import ProtocolError

        overrides = {Option.ILNP_Nonce: {'nonce': 0xFFFFFF},
                     Option.Line_Identification_Option: {'id': b'line-1'}}
        for cls, next_header, _ in self.headers():
            cases = [(code, overrides.get(code, {})) for code in cls.__option__] + variants()
            for code, kwargs in cases:
                for lead in (False, True):
                    whole, _ = self.build(cls, code, kwargs, lead)
                    for cut in range(1, len(whole)):
                        raw = whole[:cut]
                        with self.subTest(header=cls.__name__, option=whole.hex(), cut=cut):
                            try:
                                header, messages = self.parse(lambda: cls(raw))  # pylint: disable=cell-var-from-loop
                            except ProtocolError:
                                pass
                            else:
                                self.assertEqual((header.data, refusals(messages)), (raw, []))
                                self.assertIsNotNone(header.info.get('__short_read__'))
                                self.assertRebuildsQuietly(cls, header, raw)

                            packet = ipv6(next_header, raw, len(whole))
                            ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                            self.assertEqual((ip6.data, refusals(messages)), (packet, []))
                            self.assertRebuildsQuietly(IPv6, ip6, packet, reparsed=True)

    def test_a_cut_after_the_type_reads_short(self) -> None:
        # a CALIPSO or SMF_DPD option cut after its type is a short read, as one cut
        # an octet later is, on its own and inside IPv6
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        for cls, next_header, key in self.headers():
            for code, kwargs in variants():
                if code == Option.MPL_Option:
                    continue
                for lead in (False, True):
                    whole, start = self.build(cls, code, kwargs, lead)
                    self.assertEqual(whole[start], code)
                    for cut in (start + 1, start + 2):
                        raw = whole[:cut]
                        with self.subTest(header=cls.__name__, option=whole.hex(), cut=cut):
                            header, messages = self.parse(lambda: cls(raw))  # pylint: disable=cell-var-from-loop
                            # NOTE: An SMF_DPD option the data ends in before its
                            # ``Opt Data Len`` sizes its identifier schema by the zero
                            # read there, at two octets, which its fields run past.
                            if code != Option.SMF_DPD or cut > start + 1:
                                self.assertEqual(messages, [])
                            self.assertEqual((header.data, refusals(messages)), (raw, []))
                            self.assertEqual(header.info.get('__short_read__'), ('options', cut - 2))
                            self.assertEqual(list(header.info.options)[-1], code)
                            self.assertRebuildsQuietly(cls, header, raw)

                            packet = ipv6(next_header, raw, len(whole))
                            ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                            self.assertEqual((ip6.data, refusals(messages)), (packet, []))
                            if cut >= OPTIONS_HINT:
                                kept = ip6.extension_headers.get(key)
                                self.assertIsNotNone(kept)
                                self.assertEqual(kept.info.get('__short_read__'), ('options', cut - 2))
                            self.assertRebuildsQuietly(IPv6, ip6, packet, reparsed=True)

    def test_an_mpl_option_cut_after_the_type_is_refused_quietly(self) -> None:
        # its parser refuses the zero length the cut leaves, as Router Alert's does
        # (#2694), so the header is refused, and kept as Raw inside IPv6, quietly
        from pcapkit.const.ipv6.option import Option
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        error = r'\[OptNo 109\] option cut short: .*\[OptNo 109\] invalid format'
        for cls, next_header, _ in self.headers():
            for code, kwargs in variants():
                if code != Option.MPL_Option:
                    continue
                for lead in (False, True):
                    whole, start = self.build(cls, code, kwargs, lead)
                    self.assertEqual(whole[start], code)
                    raw = whole[:start + 1]
                    with self.subTest(header=cls.__name__, option=whole.hex()):
                        with reported(), self.assertRaisesRegex(ProtocolError, error):
                            cls(raw)

                        packet = ipv6(next_header, raw, len(whole))
                        ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                        self.assertEqual((ip6.data, messages), (packet, []))
                        self.assertIs(type(ip6.payload), Raw)
                        self.assertRebuildsQuietly(IPv6, ip6, packet)

    def test_a_length_on_the_wire_too_short_is_refused_quietly(self) -> None:
        # whole headers whose option declares an ``Opt Data Len`` too short for its
        # fields: refused with a ProtocolError, and kept as Raw inside IPv6 quietly
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        cases = (
            # CALIPSO of Opt Data Len 0, and of 8 with a compartment word declared
            ('3b0007000000000000000000000000', 'invalid CALIPSO option length: 0'),
            ('3b01070800000000010000000000000000', 'invalid CALIPSO option length: 8'),
            # MPL of Opt Data Len 0, and of 3 with a 16-bit Seed-ID
            ('3b006d0000000000', 'invalid MPL option length: 0'),
            ('3b016d03400000000000000000000000', 'invalid MPL option length: 3'),
            # SMF_DPD of Opt Data Len 0 before an octet with the mode bit clear and
            # one with it set, and in the last two octets of the header (#1195)
            ('3b00080000000000', 'invalid SMF DPD option length: 0'),
            ('3b00080080000000', 'invalid SMF DPD option length: 0'),
            ('3b00010200000800', 'invalid SMF DPD option length: 0'),
            # SMF I-DPD of Opt Data Len 3 with an IPv4 TaggerID
            ('3b010803230000000000000000000000', 'invalid SMF I-DPD option length: 3'),
        )
        for cls, next_header, _ in self.headers():
            for whole, error in cases:
                raw = bytes.fromhex(whole)
                with self.subTest(header=cls.__name__, raw=whole):
                    with reported(), self.assertRaisesRegex(ProtocolError, error):
                        cls(raw)

                    packet = ipv6(next_header, raw)
                    ip6, messages = self.parse(lambda: IPv6(packet))  # pylint: disable=cell-var-from-loop
                    self.assertEqual((ip6.data, messages), (packet, []))
                    self.assertIs(type(ip6.payload), Raw)
                    self.assertRebuildsQuietly(IPv6, ip6, packet)

    def test_the_helpers_leave_a_cut_length_to_the_short_read(self) -> None:
        # a packet whose short read names ``len`` was cut before it; one naming a
        # later field, or none, holds a length read off the wire
        from pcapkit.corekit.fields.misc import SchemaField
        from pcapkit.protocols.internet.hopopt import schema as hopopt
        from pcapkit.protocols.internet.ipv6_ext import schema as ipv6_option
        from pcapkit.utilities.exceptions import ProtocolError

        helpers = (
            (ipv6_option.calipso_pad_len, {'len': 0, 'cmpt_len': 0}, 'domain'),
            (ipv6_option.mpl_opt_pad_len, {'len': 0, 'flags': {'type': 0}}, 'flags'),
            (ipv6_option.smf_i_dpd_id_len, {'len': 0, 'info': {'type': 0, 'len': 0}}, 'info'),
        )
        for helper, packet, later in helpers:
            with self.subTest(helper=helper.__name__):
                self.assertEqual(helper({**packet, '__short_read__': ('len', 0)}, prefix='X'), 0)
                for record in ((later, 0), None):
                    with self.assertRaisesRegex(ProtocolError, r'^X: invalid .* option length: 0$'):
                        helper({**packet, '__short_read__': record}, prefix='X')

        # the forward match of an SMF_DPD option, ended before its second octet, and
        # after it
        select = ipv6_option.smf_dpd_data_selector
        field = select({'test': {'len': 0, 'mode': 0}, '__short_read__': ('test', 1)},
                       prefix='X', base=hopopt.SMFDPDOption)
        self.assertIsInstance(field, SchemaField)
        self.assertEqual((field.length, field.schema), (2, hopopt.SMFIdentificationBasedDPDOption))
        for record in (('test', 2), None):
            with self.assertRaisesRegex(ProtocolError, '^X: invalid SMF DPD option length: 0$'):
                select({'test': {'len': 0, 'mode': 0}, '__short_read__': record},
                       prefix='X', base=hopopt.SMFDPDOption)


class SchemaShortReadContextTests(unittest.TestCase):
    """Pin the short read ``Schema.unpack`` gives the fields after it."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_fields_after_the_end_of_the_data_are_told(self) -> None:
        from pcapkit.corekit.fields.misc import ForwardMatchField, SchemaField
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema import Schema, schema_final

        seen = []  # type: list[tuple[str, Any]]

        def probe(name: str) -> 'Callable[[dict[str, Any]], int]':
            def length(pkt: 'dict[str, Any]') -> int:
                seen.append((name, pkt.get('__short_read__')))
                return 1
            return length

        @schema_final
        class Inner(Schema):
            a: int = UInt8Field()
            b: bytes = BytesField(length=probe('inner'))

        @schema_final
        class Outer(Schema):
            peek: bytes = ForwardMatchField(BytesField(length=3))
            x: bytes = BytesField(length=probe('x'))
            inner: Inner = SchemaField(length=2, schema=Inner)
            y: bytes = BytesField(length=probe('y'))
            z: bytes = BytesField(length=probe('z'))

        # whole, a stale record in the packet handed dropped; cut after the nested
        # schema; and cut inside the forward match, where the nested schema is told
        # only of its own cut
        for raw, packet, short, expected in (
            (b'\x01\x02\x03\x04\x05', {'__short_read__': ('stale', 0)}, None,
             [('x', None), ('inner', None), ('y', None), ('z', None)]),
            (b'\x01\x02\x03', {}, ('y', 0),
             [('x', None), ('inner', None), ('y', None), ('z', ('y', 0))]),
            (b'\x01', {}, ('inner', 0),
             [('x', ('peek', 1)), ('inner', ('a', 0)), ('y', ('peek', 1)), ('z', ('peek', 1))]),
        ):
            with self.subTest(raw=raw.hex()):
                seen.clear()
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    schema = Outer.unpack(raw, len(raw), packet)
                self.assertEqual(seen, expected)
                self.assertEqual(schema.__dict__.get('__short_read__'), short)
                self.assertEqual(bytes(schema), raw)

    def test_a_short_read_noted_without_a_packet_is_kept_on_the_schema(self) -> None:
        # ``packet`` is optional, for a caller with no packet to hand the record to,
        # and the first record still wins
        from pcapkit.corekit.fields.numbers import UInt8Field
        from pcapkit.protocols.schema import Schema, schema_final

        @schema_final
        class Tiny(Schema):
            a: int = UInt8Field()
            b: int = UInt8Field()

        # pylint: disable=protected-access
        schema = Tiny.unpack(b'\x01\x02', 2, {})
        schema._note_short_read('b', 1, b'')
        self.assertEqual(schema.__dict__['__short_read__'], ('b', 0))
        schema._note_short_read('a', 1, b'')
        self.assertEqual(schema.__dict__['__short_read__'], ('b', 0))

        packet = {}  # type: dict[str, Any]
        schema = Tiny.unpack(b'\x01\x02', 2, {})
        schema._note_short_read('a', 1, b'', packet)
        self.assertEqual((schema.__dict__['__short_read__'], packet), (('a', 0), {'__short_read__': ('a', 0)}))


if __name__ == '__main__':
    unittest.main()
