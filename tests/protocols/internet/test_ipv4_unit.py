from __future__ import annotations

import datetime
import importlib.util
import io
from ipaddress import ip_address
import types
import unittest
from unittest import mock
import warnings

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPv4UnitTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_ipv4_index_returns_expected_registry_value(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4

        self.assertEqual(IPv4.__index__(), TransType.IPv4)

    def test_ipv4_make_data_preserves_selected_fields(self) -> None:
        from datetime import timedelta

        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4

        class DummyDict(dict):
            __getattr__ = dict.__getitem__

        data = DummyDict(
            tos=DummyDict(pre=0, thr=False, rel=False, ecn=0, **{'del': False}),
            id=7,
            flags=DummyDict(df=True, mf=False),
            offset=0,
            ttl=timedelta(seconds=64),
            protocol=TransType.TCP,
            checksum=b'\x12\x34',
            src='192.0.2.10',
            dst='198.51.100.20',
            options=[],
            __next_type__=None,
        )

        values = IPv4._make_data(data)
        self.assertEqual(values['id'], 7)
        self.assertEqual(values['df'], True)
        self.assertEqual(values['mf'], False)
        self.assertEqual(values['protocol'], TransType.TCP)
        self.assertEqual(values['src'], '192.0.2.10')
        self.assertEqual(values['dst'], '198.51.100.20')
        self.assertIn('payload', values)

    def test_ipv4_make_data_scales_offset_and_defaults_missing_options(self) -> None:
        """Regression test for #494.

        Two defects live in :meth:`IPv4._make_data
        <pcapkit.protocols.internet.ipv4.IPv4._make_data>`: the fragment
        ``offset`` was handed back in octets to a parameter that
        :meth:`IPv4.make <pcapkit.protocols.internet.ipv4.IPv4.make>` takes in
        on-wire 8-octet units (:rfc:`791`), and ``data.options`` was read
        unconditionally even though :meth:`IPv4.read
        <pcapkit.protocols.internet.ipv4.IPv4.read>` only sets it when
        ``hdr_len`` exceeds the fixed 20-octet header.

        The two interact: the missing-``options`` ``AttributeError`` fires
        before the unscaled ``offset`` can even be returned, so a fixture
        that always supplies ``options`` -- like the ``DummyDict`` one above,
        which also uses ``offset=0``, the one value for which the missing
        ``// 8`` is invisible -- cannot catch either. This test uses a
        non-zero offset *and* a real packet with no options, so both
        defects are exercised together, exactly as the issue's own repro
        does.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = object.__new__(IPv4)

        # Wire Fragment Offset of 5 (8-octet units), no options -> hdr_len
        # stays at the fixed 20 octets and read() never sets ``.options``.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = proto.make(offset=5, protocol=6, payload=b'\xaa' * 8).pack()
            data = IPv4(io.BytesIO(raw), len(raw)).info

        self.assertFalse(hasattr(data, 'options'))
        self.assertEqual(data.offset, 40)  # read() scales wire units to octets

        values = IPv4._make_data(data)
        self.assertEqual(values['offset'], 5)  # scaled back down to wire units
        self.assertIsNone(values['options'])

        # Full round trip: re-packing with the recovered offset must
        # reproduce the exact original wire bytes.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw2 = proto.make(offset=values['offset'], protocol=6,
                              payload=b'\xaa' * 8).pack()
        self.assertEqual(raw, raw2)

    def test_ipv4_from_data_rebuilds_a_parsed_datagram(self) -> None:
        """Regression test for #506.

        :meth:`IPv4.from_data <pcapkit.protocols.internet.ipv4.IPv4.from_data>`
        could not rebuild a datagram that had been *parsed*, only one that had
        been built by hand. The test above covers :meth:`IPv4._make_data
        <pcapkit.protocols.internet.ipv4.IPv4._make_data>` in isolation, which is
        why #494 went in without this surfacing: ``_make_data`` is one input to
        ``from_data``, and both remaining faults were downstream of it.

        The wire literals below are parsed rather than constructed, so the info
        they yield carries what parsing actually produces -- a
        :class:`~pcapkit.protocols.misc.raw.Raw` or
        :class:`~pcapkit.protocols.misc.null.NoPayload` instance for the payload,
        and an option *container* for the options -- rather than the
        constructor-shaped values :meth:`IPv4.make
        <pcapkit.protocols.internet.ipv4.IPv4.make>` is normally handed. Each one
        raised before the fix: the first two with ``ProtocolUnbound: unsupported
        type <class 'pcapkit.protocols.misc.raw.Raw'>``, the third with the same
        naming ``NoPayload``.

        The third literal is the ``RTRALT`` frame of ``options-ipv4.pcap`` as
        generated by :file:`examples/generators/make_samples.py`, inlined so the
        test does not depend on the fixture captures being present.

        It is named by its option rather than by its index because this fix
        renumbers that capture: the option-padding half below lets the generator
        emit the ``RR``, ``LSR``, ``SID`` and ``SSR`` frames it previously could
        not write at all, which grows ``options-ipv4.pcap`` from 8 frames (456
        octets) to 12 (784) and moves this frame from 8th to 12th. An index here
        would have been correct when written and wrong once the fix landed.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw

        cases = [
            # the issue's own repro: fragment offset 5, no options, 8 octets of
            # unparseable TCP that come back as ``Raw``
            ('no options', '4500001c00000005000600007f00000100000000aaaaaaaaaaaaaaaa',
             None, Raw),
            # the same, with a 4-octet Router Alert option ahead of the payload
            ('with options', '4600002000000005000600007f0000010000000094040001aaaaaaaaaaaaaaaa',
             [OptionNumber.RTRALT], Raw),
            # options-ipv4.pcap frame 8: options, and no payload at all
            ('with options, no payload', '460000180000000000060000c0000201c633640194040001',
             [OptionNumber.RTRALT], NoPayload),
        ]

        for label, hexstr, codes, payload_type in cases:
            with self.subTest(label):
                raw = bytes.fromhex(hexstr)

                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = IPv4(io.BytesIO(raw), len(raw))

                # the parsed shapes the make path has to cope with
                self.assertIsInstance(parsed.payload, payload_type)
                if codes is None:
                    self.assertFalse(hasattr(parsed.info, 'options'))
                else:
                    self.assertEqual(list(parsed.info.options.keys()), codes)

                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    rebuilt = IPv4.from_data(parsed.info)

                self.assertEqual(bytes(rebuilt), raw)

    def test_ipv4_make_accepts_a_protocol_instance_as_payload(self) -> None:
        """A protocol instance is a payload ``make`` has to accept. C.f. #506.

        This is the mechanism behind the round trip above, tested on its own
        because it is a documented part of the construction API rather than
        something only ``from_data`` reaches: every ``make`` in the library
        annotates its ``payload`` as ``bytes | Protocol | Schema``, where
        ``Protocol`` is :class:`~pcapkit.protocols.protocol.ProtocolBase`
        imported under its historical name. :meth:`Schema.pack
        <pcapkit.protocols.schema.schema.Schema.pack>` nonetheless rejected every
        protocol instance in the library, because its own ``isinstance`` check
        named the *other* class -- the thin
        :class:`~pcapkit.protocols.protocol.Protocol` subclass, which nothing
        subclasses -- so the branch that packs a protocol payload was
        unreachable.

        Asserting on the shape rather than only on the bytes is deliberate: a
        ``_make_payload`` changed to hand back :obj:`bytes` would make the round
        trip above pass again while leaving this API broken, so the two tests
        fail for different reasons.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import Protocol, ProtocolBase

        proto = object.__new__(IPv4)
        payload = b'\xaa' * 8

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            expected = proto.make(protocol=6, payload=payload).pack()

            # a protocol instance carrying the same octets packs identically ...
            raw_payload = Raw(packet=payload)
            self.assertIsInstance(raw_payload, ProtocolBase)
            # ... and it is *not* a ``Protocol``, which is the whole of the
            # defect. Asserting the negative matters because the branch was not
            # uncovered before the fix -- it was covered by the only class in the
            # tree that satisfied it, ``DummyProtocol`` in
            # tests/protocols/schema/test_schema_unit.py:167, which subclasses
            # ``Protocol`` and so packed happily while every protocol in the
            # library raised. Without this line the same hole could be reopened
            # by making a protocol subclass ``Protocol`` rather than by fixing
            # the check.
            self.assertNotIsInstance(raw_payload, Protocol)
            self.assertEqual(proto.make(protocol=6, payload=raw_payload).pack(),
                             expected)

            # ... and an empty one is the same as no payload at all
            self.assertEqual(proto.make(protocol=6, payload=NoPayload()).pack(),
                             proto.make(protocol=6, payload=b'').pack())

        # the shape ``from_data`` feeds to ``make``, named here so that routing
        # around the packing layer instead of fixing it does not go unnoticed
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(expected), len(expected))
        self.assertIsInstance(IPv4._make_data(parsed.info)['payload'], ProtocolBase)

    def test_schema_pack_packs_a_protocol_base_payload_on_its_own(self) -> None:
        """The packing layer itself, with no ``make`` in front of it. C.f. #506.

        The test above reaches :meth:`Schema.pack
        <pcapkit.protocols.schema.schema.Schema.pack>` through :meth:`IPv4.make
        <pcapkit.protocols.internet.ipv4.IPv4.make>`, so it cannot say which of
        the two was at fault. This one builds the header schema directly and
        packs it, which is where the defect actually lived: the ``PayloadField``
        branch of ``Schema.pack`` tested ``isinstance(data, Protocol)`` where it
        meant :class:`~pcapkit.protocols.protocol.ProtocolBase`.

        The three assertions are the three things the widened check has to get
        right at once, and they pull in different directions:

        * a :class:`~pcapkit.protocols.protocol.ProtocolBase` payload packs to its
          own octets -- the defect;
        * :class:`~pcapkit.protocols.protocol.Protocol` is still a subclass of
          ``ProtocolBase``, so an externally defined engine that *did* satisfy the
          old check still satisfies the new one. That is the claim the ``NOTE`` on
          the fix makes about not regressing anything, and it is the reason
          widening the check is safe rather than merely correct;
        * anything that is neither protocol, schema nor :obj:`bytes` still raises
          :exc:`~pcapkit.utilities.exceptions.ProtocolUnbound`, so the branch was
          widened and not simply removed.

        """
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import Protocol, ProtocolBase
        from pcapkit.protocols.schema.internet.ipv4 import IPv4 as Schema_IPv4
        from pcapkit.utilities.exceptions import ProtocolUnbound

        payload = b'\xaa' * 8

        def header(value: 'object') -> 'Schema_IPv4':
            return Schema_IPv4(
                vihl={'version': 4, 'ihl': 5},
                tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
                length=20 + len(payload), id=0,
                flags={'df': 0, 'mf': 0, 'offset': 0},
                ttl=0, proto=6, chksum=b'\x00\x00',
                src='127.0.0.1', dst='127.0.0.2',
                options=[], payload=value,
            )

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            expected = header(payload).pack()

            raw_payload = Raw(packet=payload)
            self.assertIsInstance(raw_payload, ProtocolBase)
            self.assertNotIsInstance(raw_payload, Protocol)
            self.assertEqual(header(raw_payload).pack(), expected)

        # an external ``Protocol`` engine is a ``ProtocolBase`` too, so widening
        # the check cannot have cost anything that used to work
        self.assertTrue(issubclass(Protocol, ProtocolBase))

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with self.assertRaises(ProtocolUnbound):
                header(object()).pack()

    def test_schema_pack_packs_a_second_real_protocol_as_payload(self) -> None:
        """A real protocol nested in another one, not ``Raw`` and not ``NoPayload``.

        This closes a hole in the three tests above rather than describing a
        defect of its own. Every one of them hands the payload field a
        :class:`~pcapkit.protocols.misc.raw.Raw` or a
        :class:`~pcapkit.protocols.misc.null.NoPayload`, because those are what
        *parsing* yields, so between them they exercise exactly two of the 43
        :class:`~pcapkit.protocols.protocol.ProtocolBase` descendants the widened
        check in :meth:`Schema.pack
        <pcapkit.protocols.schema.schema.Schema.pack>` has to accept. That is
        enough coverage to be defeated by a fix that is not one: replacing the
        ``isinstance(data, ProtocolBase)`` check of #536 with

        .. code-block:: python

           elif isinstance(data, (Protocol, Raw, NoPayload)):

        -- special-casing precisely the classes the tests use -- passes all four
        of them, measured, while leaving the general defect in place for the
        other 40 protocols. #536's own reviewer found that by falsification, and
        this test is what makes the shortcut fail.

        So the payload here is a ``UDP``, and the assertions are chosen to be
        unsatisfiable by any finite list of special cases:

        * ``UDP`` is a ``ProtocolBase`` and is *none* of the three classes such a
          list would name, which is what makes it a witness rather than another
          instance of the covered case;
        * three different real protocols are nested, so a list extended to
          include ``UDP`` alone still fails;
        * the count of descendants outside that list is asserted, so the reason
          a class list cannot be the fix is recorded as a number rather than as a
          remark. It is a lower bound, since the check only has to keep holding
          as protocols are added.

        UDP-in-IPv4 is also the plainest thing a packet library is for, which is
        the other reason it belongs in the suite on its own merits.

        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.misc.null import NoPayload
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.protocols.protocol import Protocol, ProtocolBase
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.protocols.transport.udp import UDP

        proto = object.__new__(IPv4)

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            udp = UDP(srcport=1234, dstport=53, payload=b'\xbb' * 8)
            udp_octets = bytes(udp)

        # 8 octets of UDP header and the 8 the caller gave it
        self.assertEqual(len(udp_octets), 16)

        # The witness: a real protocol is a ``ProtocolBase``, and it is not any
        # of the classes a special-cased check would enumerate. Every assertion
        # below rests on this one.
        self.assertIsInstance(udp, ProtocolBase)
        self.assertNotIsInstance(udp, Protocol)
        self.assertNotIsInstance(udp, Raw)
        self.assertNotIsInstance(udp, NoPayload)

        # Nesting it packs to exactly what handing over its own octets does, so
        # the payload branch packed the protocol rather than rejecting it or
        # stringifying it.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            nested = proto.make(protocol=17, payload=udp).pack()
            flat = proto.make(protocol=17, payload=udp_octets).pack()
        self.assertEqual(nested, flat)
        self.assertEqual(nested[20:], udp_octets)
        self.assertEqual(len(nested), 36)

        # And the datagram parses back as UDP, which is the end-to-end statement
        # that the nesting produced a real packet and not merely equal bytes.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(nested), len(nested))
        self.assertEqual(parsed.info.len, 36)
        self.assertIsInstance(parsed.payload, ProtocolBase)

        # More than one, so extending the special-case list with ``UDP`` does not
        # buy the shortcut anything either.
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            others = [
                TCP(srcport=1234, dstport=80, payload=b'\xcc' * 8),
                IPv4(protocol=6, src='192.0.2.1', dst='198.51.100.1',
                     payload=b'\xcc' * 8),
            ]
            for inner in others:
                with self.subTest(payload=type(inner).__name__):
                    self.assertIsInstance(inner, ProtocolBase)
                    self.assertNotIsInstance(inner, (Protocol, Raw, NoPayload))
                    octets = bytes(inner)
                    self.assertEqual(
                        proto.make(protocol=6, payload=inner).pack()[20:],
                        octets
                    )

        # The number that says why a class list is the wrong shape of fix. The
        # walk is over descendants rather than direct subclasses because the
        # tree is several levels deep -- ``UDP`` is a ``Transport`` is a
        # ``ProtocolBase``.
        def descendants(cls: 'type') -> 'set[type]':
            found = set()  # type: set[type]
            pending = [cls]
            while pending:
                for sub in pending.pop().__subclasses__():
                    if sub not in found:
                        found.add(sub)
                        pending.append(sub)
            return found

        excluded = {Protocol, Raw, NoPayload} | descendants(Protocol)
        uncovered = descendants(ProtocolBase) - excluded
        self.assertGreaterEqual(
            len(uncovered), 30,
            'the payload branch has to accept every ProtocolBase subclass, and '
            'there are far more of them than the Raw and NoPayload the other '
            'tests in this file use; if this number has collapsed, the walk '
            'broke rather than the library shrinking'
        )
        self.assertIn(UDP, uncovered)

    def test_ipv4_make_options_pads_with_an_eool_option_not_its_wire_code(self) -> None:
        """Option padding has to be an option, not an option number. C.f. #506.

        :meth:`IPv4._make_ipv4_options
        <pcapkit.protocols.internet.ipv4.IPv4._make_ipv4_options>` pads each
        option out to a 32-bit boundary with ``NOP`` options and a terminating
        ``EOOL``. The ``NOP``\\ s went in as option schemas but the ``EOOL`` went
        in as :attr:`OptionNumber.EOOL
        <pcapkit.const.ipv4.option_number.OptionNumber.EOOL>` itself, and the
        enclosing option field takes only schemas and :obj:`bytes`, so packing
        the header failed with ``FieldValueError: Field options has invalid
        value``.

        Both of the method's branches are exercised: the ``list`` branch a caller
        reaches through ``make``, and the container branch ``from_data`` reaches,
        since a parsed datagram hands its options back as an
        :class:`~pcapkit.corekit.multidict.OrderedMultiDict`. Any option whose
        length is not already a multiple of four reaches the padding; ``SEC`` is
        three octets, so one octet of it is padding.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.schema import Schema

        proto = object.__new__(IPv4)
        sec = (OptionNumber.SEC, {})

        # list branch: three octets of option, one of padding
        options, total_length = proto._make_ipv4_options([sec])
        self.assertEqual(total_length, 4)
        for entry in options:
            self.assertIsInstance(entry, (Schema, bytes))
        self.assertIsInstance(options[-1], Schema)
        self.assertEqual(options[-1].type, OptionNumber.EOOL)

        # ... and the header it feeds actually packs, with the padding octet where
        # the terminator belongs
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            raw = proto.make(protocol=6, options=[sec], payload=b'\xaa' * 4).pack()
        self.assertEqual(raw[20], OptionNumber.SEC)
        self.assertEqual(raw[21], 3)
        self.assertEqual(raw[23], OptionNumber.EOOL)

        # container branch: the same option area, arriving the way a parsed
        # datagram hands it back, and rebuilding to the same octets
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(raw), len(raw))
            options, total_length = proto._make_ipv4_options(parsed.info.options)
            rebuilt = IPv4.from_data(parsed.info)
        self.assertEqual(total_length, 4)
        for entry in options:
            self.assertIsInstance(entry, (Schema, bytes))
        # the terminator is asserted on this branch too, not only on the list
        # branch above, and against the method's own return value rather than
        # against the assembled packet. The bytes comparison at the end of this
        # test does catch a wrong terminator, but it reports it as two hex
        # strings; this says which entry was wrong.
        self.assertIsInstance(options[-1], Schema)
        self.assertEqual(options[-1].type, OptionNumber.EOOL)
        self.assertEqual(bytes(rebuilt), raw)

    def test_ipv4_make_opt_sec_sets_the_field_termination_indicator(self) -> None:
        """A SEC option this library writes is one this library can read. C.f. #537.

        :rfc:`1108` section 2.2 makes bit 0 of each protection authority octet a
        *field termination indicator*: ``0`` means another octet follows, ``1``
        means this is the last. ``_read_opt_sec`` enforces it, warning
        ``field termination indicator not set`` when the final octet has it
        clear. ``_make_opt_sec`` built the bitmap purely out of authority bit
        positions and never set it, so *every* SEC option the library wrote with
        at least one authority was one its own reader flagged as malformed --
        visible in the project's own generated capture
        :file:`examples/captures/options-ipv4.pcap`, which warned
        ``IPv4: [OptNo 130] invalid format: field termination indicator not set``
        on extraction.

        The round trip is asserted through a real datagram and with warnings
        promoted to errors, because the defect's only symptom was a warning:
        asserting on the octets alone would have let it back in, and asserting
        that the flags survive alone would too -- they always did.

        ``0x91`` rather than ``0x90`` is the whole change on the wire:
        ``1001 0001``, bits 0 and 3 for ``GENSER`` and ``NSA`` counted from the
        most significant, and bit 0 of the octet for the terminator.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.warnings import ProtocolWarning

        proto = object.__new__(IPv4)
        authorities = [ProtectionAuthority.GENSER, ProtectionAuthority.NSA]

        schema = proto._make_opt_sec(OptionNumber.SEC, authorities=authorities)
        self.assertEqual(schema.data, b'\x91')
        self.assertEqual(schema.data[-1] & 0x01, 1)
        self.assertEqual(schema.length, 4)

        # The reader's own predicate, stated here rather than inferred from the
        # absence of a warning below, so a reader that stopped checking does not
        # silently make this test vacuous.
        self.assertNotEqual(schema.data[-1] & 0x01, 0)

        # And the end-to-end statement: a datagram carrying this option parses
        # with no ProtocolWarning at all. The option is four octets -- type,
        # length, classification level and the one-octet bitmap -- which is
        # exactly the option area an ihl of 6 declares, so nothing is padded.
        packed = schema.pack()
        self.assertEqual(len(packed), 4)
        header = bytes.fromhex('46000018 00000000 00060000 '
                               '7f000001 7f000002') + packed
        self.assertEqual(len(header), 24)

        with warnings.catch_warnings():
            warnings.simplefilter('error', ProtocolWarning)
            parsed = IPv4(header, len(header))

        self.assertEqual(parsed.info.options[OptionNumber.SEC].flags,
                         tuple(authorities))

    def test_ipv4_make_opt_sec_sizes_the_bitmap_from_the_bit_count(self) -> None:
        """One authority numbered zero is one octet, not zero octets. C.f. #537.

        ``int_len`` was ``math.ceil(max_auth / 8)``, which sizes the bitmap from
        the highest bit *index* rather than from the bit *count* one past it.
        With ``GENSER`` (value ``0``) the only authority that is ``0`` octets,
        and the ``data_list[auth] = b'1'`` below it then raised a bare
        ``IndexError: list assignment index out of range`` -- not an in-library
        exception, and out of a ``_make_opt_*`` helper.

        That is why :file:`examples/generators/options.py` passed *two*
        authorities to this option; with the arithmetic fixed, one is a
        legitimate argument again, which is the thing this test is really
        asserting.

        The same off-by-one under-sized by a whole octet at every exact multiple
        of eight, which is checked here too. No shipped enumeration member has
        value ``8``, so that half was latent rather than reachable -- and it is
        the half that would have corrupted an option instead of raising, so it is
        worth pinning even though nothing reaches it today.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = object.__new__(IPv4)

        # One octet: GENSER at bit 0 from the most significant, and the
        # terminator. Formerly an IndexError.
        schema = proto._make_opt_sec(OptionNumber.SEC,
                                     authorities=[ProtectionAuthority.GENSER])
        self.assertEqual(schema.data, b'\x81')
        self.assertEqual(schema.length, 4)

        # The largest authority that still fits one octet, bit 6, since bit 7 is
        # the terminator.
        schema = proto._make_opt_sec(OptionNumber.SEC,
                                     authorities=[ProtectionAuthority(6)])
        self.assertEqual(schema.data, b'\x03')
        self.assertEqual(schema.length, 4)

        # Index 8 is the first bit of the *second* octet, so it needs two --
        # ceil(8/8) said one. The first octet is all zeros, its own terminator
        # included, which is what says "another octet follows".
        schema = proto._make_opt_sec(OptionNumber.SEC,
                                     authorities=[ProtectionAuthority(8)])
        self.assertEqual(schema.data, b'\x00\x81')
        self.assertEqual(schema.length, 5)

        # Only the last octet terminates the field; an intermediate one that did
        # would make the reader warn 'remaining data'.
        self.assertEqual(schema.data[0] & 0x01, 0)
        self.assertEqual(schema.data[-1] & 0x01, 1)

        # No authorities at all stays a bare 3-octet option with no bitmap, so
        # there is no final octet to terminate.
        schema = proto._make_opt_sec(OptionNumber.SEC, authorities=[])
        self.assertEqual(schema.data, b'')
        self.assertEqual(schema.length, 3)

    def test_ipv4_make_opt_sec_rejects_a_termination_bit_as_an_authority(self) -> None:
        """Bit positions the reader treats as structure are not authorities. C.f. #537.

        ``Enum_ProtectionAuthority`` member ``7`` is named
        ``Field_Termination_Indicator`` -- it is not an authority at all, yet it
        was a member of the enumeration the writer accepted as one. Passing it
        produced ``data=b'\\x01'``: an option that reads as validly terminated
        while encoding zero authorities.

        The writer and the reader disagreed about whether index 7 is data, and
        this test records which of the two won. ``_read_opt_sec`` loops over
        ``range(7)`` per octet and maps octet ``base`` bit ``bit`` to authority
        ``base * 8 + bit``, so the authority numbering it produces *skips* 7, 15
        and 23 -- those positions are termination bits and nothing else. The
        reader is right and the writer was wrong, so the rejection is on the
        write side and ``range(7)`` is left alone; widening it would make the
        reader report a terminator as an authority.

        Rejecting the whole congruence class rather than only the named ``7``
        follows from that: 15 and 23 are termination bits for exactly the same
        reason and are just as undeliverable, they simply have no name in the
        enumeration yet. Asserting 15 is what stops the fix being read as a
        special case of one value.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)

        with self.assertRaises(ProtocolError) as caught:
            proto._make_opt_sec(
                OptionNumber.SEC,
                authorities=[ProtectionAuthority.Field_Termination_Indicator],
            )
        self.assertIn('Field_Termination_Indicator', str(caught.exception))
        self.assertIn('field termination indicator', str(caught.exception))

        # An in-library exception, which a bare IndexError was not. Both halves
        # matter: the type, and that it carries the option number the way every
        # other rejection in this module does.
        self.assertIsInstance(caught.exception, ProtocolError)
        self.assertIn(f'[OptNo {OptionNumber.SEC}]', str(caught.exception))

        # 15 and 23 are termination bits too, by the reader's own numbering.
        for value in (15, 23):
            with self.subTest(authority=value):
                with self.assertRaises(ProtocolError):
                    proto._make_opt_sec(OptionNumber.SEC,
                                        authorities=[ProtectionAuthority(value)])

        # A negative index would have written to the terminator through Python's
        # negative indexing rather than raising -- silent corruption, and the one
        # way the IndexError could still have been reached after the arithmetic
        # was fixed.
        with self.assertRaises(ProtocolError):
            proto._make_opt_sec(OptionNumber.SEC, authorities=[-1])

        # The control: the neighbouring index is a real authority and still
        # works, so this is a statement about position 7 and not about the
        # rejection swallowing the whole argument.
        self.assertEqual(
            proto._make_opt_sec(OptionNumber.SEC,
                                authorities=[ProtectionAuthority.DOE]).data,
            b'\x09',
        )

    def test_ipv4_sid_option_is_four_octets_wide_on_the_wire(self) -> None:
        """RFC 791's four-octet Stream ID option survives the round trip. C.f. #534.

        ``SIDOption.sid`` was a
        :class:`~pcapkit.corekit.fields.numbers.UInt32Field` where :rfc:`791`
        section 3.1 gives the Stream ID two octets inside a four-octet option --
        which is what ``_make_opt_sid`` itself had always written into
        ``length``. Only the schema field disagreed, so it over-read a
        well-formed option by two octets on the way in, warning
        ``packet length < 0: -2``, and over-wrote it by two on the way out:
        ``880400000037`` for an option that is ``88040037``.

        Six not being a multiple of four, the option area then reached the
        32-bit padding branch and picked up a ``NOP`` and an ``EOOL``, so the
        rebuilt datagram came back four octets longer than the one it was read
        from, with ``ihl`` and total length grown to match -- 28 octets and
        ``ihl=7`` against the 24 and ``ihl=6`` on the wire.

        This starts from wire octets rather than from a constructed option
        because that is the only place the width shows: constructing and
        reconstructing both go through the same ``_make_opt_sid``, so the two
        halves agreed with each other while disagreeing with :rfc:`791`. That
        symmetry is why the defect could not be recorded as an
        ``EXPECTED_FAILURES`` entry, and it is why the assertion here is
        byte-for-byte identity against the input rather than a comparison of two
        outputs.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        option = bytes.fromhex('88040037')
        header = bytes.fromhex('46000018 00000000 00060000 '
                               '7f000001 7f000002') + option
        self.assertEqual(len(header), 24)

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            parsed = IPv4(header, len(header))

        # The over-read was the library naming its own defect. It is gone.
        self.assertNotIn('packet length < 0: -2',
                         [str(entry.message) for entry in caught])

        sid = parsed.info.options[OptionNumber.SID]
        self.assertEqual(sid.sid, 0x37)
        self.assertEqual(sid.length, 4)

        proto = object.__new__(IPv4)
        self.assertEqual(proto._make_opt_sid(OptionNumber.SID, sid).pack(),
                         option)

        # Four octets is already 32-bit aligned, so the padding branch is not
        # reached at all -- no NOP and no EOOL, where before there was one of
        # each.
        options, total_length = proto._make_ipv4_options(parsed.info.options)
        self.assertEqual([type(entry).__name__ for entry in options],
                         ['SIDOption'])
        self.assertEqual(total_length, 4)

        # And so the datagram rebuilds to exactly the octets it was read from.
        rebuilt = bytes(IPv4.from_data(parsed.info))
        self.assertEqual(rebuilt, header)
        self.assertEqual(len(rebuilt), 24)
        self.assertEqual(rebuilt[0] & 0x0F, 6)
        self.assertEqual(int.from_bytes(rebuilt[2:4], 'big'), 24)

    def test_ipv4_properties_read_and_make_cover_packet_paths(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)
        proto._info = types.SimpleNamespace(
            hdr_len=20,
            protocol=TransType.TCP,
            src=ip_address('192.0.2.1'),
            dst=ip_address('198.51.100.1'),
        )
        self.assertEqual(proto.name, 'Internet Protocol version 4')
        self.assertEqual(proto.length, 20)
        self.assertEqual(proto.protocol, TransType.TCP)
        self.assertEqual(proto.src, ip_address('192.0.2.1'))
        self.assertEqual(proto.dst, ip_address('198.51.100.1'))
        self.assertEqual(proto.__length_hint__(), 20)
        self.assertEqual(IPv4.id(), ('IPv4',))

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 4, 'ihl': 7},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=32,
            id=7,
            flags={'df': 1, 'mf': 0, 'offset': 1},
            ttl=64,
            proto=TransType.TCP,
            chksum=b'\x12\x34',
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[
                ipv4_schema.SIDOption(type=OptionNumber.SID, length=4, sid=55),
                ipv4_schema.EOOLOption(type=OptionNumber.EOOL),
            ],
            payload=b'data',
        )
        proto._data = b'\x00' * 32
        proto.__cached__ = {}
        proto._decode_next_layer = mock.Mock(return_value='decoded')

        self.assertEqual(proto.read(), 'decoded')
        decoded_ip, next_type, payload_length = proto._decode_next_layer.call_args.args
        self.assertEqual(decoded_ip.hdr_len, 28)
        self.assertEqual(decoded_ip.options[OptionNumber.SID].sid, 55)
        self.assertEqual(decoded_ip.offset, 8)
        self.assertEqual(next_type, TransType.TCP)
        self.assertEqual(payload_length, 4)

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 4, 'ihl': 5},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=24,
            id=8,
            flags={'df': 0, 'mf': 0, 'offset': 0},
            ttl=32,
            proto=TransType.UDP,
            chksum=b'\x00\x00',
            src='192.0.2.2',
            dst='198.51.100.2',
            options=[],
            payload=b'data',
        )
        proto._decode_next_layer.reset_mock()
        self.assertEqual(proto.read(length=24), 'decoded')
        decoded_no_options = proto._decode_next_layer.call_args.args[0]
        self.assertFalse(hasattr(decoded_no_options, 'options'))

        proto.__header__ = ipv4_schema.IPv4(
            vihl={'version': 6, 'ihl': 5},
            tos={'pre': 0, 'del': 0, 'thr': 0, 'rel': 0, 'ecn': 0},
            length=20,
            id=1,
            flags={'df': 0, 'mf': 0, 'offset': 0},
            ttl=1,
            proto=TransType.UDP,
            chksum=b'\x00\x00',
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[],
            payload=b'',
        )
        with self.assertRaises(ProtocolError):
            proto.read(length=20)

        made = proto.make(
            ttl=datetime.timedelta(seconds=64),
            protocol=TransType.TCP,
            src='192.0.2.1',
            dst='198.51.100.1',
            options=[(OptionNumber.SID, {'sid': 5})],
            payload=b'data',
        )
        # 20 of header, the 4-octet SID option, and 4 of payload. This read 32
        # with ihl=7 while ``SIDOption.sid`` was 32 bits wide: the option packed
        # to six octets, which is not 32-bit aligned, so the option area picked
        # up a NOP and an EOOL and grew to eight. See #534.
        self.assertEqual(made.length, 28)
        self.assertEqual(made.vihl['ihl'], 6)
        self.assertEqual(made.ttl, 64)
        self.assertEqual(made.proto, TransType.TCP)

        no_options = proto.make(options=None, payload=b'')
        self.assertEqual(no_options.length, 20)
        self.assertEqual(no_options.vihl['ihl'], 5)

    def test_ipv4_register_option_warns_on_overwrite(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        registry = IPv4.__dict__['__option__']

        original = registry[OptionNumber.EOOL]
        try:
            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(OptionNumber.EOOL, 'eool')
            warn.assert_called_once()
            self.assertEqual(registry[OptionNumber.EOOL], 'eool')
        finally:
            registry[OptionNumber.EOOL] = original

        # An unregistered code carries no entry, so registering one is not an
        # overwrite. The setattr form could not tell the two apart: it keyed the
        # warning on ``hasattr(cls, f'_read_opt_{name}')``, which is true of every
        # shipped handler as well as of anything a user had already installed.
        custom = OptionNumber.get(31)
        self.assertNotIn(custom, registry)
        try:
            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(custom, 'unassigned')
            warn.assert_not_called()
            self.assertEqual(registry[custom], 'unassigned')

            with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                IPv4.register_option(custom, 'unassigned')
            warn.assert_called_once()
        finally:
            registry.pop(custom, None)

    def test_ipv4_register_option_dispatches_a_registered_callable_pair(self) -> None:
        """A ``(parser, constructor)`` pair must reach both dispatch directions.

        The pair is called with the signatures :data:`OptionParser` and
        :data:`OptionConstructor` declare -- ``(schema, *, options)`` and
        ``(code, option=None, **kwargs)`` -- i.e. as plain callables rather than
        as methods with an implicit ``self``. That is the calling convention
        every other dispatch family uses, and the reason the registry form
        replaced ``setattr``: installing the callable on the class made it a
        descriptor, so dispatch passed ``self`` as the first positional argument
        and a handler written to the declared signature could not be called at
        all.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import ipv4 as ipv4_data
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema

        registry = IPv4.__dict__['__option__']
        custom = OptionNumber.get(31)
        proto = object.__new__(IPv4)
        seen = []  # type: list[str]

        def read_option(schema, *, options):
            seen.append('read')
            return ipv4_data.UnassignedOption(
                code=schema.type,
                type=proto._read_ipv4_opt_type(schema.type),
                length=schema.length,
                data=schema.data,
            )

        def make_option(code, option=None, *, data=b'', **kwargs):
            seen.append('make')
            if option is not None:
                data = option.data
            return ipv4_schema.UnassignedOption(type=code, length=len(data) + 2,
                                                data=data)

        self.assertNotIn(custom, registry)
        try:
            IPv4.register_option(custom, (read_option, make_option))
            self.assertEqual(registry[custom], (read_option, make_option))

            proto.__header__ = types.SimpleNamespace(
                options=[ipv4_schema.UnassignedOption(type=custom, length=4,
                                                      data=b'xx')],
            )
            parsed = proto._read_ipv4_options(4)
            self.assertEqual(seen, ['read'])
            self.assertEqual(parsed[custom].data, b'xx')

            # the list-of-tuples branch of the constructor
            seen.clear()
            made_list, list_len = proto._make_ipv4_options([(custom, {'data': b'yy'})])
            self.assertEqual(seen, ['make'])
            self.assertEqual(made_list[0].data, b'yy')
            self.assertEqual(list_len, 4)

            # ... and the OrderedMultiDict branch, which the two halves of an
            # issue like this are equally easy to fix one of and forget the other
            seen.clear()
            made_dict, dict_len = proto._make_ipv4_options(
                OrderedMultiDict([(custom, parsed[custom])]))
            self.assertEqual(seen, ['make'])
            self.assertEqual(made_dict[0].data, b'xx')
            self.assertEqual(dict_len, 4)
        finally:
            registry.pop(custom, None)

    def test_ipv4_option_registry_covers_every_shipped_handler(self) -> None:
        """Every ``_read_opt_*`` / ``_make_opt_*`` pair must be reachable.

        The setattr form derived the handler name from ``code.name.lower()``, so
        a handler was reachable by construction and "what is registered?" had no
        direct answer. Under the registry the mapping is explicit data, which
        means a handler added without its registry entry becomes dead code --
        this pins the two sides together.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        registry = IPv4.__dict__['__option__']
        fallback = registry.default_factory()
        self.assertEqual(fallback, 'unassigned')

        registered = set(registry.values()) | {fallback}
        shipped = {name[len('_read_opt_'):] for name in vars(IPv4)
                   if name.startswith('_read_opt_')}
        self.assertEqual(shipped, registered)
        self.assertEqual(
            {name[len('_make_opt_'):] for name in vars(IPv4)
             if name.startswith('_make_opt_')},
            registered,
        )

        # every key is a real option number, and every value names real methods
        for code, name in registry.items():
            with self.subTest(code=code):
                self.assertIsInstance(code, OptionNumber)
                self.assertTrue(hasattr(IPv4, f'_read_opt_{name}'))
                self.assertTrue(hasattr(IPv4, f'_make_opt_{name}'))

    def test_ipv4_unregistered_option_code_does_not_mutate_the_registry(self) -> None:
        """Parsing must not write to the shared IPv4 option registry.

        :attr:`IPv4.__option__ <pcapkit.protocols.internet.ipv4.IPv4.__option__>`
        is a :class:`collections.defaultdict` on a class attribute shared by
        every instance in the process, so ``registry[code]`` would insert each
        code it missed -- the leak #428 swept out of the sixteen registries that
        already existed. This one is new, so the guard has to be pinned here too:
        the reads go through
        :meth:`~pcapkit.protocols.protocol.ProtocolBase._lookup_registry`.

        Option number 31 is unassigned in IANA's registry and 134 is ``CIPSO``,
        which is assigned but has no parser, so both take the fallback.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema

        registry = IPv4.__dict__['__option__']
        proto = object.__new__(IPv4)

        for code in (OptionNumber.get(31), OptionNumber.CIPSO):
            with self.subTest(code=code):
                before = set(registry)
                self.assertNotIn(code, before)

                proto.__header__ = types.SimpleNamespace(
                    options=[ipv4_schema.UnassignedOption(type=code, length=4,
                                                          data=b'xx')],
                )
                proto._read_ipv4_options(4)
                self.assertEqual(set(registry), before)

                # both constructor branches, since either can leak on its own
                proto._make_ipv4_options([(code, {'data': b'xx'})])
                self.assertEqual(set(registry), before)

                # The OrderedMultiDict branch cannot get as far as building the
                # option: :meth:`IPv4._make_opt_unassigned
                # <pcapkit.protocols.internet.ipv4.IPv4._make_opt_unassigned>`
                # declares ``data`` keyword-only with no default, where every
                # sibling fallback constructor defaults it to ``b''``, so it
                # raises before reading the payload out of ``option.data``. That
                # predates the registry migration and is left alone here; what
                # this asserts is that the *lookup* which runs first still does
                # not insert.
                with self.assertRaises(TypeError):
                    proto._make_ipv4_options(OrderedMultiDict([
                        (code, types.SimpleNamespace(data=b'xx')),
                    ]))
                self.assertEqual(set(registry), before)

                # a leak would make the next genuine registration warn
                with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
                    try:
                        IPv4.register_option(code, 'unassigned')
                        warn.assert_not_called()
                    finally:
                        registry.pop(code, None)

    def test_ipv4_option_constructors_cover_common_and_error_branches(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)

        unknown = proto._make_opt_unassigned(OptionNumber.get(31), data=b'abc')
        self.assertEqual(unknown.to_dict()['length'], 3)
        self.assertEqual(unknown.to_dict()['data'], b'abc')

        self.assertEqual(proto._make_opt_eool(OptionNumber.EOOL).to_dict()['length'], 1)
        self.assertEqual(proto._make_opt_nop(OptionNumber.NOP).to_dict()['length'], 1)

        # ``GENSER`` alone, where this passed
        # ``[GENSER, Field_Termination_Indicator]`` before #537: the expected
        # octets are unchanged, because bit 0 of the last octet is now set by
        # ``_make_opt_sec`` itself rather than by naming the terminator as though
        # it were an authority -- which is what produced the 0x01 here, and what
        # is now rejected.
        sec = proto._make_opt_sec(
            OptionNumber.SEC,
            authorities=[ProtectionAuthority.GENSER],
        )
        self.assertEqual(sec.to_dict()['length'], 4)
        self.assertEqual(sec.to_dict()['data'], b'\x81')

        loose = proto._make_opt_lsr(OptionNumber.LSR, counts=2, route=['192.0.2.1'])
        self.assertEqual(loose.to_dict()['length'], 11)
        self.assertEqual(loose.to_dict()['pointer'], 8)

        ts_only = proto._make_opt_ts(OptionNumber.TS, counts=2,
                                     timestamp=[datetime.timedelta(seconds=1), 2])
        self.assertEqual(ts_only.to_dict()['length'], 12)
        self.assertEqual(ts_only.to_dict()['flags']['flag'], TSFlag.Timestamp_Only)

        ts_with_ip = proto._make_opt_ts(
            OptionNumber.TS,
            counts=2,
            timestamp={
                ip_address('192.0.2.1'): 0,
                ip_address('192.0.2.2'): datetime.timedelta(seconds=3),
            },
        )
        self.assertEqual(ts_with_ip.to_dict()['length'], 20)
        self.assertEqual(ts_with_ip.to_dict()['flags']['flag'], TSFlag.Prespecified_IP_with_Timestamp)

        self.assertEqual(proto._make_opt_e_sec(OptionNumber.E_SEC, format=1,
                                               info=b'info').to_dict()['length'], 7)
        self.assertEqual(proto._make_opt_rr(OptionNumber.RR, counts=2,
                                            route=['192.0.2.1', '192.0.2.2']).to_dict()['pointer'], 12)
        self.assertEqual(proto._make_opt_sid(OptionNumber.SID, sid=123).to_dict()['sid'], 123)
        self.assertEqual(proto._make_opt_ssr(OptionNumber.SSR, counts=2,
                                             route=['192.0.2.1']).to_dict()['pointer'], 8)
        self.assertEqual(proto._make_opt_mtup(OptionNumber.MTUP, mtu=1500).to_dict()['mtu'], 1500)
        self.assertEqual(proto._make_opt_mtur(OptionNumber.MTUR, mtu=1500).to_dict()['mtu'], 1500)
        self.assertEqual(proto._make_opt_tr(OptionNumber.TR, id=1, out=2, ret=3,
                                            origin='192.0.2.9').to_dict()['origin'], '192.0.2.9')
        self.assertEqual(proto._make_opt_rtralt(OptionNumber.RTRALT, alert=0).to_dict()['alert'], 0)

        request = proto._make_opt_qs(OptionNumber.QS, func=QSFunction.Quick_Start_Request,
                                     rate=80, ttl=datetime.timedelta(seconds=7), nonce=3)
        self.assertEqual(request.to_dict()['ttl'], 7)
        self.assertEqual(request.to_dict()['flags']['rate'], 1)

        report = proto._make_opt_qs(OptionNumber.QS, func=QSFunction.Report_of_Approved_Rate,
                                    rate=80, nonce=3)
        self.assertEqual(report.to_dict()['flags']['func'], QSFunction.Report_of_Approved_Rate)

        options, total_length = proto._make_ipv4_options([
            b'\x1fabc',
            (OptionNumber.SID, {'sid': 5}),
            (OptionNumber.NOP, {}),
        ])
        # Four octets of raw option and the four of SID, with the NOP dropped as
        # padding. This read 12 before #534, when SID packed to six octets and so
        # dragged a NOP and an EOOL in behind it; four is already 32-bit aligned,
        # so the alignment branch is not reached here at all any more.
        self.assertEqual(total_length, 8)
        self.assertEqual([type(item).__name__ for item in options],
                         ['bytes', 'SIDOption'])

        # Which is why the alignment branch gets a case of its own rather than
        # riding along on SID's old width. The padding terminator is an EOOL
        # *option*, not the bare wire code, and these assertions pinned the
        # latter -- that is what #506 fixed, and it would have been lost here
        # when SID stopped being a trigger. A SEC option carrying a two-octet
        # bitmap packs to five, so it still is one: three octets of padding, two
        # NOPs and the EOOL.
        padded, padded_length = proto._make_ipv4_options([
            (OptionNumber.SEC, {'authorities': [ProtectionAuthority(8)]}),
        ])
        self.assertEqual(padded_length, 8)
        self.assertEqual([type(item).__name__ for item in padded],
                         ['SECOption', 'NOPOption', 'NOPOption', 'EOOLOption'])
        self.assertEqual(padded[-1].type, OptionNumber.EOOL)

        with self.assertRaises(ProtocolError):
            proto._make_opt_ts(OptionNumber.TS, timestamp=None)
        with self.assertRaises(ProtocolError):
            proto._make_opt_qs(OptionNumber.QS, func=99)

    def test_ipv4_option_constructors_cover_data_model_and_mapping_paths(self) -> None:
        from pcapkit.const.ipv4.classification_level import ClassificationLevel
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.router_alert import RouterAlert
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.data.internet import ipv4 as ipv4_data
        from pcapkit.protocols.internet.ipv4 import IPv4

        proto = object.__new__(IPv4)

        def opt_type(code):
            return proto._read_ipv4_opt_type(code)

        unassigned = ipv4_data.UnassignedOption(
            code=OptionNumber.get(31),
            type=opt_type(OptionNumber.get(31)),
            length=5,
            data=b'abcde',
        )
        self.assertEqual(proto._make_opt_unassigned(
            OptionNumber.get(31),
            unassigned,
            data=b'ignored',
        ).data, b'abcde')

        sec = ipv4_data.SECOption(
            code=OptionNumber.SEC,
            type=opt_type(OptionNumber.SEC),
            length=4,
            level=ClassificationLevel.Unclassified,
            # ``NSA`` where this was ``Field_Termination_Indicator``, which #537
            # now rejects. It is also the more faithful data model: the
            # terminator is structure, and ``_read_opt_sec`` never puts it in
            # ``flags`` in the first place.
            flags=(ProtectionAuthority.GENSER, ProtectionAuthority.NSA),
        )
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC, sec).level,
                         ClassificationLevel.Unclassified)
        self.assertEqual(proto._make_opt_sec(OptionNumber.SEC).data, b'')

        lsr = ipv4_data.LSROption(
            code=OptionNumber.LSR,
            type=opt_type(OptionNumber.LSR),
            length=7,
            pointer=8,
            route=[ip_address('192.0.2.1')],
        )
        rr = ipv4_data.RROption(
            code=OptionNumber.RR,
            type=opt_type(OptionNumber.RR),
            length=11,
            pointer=12,
            route=[ip_address('192.0.2.1'), ip_address('192.0.2.2')],
        )
        ssr = ipv4_data.SSROption(
            code=OptionNumber.SSR,
            type=opt_type(OptionNumber.SSR),
            length=7,
            pointer=8,
            route=[ip_address('192.0.2.3')],
        )
        self.assertEqual(proto._make_opt_lsr(OptionNumber.LSR, lsr).pointer, 8)
        self.assertEqual(proto._make_opt_rr(OptionNumber.RR, rr).pointer, 12)
        self.assertEqual(proto._make_opt_ssr(OptionNumber.SSR, ssr).pointer, 8)

        ts_tuple = ipv4_data.TSOption(
            code=OptionNumber.TS,
            type=opt_type(OptionNumber.TS),
            length=12,
            pointer=12,
            overflow=1,
            flag=TSFlag.Timestamp_Only,
            timestamp=(datetime.timedelta(seconds=1), 0x80000000),
        )
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            ts_schema = proto._make_opt_ts(OptionNumber.TS, ts_tuple)
        self.assertEqual(ts_schema.flags['oflw'], 1)
        warn.assert_called_once()

        ts_map = OrderedMultiDict([
            (ip_address('192.0.2.10'), datetime.timedelta(seconds=2)),
            (ip_address('192.0.2.11'), 0x80000000),
        ])
        ts_prespecified = ipv4_data.TSOption(
            code=OptionNumber.TS,
            type=opt_type(OptionNumber.TS),
            length=20,
            pointer=20,
            overflow=0,
            flag=TSFlag.Prespecified_IP_with_Timestamp,
            timestamp=ts_map,
        )
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            self.assertEqual(proto._make_opt_ts(OptionNumber.TS, ts_prespecified).flags['flag'],
                             TSFlag.Prespecified_IP_with_Timestamp)
        warn.assert_called_once()

        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp=[1, 2])
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp=[0x80000000])
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1, timestamp={
                ip_address('192.0.2.20'): 1,
                ip_address('192.0.2.21'): 2,
            })
        warn.assert_called_once()
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._make_opt_ts(OptionNumber.TS, counts=1,
                               timestamp={ip_address('192.0.2.22'): 0x80000000})
        warn.assert_called_once()

        e_sec = ipv4_data.ESECOption(
            code=OptionNumber.E_SEC,
            type=opt_type(OptionNumber.E_SEC),
            length=7,
            format=1,
            info=b'info',
        )
        sid = ipv4_data.SIDOption(
            code=OptionNumber.SID,
            type=opt_type(OptionNumber.SID),
            length=4,
            sid=123,
        )
        mtup = ipv4_data.MTUPOption(
            code=OptionNumber.MTUP,
            type=opt_type(OptionNumber.MTUP),
            length=4,
            mtu=1500,
        )
        mtur = ipv4_data.MTUROption(
            code=OptionNumber.MTUR,
            type=opt_type(OptionNumber.MTUR),
            length=4,
            mtu=1400,
        )
        tr = ipv4_data.TROption.from_dict({
            'code': OptionNumber.TR,
            'type': opt_type(OptionNumber.TR),
            'length': 12,
            'id': 1,
            'outbound': 2,
            'return': 3,
            'originator': ip_address('192.0.2.30'),
        })
        rtralt = ipv4_data.RTRALTOption(
            code=OptionNumber.RTRALT,
            type=opt_type(OptionNumber.RTRALT),
            length=4,
            alert=RouterAlert.Aggregated_Reservation_Nesting_Level_0,
        )
        self.assertEqual(proto._make_opt_e_sec(OptionNumber.E_SEC, e_sec).info, b'info')
        self.assertEqual(proto._make_opt_sid(OptionNumber.SID, sid).sid, 123)
        self.assertEqual(proto._make_opt_mtup(OptionNumber.MTUP, mtup).mtu, 1500)
        self.assertEqual(proto._make_opt_mtur(OptionNumber.MTUR, mtur).mtu, 1400)
        self.assertEqual(proto._make_opt_tr(OptionNumber.TR, tr).ret, 3)
        self.assertEqual(proto._make_opt_rtralt(OptionNumber.RTRALT, rtralt).alert,
                         RouterAlert.Aggregated_Reservation_Nesting_Level_0)

        qs_request = ipv4_data.QuickStartRequestOption(
            code=OptionNumber.QS,
            type=opt_type(OptionNumber.QS),
            length=8,
            func=QSFunction.Quick_Start_Request,
            rate=80,
            ttl=datetime.timedelta(seconds=7),
            nonce=3,
        )
        self.assertEqual(proto._make_opt_qs(OptionNumber.QS, qs_request).ttl, 7)
        qs_report = ipv4_data.QuickStartReportOption(
            code=OptionNumber.QS,
            type=opt_type(OptionNumber.QS),
            length=8,
            func=QSFunction.Report_of_Approved_Rate,
            rate=80,
            nonce=3,
        )
        self.assertEqual(proto._make_opt_qs(OptionNumber.QS, qs_report).nonce['nonce'], 3)

        schema_options, schema_total = proto._make_ipv4_options([
            bytes([OptionNumber.NOP]),
            proto._make_opt_nop(OptionNumber.NOP),
            proto._make_opt_sid(OptionNumber.SID, sid=9),
        ])
        # Both NOPs are dropped as padding, on the bytes branch and the schema
        # branch respectively, which is what this case is here to cover. Only the
        # SID option survives, and since #534 it is four octets and needs no
        # padding of its own -- this was 8 across 3 entries while the option
        # packed to six and pulled a NOP and an EOOL in after it.
        self.assertEqual(schema_total, 4)
        self.assertEqual(len(schema_options), 1)
        self.assertEqual(schema_options[0].sid, 9)

        option_map = OrderedMultiDict([
            (OptionNumber.NOP, ipv4_data.NOPOption(
                code=OptionNumber.NOP,
                type=opt_type(OptionNumber.NOP),
                length=1,
            )),
            (OptionNumber.SID, sid),
            (OptionNumber.LSR, lsr),
            # A SEC option whose authorities reach into a second bitmap octet, so
            # it packs to five and needs three octets of padding -- two NOPs and
            # the EOOL. Which is what keeps the multi-NOP arm of the alignment
            # branch exercised on this, the data-model path: SID used to reach it
            # by being two octets over-wide (6 % 4 == 2, one NOP), and since #534
            # it is 4-aligned and reaches it not at all.
            (OptionNumber.SEC, ipv4_data.SECOption(
                code=OptionNumber.SEC,
                type=opt_type(OptionNumber.SEC),
                length=5,
                level=ClassificationLevel.Unclassified,
                flags=(ProtectionAuthority.GENSER, ProtectionAuthority(8)),
            )),
            (OptionNumber.MTUP, mtup),
        ])
        mapped_options, mapped_total = proto._make_ipv4_options(option_map)
        # 4 of SID, 8 of LSR and its padding, 8 of SEC and its padding, 4 of
        # MTUP, with the NOP dropped. The SID half of this was 20 before #534,
        # the extra four being the two octets it was over-wide by plus the two of
        # padding they then needed.
        self.assertEqual(mapped_total, 24)
        self.assertEqual(mapped_options[0].sid, 123)
        # As above: the terminator is an EOOL option schema, so look for its type
        # rather than for the wire code itself. See #506.
        self.assertIn(OptionNumber.EOOL, [item.type for item in mapped_options])
        # Two NOPs from the SEC option's three octets of padding, which is the
        # arm that ``for _ in range(pad_len - 1)`` only reaches when pad_len > 1.
        self.assertEqual(
            [item.type for item in mapped_options].count(OptionNumber.NOP), 2)
        self.assertEqual(mapped_options[-1].mtu, 1500)

    def test_ipv4_option_readers_cover_common_and_error_branches(self) -> None:
        from pcapkit.const.ipv4.classification_level import ClassificationLevel
        from pcapkit.const.ipv4.option_class import OptionClass
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.protocols.schema.internet.ipv4 import (
            EOOLOption,
            ESECOption,
            LSROption,
            MTUROption,
            MTUPOption,
            NOPOption,
            QuickStartReportOption,
            QuickStartRequestOption,
            RROption,
            RTRALTOption,
            SECOption,
            SIDOption,
            SSROption,
            TROption,
            TSOption,
            UnassignedOption,
        )
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(IPv4)
        options = OrderedMultiDict()

        def assert_bad(reader, schema) -> None:
            with self.assertRaises(ProtocolError):
                reader(schema, options=options)

        proto._read_fileng = lambda length: b'\xc0\x00\x02\x01'
        self.assertEqual(str(proto._read_ipv4_addr()), '192.0.2.1')

        opt_type = proto._read_ipv4_opt_type(OptionNumber.SEC)
        self.assertTrue(opt_type.change)
        self.assertEqual(opt_type.to_dict()['class'], OptionClass.control)
        self.assertEqual(opt_type.number, 2)

        unknown = proto._read_opt_unassigned(
            UnassignedOption(type=OptionNumber.get(31), length=3, data=b'x'),
            options=options,
        )
        self.assertEqual(unknown.data, b'x')
        self.assertEqual(proto._read_opt_eool(EOOLOption(type=OptionNumber.EOOL),
                                              options=options).length, 1)
        self.assertEqual(proto._read_opt_nop(NOPOption(type=OptionNumber.NOP),
                                             options=options).length, 1)

        sec = proto._read_opt_sec(
            SECOption(type=OptionNumber.SEC, length=4,
                      level=ClassificationLevel.Unclassified, data=b'\x81'),
            options=options,
        )
        self.assertEqual(sec.level, ClassificationLevel.Unclassified)
        self.assertEqual(sec.flags, (ProtectionAuthority.GENSER,))
        self.assertEqual(proto._read_opt_sec(
            SECOption(type=OptionNumber.SEC, length=3,
                      level=ClassificationLevel.Unclassified, data=b''),
            options=options,
        ).flags, ())
        with mock.patch('pcapkit.protocols.internet.ipv4.warn') as warn:
            proto._read_opt_sec(
                SECOption(type=OptionNumber.SEC, length=5,
                          level=ClassificationLevel.Unclassified,
                          data=b'\x05\x00'),
                options=options,
            )
        self.assertEqual(warn.call_count, 3)

        lsr = proto._read_opt_lsr(
            LSROption(type=OptionNumber.LSR, length=7, pointer=8,
                      route=[ip_address('192.0.2.1')]),
            options=options,
        )
        self.assertEqual([str(route) for route in lsr.route], ['192.0.2.1'])

        ts_schema = TSOption(type=OptionNumber.TS, length=12, pointer=12,
                             flags={'oflw': 0, 'flag': TSFlag.Timestamp_Only},
                             ts_data=[1000, 2000])
        object.__setattr__(ts_schema, 'ts_flag', TSFlag.Timestamp_Only)
        object.__setattr__(ts_schema, 'timestamp', (
            datetime.timedelta(seconds=1),
            datetime.timedelta(seconds=2),
        ))
        ts = proto._read_opt_ts(ts_schema, options=options)
        self.assertEqual(ts.flag, TSFlag.Timestamp_Only)
        self.assertEqual(ts.timestamp[0], datetime.timedelta(seconds=1))

        e_sec = proto._read_opt_e_sec(
            ESECOption(type=OptionNumber.E_SEC, length=7, format=1, info=b'info'),
            options=options,
        )
        self.assertEqual(e_sec.info, b'info')

        rr = proto._read_opt_rr(
            RROption(type=OptionNumber.RR, length=11, pointer=12,
                     route=[ip_address('192.0.2.1'), ip_address('192.0.2.2')]),
            options=options,
        )
        self.assertEqual(len(rr.route), 2)
        self.assertEqual(proto._read_opt_sid(SIDOption(type=OptionNumber.SID, length=4, sid=123),
                                             options=options).sid, 123)

        ssr = proto._read_opt_ssr(
            SSROption(type=OptionNumber.SSR, length=7, pointer=8,
                      route=[ip_address('192.0.2.1')]),
            options=options,
        )
        self.assertEqual([str(route) for route in ssr.route], ['192.0.2.1'])
        self.assertEqual(proto._read_opt_mtup(MTUPOption(type=OptionNumber.MTUP, length=4,
                                                         mtu=1500), options=options).mtu, 1500)
        self.assertEqual(proto._read_opt_mtur(MTUROption(type=OptionNumber.MTUR, length=4,
                                                         mtu=1400), options=options).mtu, 1400)
        tr = proto._read_opt_tr(
            TROption(type=OptionNumber.TR, length=12, id=1, out=2, ret=3,
                     origin=ip_address('192.0.2.9')),
            options=options,
        )
        self.assertEqual(tr.to_dict()['return'], 3)
        self.assertEqual(str(tr.originator), '192.0.2.9')
        self.assertEqual(proto._read_opt_rtralt(RTRALTOption(type=OptionNumber.RTRALT,
                                                             length=4, alert=0),
                                                options=options).alert, 0)

        qs_request = QuickStartRequestOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_request, 'func', QSFunction.Quick_Start_Request)
        qs_req = proto._read_opt_qs(qs_request, options=options)
        self.assertEqual(qs_req.rate, 80.0)
        self.assertEqual(qs_req.ttl, datetime.timedelta(seconds=7))

        qs_report = QuickStartReportOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Report_of_Approved_Rate, 'rate': 1},
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_report, 'func', QSFunction.Report_of_Approved_Rate)
        qs_rep = proto._read_opt_qs(qs_report, options=options)
        self.assertEqual(qs_rep.rate, 80.0)
        self.assertEqual(qs_rep.nonce, 3)

        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_opt_sid(OptionNumber.SID, sid=5),
            proto._make_opt_nop(OptionNumber.NOP),
            proto._make_opt_eool(OptionNumber.EOOL),
            proto._make_opt_mtup(OptionNumber.MTUP, mtu=1500),
        ])
        parsed = proto._read_ipv4_options(6)
        self.assertEqual(list(parsed.keys()), [OptionNumber.SID, OptionNumber.NOP, OptionNumber.EOOL])
        self.assertEqual(list(parsed.values())[0].sid, 5)
        proto.__header__ = types.SimpleNamespace(options=[
            proto._make_opt_sid(OptionNumber.SID, sid=6),
        ])
        parsed_without_eool = proto._read_ipv4_options(4)
        self.assertEqual(parsed_without_eool[OptionNumber.SID].sid, 6)
        with self.assertRaises(ProtocolError):
            proto._read_ipv4_options(3)

        assert_bad(proto._read_opt_unassigned, UnassignedOption(type=OptionNumber.get(31),
                                                               length=2, data=b''))
        assert_bad(proto._read_opt_sec, SECOption(type=OptionNumber.SEC, length=2,
                                                  level=ClassificationLevel.Unclassified,
                                                  data=b''))
        assert_bad(proto._read_opt_lsr, LSROption(type=OptionNumber.LSR, length=6,
                                                  pointer=8, route=[]))
        assert_bad(proto._read_opt_lsr, LSROption(type=OptionNumber.LSR, length=7,
                                                  pointer=3, route=[]))
        assert_bad(proto._read_opt_ts, TSOption(type=OptionNumber.TS, length=41,
                                                pointer=12, flags={'oflw': 0,
                                                                   'flag': TSFlag.Timestamp_Only},
                                                ts_data=[]))
        assert_bad(proto._read_opt_ts, TSOption(type=OptionNumber.TS, length=12,
                                                pointer=4, flags={'oflw': 0,
                                                                  'flag': TSFlag.Timestamp_Only},
                                                ts_data=[]))
        assert_bad(proto._read_opt_e_sec, ESECOption(type=OptionNumber.E_SEC,
                                                     length=2, format=1, info=b''))
        assert_bad(proto._read_opt_rr, RROption(type=OptionNumber.RR, length=6,
                                                pointer=8, route=[]))
        assert_bad(proto._read_opt_rr, RROption(type=OptionNumber.RR, length=7,
                                                pointer=3, route=[]))
        assert_bad(proto._read_opt_sid, SIDOption(type=OptionNumber.SID, length=3, sid=123))
        assert_bad(proto._read_opt_ssr, SSROption(type=OptionNumber.SSR, length=6,
                                                  pointer=8, route=[]))
        assert_bad(proto._read_opt_ssr, SSROption(type=OptionNumber.SSR, length=7,
                                                  pointer=3, route=[]))
        assert_bad(proto._read_opt_mtup, MTUPOption(type=OptionNumber.MTUP, length=3,
                                                    mtu=1500))
        assert_bad(proto._read_opt_mtur, MTUROption(type=OptionNumber.MTUR, length=3,
                                                    mtu=1500))
        assert_bad(proto._read_opt_tr, TROption(type=OptionNumber.TR, length=11,
                                                id=1, out=2, ret=3,
                                                origin=ip_address('192.0.2.9')))
        assert_bad(proto._read_opt_rtralt, RTRALTOption(type=OptionNumber.RTRALT,
                                                        length=3, alert=0))
        assert_bad(proto._read_opt_qs, QuickStartRequestOption(
            type=OptionNumber.QS,
            length=7,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        ))
        qs_unknown = QuickStartRequestOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Quick_Start_Request, 'rate': 1},
            ttl=7,
            nonce={'nonce': 3},
        )
        object.__setattr__(qs_unknown, 'func', QSFunction.get(1))
        assert_bad(proto._read_opt_qs, qs_unknown)

    def test_ipv4_schema_helpers_and_post_process_branches(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.qs_function import QSFunction
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.schema.internet import ipv4 as ipv4_schema
        from pcapkit.utilities.exceptions import FieldValueError

        eool = ipv4_schema.EOOLOption(type=OptionNumber.EOOL, length=99)
        self.assertEqual(eool.post_process({}).length, 1)
        nop = ipv4_schema.NOPOption(type=OptionNumber.NOP, length=99)
        self.assertEqual(nop.post_process({}).length, 1)
        custom = ipv4_schema.UnassignedOption(type=OptionNumber.get(31), length=3, data=b'x')
        self.assertEqual(custom.post_process({}).length, 3)

        packet = {'flags': {'func': QSFunction.Quick_Start_Request.value}}
        request_field = ipv4_schema.quick_start_data_selector(packet)
        self.assertIs(request_field.schema, ipv4_schema.QuickStartRequestOption)
        self.assertIs(packet['flags']['func'], QSFunction.Quick_Start_Request)

        report_field = ipv4_schema.quick_start_data_selector({
            'flags': {'func': QSFunction.Report_of_Approved_Rate.value},
        })
        self.assertIs(report_field.schema, ipv4_schema.QuickStartReportOption)
        with self.assertRaises(FieldValueError):
            ipv4_schema.quick_start_data_selector({'flags': {'func': 1}})

        wrapped_qs = ipv4_schema.QuickStartReportOption(
            type=OptionNumber.QS,
            length=8,
            flags={'func': QSFunction.Report_of_Approved_Rate, 'rate': 1},
            nonce={'nonce': 7},
        )
        wrapper = object.__new__(ipv4_schema._QSOption)
        object.__setattr__(wrapper, 'data', wrapped_qs)
        object.__setattr__(wrapper, 'flags', {'func': QSFunction.Report_of_Approved_Rate.value})
        processed = ipv4_schema._QSOption.post_process(wrapper, {})
        self.assertIs(processed, wrapped_qs)
        self.assertIs(processed.func, QSFunction.Report_of_Approved_Rate)

        ts_only = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=12,
            pointer=13,
            flags={'oflw': 0, 'flag': TSFlag.Timestamp_Only},
            ts_data=[1000, 0x80000005],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            ts_only.post_process({})
        self.assertEqual(ts_only.ts_flag, TSFlag.Timestamp_Only)
        self.assertEqual(ts_only.data, [1000, 0x80000005])
        self.assertEqual(ts_only.timestamp[0], datetime.timedelta(seconds=1))
        self.assertEqual(ts_only.timestamp[1], 5)
        warn.assert_called_once()

        ip_ts = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=20,
            pointer=21,
            flags={'oflw': 0, 'flag': TSFlag.IP_with_Timestamp},
            ts_data=[
                int(ip_address('192.0.2.1')),
                2000,
                int(ip_address('192.0.2.4')),
                0x80000007,
            ],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            ip_ts.post_process({})
        self.assertIsInstance(ip_ts.data, OrderedMultiDict)
        self.assertEqual(ip_ts.timestamp[ip_address('192.0.2.1')],
                         datetime.timedelta(seconds=2))
        self.assertEqual(ip_ts.timestamp[ip_address('192.0.2.4')], 7)
        warn.assert_called_once()

        pre_ts = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=20,
            pointer=21,
            flags={'oflw': 0, 'flag': TSFlag.Prespecified_IP_with_Timestamp},
            ts_data=[
                int(ip_address('192.0.2.2')),
                0x80000006,
                int(ip_address('192.0.2.5')),
                3000,
            ],
        )
        pre_ts.remainder = ip_address('192.0.2.3').packed + b'\x00\x00\x00\x00'
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            pre_ts.post_process({})
        self.assertEqual(pre_ts.timestamp[ip_address('192.0.2.2')], 6)
        self.assertEqual(pre_ts.timestamp[ip_address('192.0.2.5')],
                         datetime.timedelta(seconds=3))
        self.assertEqual(pre_ts.data[ip_address('192.0.2.3')], 0)
        warn.assert_called_once()

        unknown = ipv4_schema.TSOption(
            type=OptionNumber.TS,
            length=8,
            pointer=9,
            flags={'oflw': 0, 'flag': 2},
            ts_data=[1],
        )
        with mock.patch('pcapkit.protocols.schema.internet.ipv4.warn') as warn:
            unknown.post_process({})
        self.assertEqual(tuple(unknown.timestamp), (1,))
        warn.assert_called_once()

    def test_an_option_area_longer_than_the_datagram_still_parses(self) -> None:
        """An ``ihl`` promising more options than are there is tolerated.

        The header below sets ``ihl`` to 10 -- a 20-octet option area -- and stops
        after the fixed 20 octets, so there are no option octets at all. Reading
        past them yields ``b''``, which decodes the option number as 0, and 0 is
        IPv4's end-of-option-list, so the option loop breaks there and reports the
        whole area as padding. That is how a datagram cut short by the snapshot
        length parses at all, and it is why :meth:`OptionField.unpack
        <pcapkit.corekit.fields.collections.OptionField.unpack>` checks each
        option's progress *after* its end-of-option-list break rather than before:
        checking first turns every such header into an error. C.f. #431.

        """
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4
        from tests._support import time_limit

        raw = bytes.fromhex('4a00001800010000400600000a0000010a000002')
        with time_limit(5):
            proto = IPv4(raw, len(raw))

        self.assertEqual(proto.info.hdr_len, 40)
        self.assertEqual(
            [(code, opt.length) for code, opt in proto.info.options.items(multi=True)],
            [(OptionNumber.EOOL, 1)],
        )


if __name__ == '__main__':
    unittest.main()
