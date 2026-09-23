from __future__ import annotations

import importlib.util
import ipaddress
import unittest

from tests._support import purge_modules

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: Prefix lengths whose octet happens to be an ASCII digit, i.e. ``0x30``--``0x39``.
#: :meth:`IPv6InterfaceField.post_process` used to read the octet as an ASCII
#: decimal string, so these were the only prefix lengths that parsed at all --
#: and every one of them decoded to ``prefixlen - 48``. Every other prefix length,
#: including all the common ones, raised :exc:`ValueError`.
ASCII_DIGIT_PREFIX_LENGTHS = tuple(range(48, 58))

#: Section 4.2 of the PCAP-NG specification: ``if_IPv6addr`` is 17 octets, of
#: which the first 16 are the address and the 17th is the prefix length, so
#: ``2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64`` is written with a trailing ``40``.
SPEC_INTERFACE = '2001:0db8:85a3:08d3:1319:8a2e:0370:7344/64'
SPEC_ENCODING = bytes.fromhex('2001 0db8 85a3 08d3 1319 8a2e 0370 7344 40'.replace(' ', ''))


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class IPAddressFieldTests(unittest.TestCase):
    def setUp(self) -> None:
        purge_modules(['pcapkit'])

    def test_address_fields_round_trip_and_reject_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
        from pcapkit.utilities.exceptions import FieldValueError

        ipv4 = IPv4AddressField()
        self.assertEqual(ipv4.length, 4)
        self.assertEqual(ipv4.unpack(ipv4.pack(ipaddress.ip_address('192.0.2.1'), {}), {}),
                         ipaddress.ip_address('192.0.2.1'))

        ipv6 = IPv6AddressField()
        self.assertEqual(ipv6.length, 16)
        self.assertEqual(ipv6.unpack(ipv6.pack(ipaddress.ip_address('2001:db8::1'), {}), {}),
                         ipaddress.ip_address('2001:db8::1'))

        with self.assertRaises(FieldValueError):
            ipv4.pre_process('2001:db8::1', {})
        with self.assertRaises(FieldValueError):
            ipv6.pre_process('192.0.2.1', {})

    def test_ipv6_interface_round_trips_every_prefix_length(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        self.assertEqual(field.length, 17)

        for prefixlen in range(129):
            interface = ipaddress.ip_interface(f'2001:db8:85a3:8d3:1319:8a2e:370:7344/{prefixlen}')
            raw = field.pack(interface, {})

            self.assertEqual(len(raw), 17, msg=f'/{prefixlen} packed to {len(raw)} octets')
            self.assertEqual(raw[:16], interface.ip.packed,
                             msg=f'/{prefixlen} packed the wrong address')
            self.assertEqual(raw[16], prefixlen,
                             msg=f'/{prefixlen} wrote prefix length octet {raw[16]:#04x}')
            self.assertEqual(field.unpack(raw, {}), interface,
                             msg=f'/{prefixlen} did not survive the round trip')

    def test_ipv6_interface_prefix_length_octet_matches_specification(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        interface = ipaddress.ip_interface(SPEC_INTERFACE)

        self.assertEqual(field.pack(interface, {}), SPEC_ENCODING)
        self.assertEqual(field.unpack(SPEC_ENCODING, {}), interface)
        self.assertEqual(field.unpack(SPEC_ENCODING, {}).network.prefixlen, 64)

    def test_ipv6_interface_does_not_read_prefix_length_octet_as_an_ascii_digit(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField

        field = IPv6InterfaceField()
        for prefixlen in ASCII_DIGIT_PREFIX_LENGTHS:
            with self.subTest(prefixlen=prefixlen):
                interface = ipaddress.ip_interface(f'2001:db8::1/{prefixlen}')
                raw = field.pack(interface, {})

                # the octet really is an ASCII digit, which is why these ten used
                # to parse while every other prefix length raised
                self.assertIn(raw[16:], [str(digit).encode() for digit in range(10)])

                parsed = field.unpack(raw, {})
                self.assertEqual(parsed, interface)
                self.assertEqual(parsed.network.prefixlen, prefixlen)
                # the old ASCII reading decoded /48../57 as /0../9
                self.assertNotEqual(parsed.network.prefixlen, prefixlen - 48)

    def test_ipv6_interface_rejects_out_of_range_prefix_length(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        field = IPv6InterfaceField()
        address = ipaddress.IPv6Address('2001:db8::1').packed

        for prefixlen in (129, 200, 255):
            with self.subTest(prefixlen=prefixlen):
                with self.assertRaises(FieldValueError) as context:
                    field.unpack(address + bytes([prefixlen]), {})
                self.assertIn(str(prefixlen), str(context.exception))

    def test_ipv6_interface_rejects_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv6InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            IPv6InterfaceField().pre_process('192.0.2.1/24', {})

    def test_ipv4_interface_round_trips_every_prefix_length_as_a_netmask(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        self.assertEqual(field.length, 8)

        for prefixlen in range(33):
            interface = ipaddress.ip_interface(f'192.0.2.1/{prefixlen}')
            raw = field.pack(interface, {})

            self.assertEqual(len(raw), 8, msg=f'/{prefixlen} packed to {len(raw)} octets')
            self.assertEqual(raw[:4], interface.ip.packed,
                             msg=f'/{prefixlen} packed the wrong address')
            # the IPv4 option carries a dotted netmask, not a prefix length --
            # the two interface fields are deliberately not interchangeable
            self.assertEqual(raw[4:], interface.netmask.packed,
                             msg=f'/{prefixlen} wrote {raw[4:].hex()} instead of a netmask')
            self.assertEqual(field.unpack(raw, {}), interface,
                             msg=f'/{prefixlen} did not survive the round trip')

    def test_interface_field_encodings_are_not_interchangeable(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField, IPv6InterfaceField

        ipv4 = IPv4InterfaceField().pack(ipaddress.ip_interface('192.0.2.1/24'), {})
        ipv6 = IPv6InterfaceField().pack(ipaddress.ip_interface('2001:db8::1/24'), {})

        # /24 as four netmask octets on one side, as a single binary octet on the other
        self.assertEqual(ipv4[4:], b'\xff\xff\xff\x00')
        self.assertEqual(ipv6[16:], b'\x18')

    def test_ipv4_interface_rejects_the_other_version(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError):
            IPv4InterfaceField().pre_process('2001:db8::1/64', {})

    def test_pre_process_malformed_value_raises_in_library_error(self) -> None:
        """A malformed address/interface string used to let a bare
        :exc:`ValueError` from :mod:`ipaddress` escape -- unlike the very next
        statement in the same method, which already raised the library's own
        :exc:`FieldValueError` for a value that is merely the wrong IP
        version. So ``except BaseError`` could not reliably catch a bad field
        value: whether the exception was in-library depended on *how* the
        value was wrong. All four public field classes must now raise
        :exc:`FieldValueError` here too, with the original :mod:`ipaddress`
        message preserved.
        """
        from pcapkit.corekit.fields.ipaddress import (
            IPv4AddressField, IPv6AddressField, IPv4InterfaceField, IPv6InterfaceField,
        )
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        cases = [
            (IPv4AddressField(), 'not-an-address'),
            (IPv6AddressField(), 'not-an-address'),
            (IPv4InterfaceField(), 'not-an-interface'),
            (IPv6InterfaceField(), 'not-an-interface'),
        ]
        for field, bad_value in cases:
            with self.subTest(field=type(field).__name__):
                with self.assertRaises(FieldValueError) as context:
                    field.pre_process(bad_value, {})
                # ``FieldValueError`` subclasses ``BaseError``, but assert the
                # in-library type directly (above) rather than only this.
                self.assertIsInstance(context.exception, BaseError)
                # the original stdlib ``ipaddress`` message must survive the
                # translation, not just some generic replacement text
                self.assertIn(repr(bad_value), str(context.exception))

    def test_wrong_version_message_is_not_relabelled_as_a_malformed_value(self) -> None:
        """Wrapping the conversion must not broaden into swallowing the
        pre-existing wrong-version ``FieldValueError`` -- its message stays
        the version-mismatch message, not the "invalid IP ..." message used
        for a genuinely malformed value.
        """
        from pcapkit.corekit.fields.ipaddress import IPv6AddressField, IPv6InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaises(FieldValueError) as address_context:
            IPv6AddressField().pre_process(ipaddress.IPv4Address('1.2.3.4'), {})
        self.assertIn('IP version mismatch', str(address_context.exception))
        self.assertNotIn('invalid IP', str(address_context.exception))

        with self.assertRaises(FieldValueError) as interface_context:
            IPv6InterfaceField().pre_process(ipaddress.IPv4Interface('1.2.3.4/24'), {})
        self.assertIn('IP version mismatch', str(interface_context.exception))
        self.assertNotIn('invalid IP', str(interface_context.exception))

    def test_address_and_interface_fields_reject_a_bool_value_for_every_version(self) -> None:
        """A :obj:`bool` value must not be silently accepted as an IP address.

        :obj:`bool` is an :class:`int` subclass, and :func:`ipaddress.ip_address`/
        :func:`ipaddress.ip_interface` both treat any :class:`int` below
        ``2**32`` as IPv4 -- so before this fix, ``True``/``False`` were
        silently converted to ``0.0.0.1``/``0.0.0.0`` (or the equivalent
        interface) on an IPv4-typed field, with no exception and no warning.
        On an IPv6-typed field the same conversion happened to raise instead,
        because the resulting :class:`~ipaddress.IPv4Address`'s version
        mismatched -- and that asymmetry is exactly what let this survive
        #481, which fixed the identical mechanism at only one call site
        (``MH._make_opt_mn_id``). See #491.

        Sweeps ``{True, False}`` across both address and interface field
        types, for both IPv4 and IPv6, since the asymmetry above is exactly
        what a partial sweep would miss.
        """
        from pcapkit.corekit.fields.ipaddress import (
            IPv4AddressField, IPv4InterfaceField, IPv6AddressField, IPv6InterfaceField,
        )
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        fields = [
            IPv4AddressField(),
            IPv6AddressField(),
            IPv4InterfaceField(),
            IPv6InterfaceField(),
        ]

        for field in fields:
            for value in (True, False):
                with self.subTest(field=type(field).__name__, value=value):
                    with self.assertRaises(FieldValueError) as context:
                        field.pre_process(value, {})
                    # ``FieldValueError`` subclasses ``BaseError``, but assert
                    # the in-library type directly (above) rather than only this.
                    self.assertIsInstance(context.exception, BaseError)
                    self.assertIn('must not be a bool', str(context.exception))
                    self.assertIn(repr(value), str(context.exception))
                    # the escape hatch the message points at must actually work
                    self.assertIn(f'int({value!r})', str(context.exception))

        # the escape hatch: int(True)/int(False) still convert correctly,
        # proving this tightens bool specifically rather than int generally
        self.assertEqual(fields[0].pre_process(int(True), {}), b'\x00\x00\x00\x01')
        self.assertEqual(fields[0].pre_process(int(False), {}), b'\x00\x00\x00\x00')

    def test_ipv4_make_rejects_a_bool_address_through_the_public_api(self) -> None:
        """The corruption reported in #491, reproduced through the public API.

        Before this fix, ``IPv4.make(src=True, dst=False)`` packed and
        decoded without any exception or warning, silently corrupting the
        addresses to ``0.0.0.1``/``0.0.0.0``. It must now raise instead.
        """
        from pcapkit.protocols.internet.ipv4 import IPv4
        from pcapkit.utilities.exceptions import BaseError

        proto = object.__new__(IPv4)
        with self.assertRaises(BaseError):
            proto.make(src=True, dst=False).pack()

    def test_parse_ip_address_rejects_a_bool_before_converting_it(self) -> None:
        """:func:`parse_ip_address` is where the construction path meets #500's guard.

        Guarding the field classes is necessary but not sufficient. A ``_make_*``
        that has to know the address *family* before it can build the schema --
        because the option length is the only thing on the wire that carries the
        family -- must convert its argument itself, and that conversion runs
        *before* the schema. A bare :func:`ipaddress.ip_address` therefore turns
        ``True`` into an ordinary :class:`~ipaddress.IPv4Address` that
        :meth:`_IPAddressField.pre_process` can only see as a legitimate address,
        which is what #508 turned out to be. This function is the one place those
        callers convert, so it is the one place the guard has to hold.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        # the bool rejection holds for every family the callers ask for, since
        # the version argument selects a *different* stdlib constructor
        for version in (None, 4, 6):
            for value in (True, False):
                with self.subTest(version=version, value=value):
                    with self.assertRaises(FieldValueError) as context:
                        parse_ip_address(value, 'invalid address', version)
                    self.assertIsInstance(context.exception, BaseError)
                    self.assertIn('invalid address', str(context.exception))
                    self.assertIn('must not be a bool', str(context.exception))
                    self.assertIn(f'int({value!r})', str(context.exception))

        # the escape hatch the message points at, and the widening that makes the
        # version argument necessary: 1 is 0.0.0.1 unqualified but ::1 for IPv6
        self.assertEqual(parse_ip_address(int(True), 'x'), ipaddress.IPv4Address('0.0.0.1'))
        self.assertEqual(parse_ip_address(int(True), 'x', 6), ipaddress.IPv6Address('::1'))
        self.assertEqual(parse_ip_address(0x102, 'x', 6), ipaddress.IPv6Address('::102'))
        self.assertEqual(parse_ip_address(0x102, 'x'), ipaddress.IPv4Address('0.0.1.2'))

        # every other accepted form is passed through untouched
        self.assertEqual(parse_ip_address('198.51.100.7', 'x'),
                         ipaddress.IPv4Address('198.51.100.7'))
        self.assertEqual(parse_ip_address(b'\xc6\x33\x64\x07', 'x'),
                         ipaddress.IPv4Address('198.51.100.7'))
        self.assertEqual(parse_ip_address(ipaddress.IPv6Address('2001:db8::1'), 'x'),
                         ipaddress.IPv6Address('2001:db8::1'))

    def test_parse_ip_address_version_check_survives_the_passthrough_branch(self) -> None:
        """An already-converted address skips the conversion, so it needs its own check.

        ``IPv6Address(IPv4Address(...))`` would have raised, but returning an
        :mod:`ipaddress` object unchanged cannot -- so the version check has to
        sit after the branch rather than inside the conversion it guards.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        with self.assertRaises(FieldValueError) as context:
            parse_ip_address(ipaddress.IPv4Address('198.51.100.7'), 'invalid locator', 6)
        self.assertIsInstance(context.exception, BaseError)
        self.assertIn('IP version mismatch: 4 != 6', str(context.exception))

        with self.assertRaises(FieldValueError) as context:
            parse_ip_address('2001:db8::1', 'invalid locator', 4)
        self.assertIsInstance(context.exception, BaseError)

    def test_parse_ip_address_malformed_value_raises_in_library_error(self) -> None:
        """A malformed value must not leak :mod:`ipaddress`'s bare :exc:`ValueError`.

        The construction-path callers used to let it out verbatim -- e.g.
        ``MH._make_opt_bid(address='nonsense')`` raised a plain
        :exc:`ValueError`, which ``except BaseError`` cannot catch.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        for value in ('nonsense', b'\x00' * 3, None, 1 << 200, -1):
            with self.subTest(value=value):
                with self.assertRaises(FieldValueError) as context:
                    parse_ip_address(value, 'invalid address')  # type: ignore[arg-type]
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn('invalid address', str(context.exception))

    def test_parse_ip_address_pins_the_family_when_version_is_given(self) -> None:
        """``version=4`` and ``version=6`` each select a *different* stdlib constructor.

        Worth stating on its own because **no caller passes ``version=4`` today** --
        only the HIP locator passes a version at all, and it passes ``6`` -- so
        nothing else in the suite pins what ``version=4`` does. An unexercised
        parameter is one that can be broken without a failure, and the widening it
        controls is the whole reason the parameter exists.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address

        # the same int is a different address in each family
        self.assertEqual(parse_ip_address(0x102, 'x', 4), ipaddress.IPv4Address('0.0.1.2'))
        self.assertEqual(parse_ip_address(0x102, 'x', 6), ipaddress.IPv6Address('::102'))
        self.assertEqual(parse_ip_address(0x102, 'x'), ipaddress.IPv4Address('0.0.1.2'))

        # every other accepted form, with the family pinned
        for version, text, packed in [
            (4, '198.51.100.7', b'\xc6\x33\x64\x07'),
            (6, '2001:db8::1', bytes.fromhex('20010db8' + '00' * 10 + '0001')),
        ]:
            with self.subTest(version=version):
                expected = ipaddress.ip_address(text)
                self.assertEqual(parse_ip_address(text, 'x', version), expected)
                self.assertEqual(parse_ip_address(packed, 'x', version), expected)
                self.assertEqual(parse_ip_address(expected, 'x', version), expected)
                self.assertEqual(parse_ip_address(int(expected), 'x', version), expected)

    def test_parse_ip_address_version_mismatch_is_reported_both_ways_round(self) -> None:
        """A ``version=4`` demand must refuse an IPv6 value, not only the reverse.

        The passthrough branch returns the object untouched, so the check after it
        is the only thing that can catch either direction -- and a check written for
        one direction only would still pass a test that exercises one direction only.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        cases = [
            (ipaddress.IPv6Address('2001:db8::1'), 4, 'IP version mismatch: 6 != 4'),
            (ipaddress.IPv4Address('198.51.100.7'), 6, 'IP version mismatch: 4 != 6'),
        ]
        for value, version, message in cases:
            with self.subTest(value=value, version=version):
                with self.assertRaises(FieldValueError) as context:
                    parse_ip_address(value, 'invalid locator', version)
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn(message, str(context.exception))
                self.assertIn('invalid locator', str(context.exception))

        # a *string* of the wrong family fails inside the conversion instead, so it
        # carries ipaddress's own wording rather than the version-mismatch wording,
        # and is still an in-library error
        for value, version in [('2001:db8::1', 4), ('198.51.100.7', 6)]:
            with self.subTest(value=value, version=version):
                with self.assertRaises(FieldValueError) as context:
                    parse_ip_address(value, 'invalid locator', version)
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn('invalid locator', str(context.exception))

    def test_parse_ip_address_rejects_an_out_of_range_int_for_the_pinned_family(self) -> None:
        """``version`` narrows what an :class:`int` may be, and the error stays in-library.

        ``2**32`` is a perfectly good IPv6 address and not an IPv4 one, so the bound
        moves with ``version`` -- and :class:`ipaddress.AddressValueError`, a bare
        :exc:`ValueError`, must not escape either way.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        self.assertEqual(parse_ip_address(1 << 32, 'x', 6),
                         ipaddress.IPv6Address('::1:0:0'))

        for value, version in [(1 << 32, 4), (1 << 128, 6), (-1, 4), (-1, 6)]:
            with self.subTest(value=value, version=version):
                with self.assertRaises(FieldValueError) as context:
                    parse_ip_address(value, 'invalid address', version)
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn('invalid address', str(context.exception))

    def test_parse_ip_address_returns_an_ipaddress_object_unchanged(self) -> None:
        """The passthrough branch returns the *same object*, not a copy of it.

        The makers assign the result straight into the schema attribute, so this is
        what lets ``address=IPv6Address(...)`` round-trip identically rather than
        through a re-conversion that could normalise it.
        """
        from pcapkit.corekit.fields.ipaddress import parse_ip_address

        for value in (ipaddress.IPv4Address('198.51.100.7'),
                      ipaddress.IPv6Address('2001:db8::1')):
            with self.subTest(value=value):
                self.assertIs(parse_ip_address(value, 'x'), value)
                self.assertIs(parse_ip_address(value, 'x', value.version), value)

        # and a 16-octet bytes value is IPv6 without being told so
        self.assertEqual(parse_ip_address(bytes.fromhex('20010db8' + '00' * 10 + '0001'), 'x'),
                         ipaddress.IPv6Address('2001:db8::1'))

    def test_both_bool_guards_stay_catchable_as_value_error_and_as_base_error(self) -> None:
        """The two exception classes used for this mistake are interchangeable to callers.

        #508's seven sites answer with :exc:`FieldValueError`, because the rejection
        happens in a field-level conversion; the two older hand-rolled guards for
        the same mistake -- ``MH._make_opt_mn_id`` from #481 and ESP's
        ``SecurityAssociation`` from #491 -- answer with
        :exc:`~pcapkit.utilities.exceptions.ProtocolError`, because they answer for
        the option rather than for a field. That inconsistency is deliberate and
        safe *only* because both classes derive from
        :exc:`~pcapkit.utilities.exceptions.BaseError` and from :exc:`ValueError`,
        so neither documented handler can tell them apart. This pins that, since it
        is the whole basis for leaving the two alone.

        It also pins the compatibility half of #508's two deliberate behaviour
        changes: ``_make_opt_bid(address='nonsense')`` and the HIP locator's
        wrong-family case used to raise a **bare** :exc:`ValueError`, so they were
        catchable by ``except ValueError`` and not by ``except BaseError``. They are
        now catchable by both -- a widening, not a break.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.mh.mn_id_subtype import MNIDSubtype
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import (BaseError, FieldValueError,
                                                  ProtocolError)

        mh = object.__new__(MH)
        hip = object.__new__(HIP)

        cases = [
            # (label, callable, expected class)
            ('mh bid, malformed address -- was a bare ValueError',
             lambda: mh._make_opt_bid(Option.Binding_Identifier,  # type: ignore[arg-type]
                                      bid=1, address='nonsense'),
             FieldValueError),
            ('hip locator, IPv4 into a v6-only locator -- was AddressValueError',
             lambda: hip._make_param_locator_set(  # type: ignore[arg-type]
                 Parameter.LOCATOR_SET, version=2,
                 locator_set=[{'ip': ipaddress.IPv4Address('198.51.100.7')}]),
             FieldValueError),
            ('mh bid, bool -- #508 site',
             lambda: mh._make_opt_bid(Option.Binding_Identifier,  # type: ignore[arg-type]
                                      bid=1, address=True),
             FieldValueError),
            ('mh mn_id, bool -- #481 guard, kept as ProtocolError',
             lambda: mh._make_opt_mn_id(  # type: ignore[arg-type]
                 Option.MN_ID_OPTION_TYPE, subtype=MNIDSubtype.IPv6_Address,
                 identifier=True),
             ProtocolError),
        ]

        for label, make, expected in cases:
            with self.subTest(case=label):
                with self.assertRaises(expected) as context:
                    make()
                # the two handlers the library documents both work, either way round
                self.assertIsInstance(context.exception, BaseError)
                self.assertIsInstance(context.exception, ValueError)

        # stated as the property rather than only per case, so a future change to
        # either class's bases fails here rather than at some caller
        for cls in (FieldValueError, ProtocolError):
            with self.subTest(cls=cls.__name__):
                self.assertTrue(issubclass(cls, BaseError))
                self.assertTrue(issubclass(cls, ValueError))

    def test_switch_backed_address_makers_reject_a_bool(self) -> None:
        """#508's remaining sites, for the two protocols outside :mod:`~pcapkit.protocols.internet.mh`.

        ``HIP``'s locator and ``TCP``'s Multipath ``ADD_ADDR`` address are both
        backed by a :class:`~pcapkit.corekit.fields.misc.SwitchField`, and both
        makers derive the wire form from the address family before the schema
        exists. Measured before the fix: ``ip=True`` packed a locator of ``::1``
        with no error at all, and ``addr=True`` gave
        ``MPTCPAddAddress(test={'version': 4}, address=IPv4Address('0.0.0.1'))``.

        The five ``mh`` sites are covered next to the rest of that module, in
        ``MHUnitTests.test_mh_length_derived_addresses_reject_a_bool``.
        """
        from pcapkit.const.hip.parameter import Parameter
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.internet.hip import HIP
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        hip = object.__new__(HIP)
        tcp = object.__new__(TCP)

        for value in (True, False):
            with self.subTest(site='hip.Locator.value', value=value):
                with self.assertRaises(FieldValueError) as context:
                    hip._make_param_locator_set(  # type: ignore[arg-type]
                        Parameter.LOCATOR_SET, version=2, locator_set=[{'ip': value}])
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn('must not be a bool', str(context.exception))

            with self.subTest(site='tcp.MPTCPAddAddress.address', value=value):
                with self.assertRaises(FieldValueError) as context:
                    tcp._make_mptcp_addaddr(  # type: ignore[arg-type]
                        MPTCPOption.ADD_ADDR, addr_id=1, addr=value)
                self.assertIsInstance(context.exception, BaseError)
                self.assertIn('must not be a bool', str(context.exception))

        # the same two sites still take every legitimate value they took before.
        #
        # These two literals are unchanged by #651, and that is worth a note rather
        # than being left to look like an oversight: #651 corrected HIP parameter
        # padding to :rfc:`7401` Section 5.2.1's
        # ``Total Length = 11 + Length - (Length + 3) % 8`` at 45 of the 46
        # parameters, and ``LOCATOR_SET`` is the one deliberately left alone. So
        # these records are byte-for-byte what ``main`` emits -- verified against
        # ``b34f132f6`` rather than assumed -- and they are *also* what the RFC
        # asks for.
        #
        # The reason they are already right is that two defects in this parameter
        # cancel each other exactly, which is why correcting the padding here alone
        # would have broken it. ``LocatorSetParameter.padding``'s callback never
        # receives the parameter's ``len``: ``ListField`` packs each nested
        # ``Locator`` into the shared packet context, whose own ``len`` overwrites
        # the parameter's, and ``padding`` is evaluated after the list -- so it sees
        # the last locator's ``len``, which is 4 for any IPv6 locator. Meanwhile
        # ``_make_param_locator_set`` writes the parameter's ``len`` as
        # ``sum(Locator.len)``, in 4-octet units, where the RFC's ``Length`` is a
        # byte count: ``4n`` where the contents are ``24n`` octets.
        #
        # Always-4 padding gives ``4 + 24n + 4 = 24n + 8``; and because ``24n`` is a
        # multiple of 8, the RFC total for a byte-count ``Length`` of ``24n`` is
        # ``11 + 24n - 3``, the same ``24n + 8``. Measured at n = 1, 2, 5 on both
        # trees: 32, 56 and 128 octets, equal to the RFC total in every case. #679
        # tracks fixing the pair together; see ``LocatorSetParameter.padding`` for
        # why neither half moves on its own.
        #
        # They pin exact octets rather than a length or a prefix, deliberately.
        # Exact octets are the whole subject of #651, and pcapkit round-trips its
        # own output whatever the padding rule says -- writer and reader shared the
        # error -- so a comparison that tolerated trailing bytes would have gone on
        # passing through the defect and through the fix alike. For the same reason
        # these stay 32 octets: a shorter pin here would silently bless the
        # four-octet shortfall that narrowing #651 exists to avoid.
        self.assertEqual(
            hip._make_param_locator_set(  # type: ignore[arg-type]
                Parameter.LOCATOR_SET, version=2,
                locator_set=[{'ip': '2001:db8::1'}]).pack().hex(),
            '00c10004000004000000000020010db800000000000000000000000100000000')
        self.assertEqual(
            tcp._make_mptcp_addaddr(  # type: ignore[arg-type]
                MPTCPOption.ADD_ADDR, addr_id=1, addr='192.0.2.1').address,
            ipaddress.IPv4Address('192.0.2.1'))
        # int(True) is 1, and 1 is ::1 for an IPv6-only locator -- the escape
        # hatch works and still widens to the family the wire format fixes.
        # Four trailing octets shorter since #651, as above.
        self.assertEqual(
            hip._make_param_locator_set(  # type: ignore[arg-type]
                Parameter.LOCATOR_SET, version=2,
                locator_set=[{'ip': int(True)}]).pack().hex(),
            '00c1000400000400000000000000000000000000000000000000000100000000')

    def test_ipv4_interface_post_process_rejects_a_non_contiguous_netmask(self) -> None:
        """``IPv4InterfaceField.post_process`` builds
        ``ipaddress.ip_interface(f'{ip}/{mask}')`` from wire bytes whose
        trailing four octets are meant to be a dotted netmask. Unlike the
        leading four octets (always exactly 4 octets, so always a valid
        address), those trailing octets are not guaranteed to form a
        *contiguous* netmask -- e.g. a capture with a malformed or corrupted
        IPv4 interface option can carry ``0.255.0.255``, which
        :func:`ipaddress.ip_interface` rejects with a bare
        :exc:`~ipaddress.NetmaskValueError`. This is reachable through
        :meth:`~pcapkit.corekit.fields.field.FieldBase.unpack` alone, with no
        malformed-length input required, and must raise :exc:`FieldValueError`
        instead.
        """
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField
        from pcapkit.utilities.exceptions import BaseError, FieldValueError

        field = IPv4InterfaceField()
        raw = ipaddress.IPv4Address('1.2.3.4').packed + bytes([0, 255, 0, 255])

        with self.assertRaises(FieldValueError) as context:
            field.unpack(raw, {})
        self.assertIsInstance(context.exception, BaseError)
        self.assertIn('0.255.0.255', str(context.exception))


if __name__ == '__main__':
    unittest.main()
