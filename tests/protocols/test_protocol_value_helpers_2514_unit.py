# -*- coding: utf-8 -*-
"""The value helpers ``Protocol`` shares with its subclasses (GitHub issue #2514).

The owner ruled on PR #2595 (TLS extensions) and PR #2607 (the 802.11 header) that the
vector, integer-list and ``_make_uint`` helpers live on the base ``Protocol``, so any
protocol can use them. Each is checked here apart from TLS:

* ``_read_vector`` and ``_read_whole_vector`` -- a length-prefixed vector, with
  prefix widths of one, two and three octets, refusing a truncated prefix, a
  length past the end of the buffer and, for the whole-buffer form, trailing
  octets;
* ``_read_uints`` -- a run of fixed-width unsigned integers, refusing a buffer
  that is not a whole number of them;
* ``_make_vector`` and ``_make_uints`` -- their inverses, refusing what does not
  fit the width;
* ``_make_uint`` -- the check that a value given for a field fits its width.

The rest of ``ProtocolBase``'s value helpers, from the audit on #2614:

* ``_read_octets`` and ``_read_uint`` -- exactly so many octets, or an unsigned
  integer of so many, out of a buffer, refusing a short read; ``_make_octets``
  checks the octets a field is given;
* ``_read_sint`` and ``_make_sint`` -- a two's-complement field, read from its
  unsigned value and checked on the way back, the unsigned spelling of the same
  bits accepted too when ``allow_unsigned`` asks for it;
* ``_uint_size`` -- the octets an unsigned integer needs;
* ``_read_mac_addr`` and ``_make_mac_addr`` -- a MAC address, an EUI-64 one, or
  one of any length;
* ``_read_text`` -- text decoded so that it encodes back to its octets.

Their errors name the instance's ``alias``, which is per instance (a TLS record's is its
tier, such as ``TLS 1.3``), so that is pinned with an alias unlike the class name.


"""

from __future__ import annotations

import enum
import unittest
from typing import TYPE_CHECKING
from unittest import mock

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Callable

    from pcapkit.protocols.application.ospf.protocol import OSPF
    from pcapkit.protocols.misc.raw.protocol import Raw

#: Test tier (#1958): the per-helper cases of the protocol base, beside the
#: ``ALL``-tier smoke slice in ``test_protocol_base_unit``.
__tier__ = 'LATEST'

#: An alias that is not the class name, to tell ``self.alias`` from ``cls.__name__``.
ALIAS = 'Sample 1.0'


class _HelperTestCase(unittest.TestCase):
    """A fresh :mod:`pcapkit` per class, and a protocol instance to call the helpers on."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.protocols.misc.raw.protocol import Raw

        self.proto = Raw(b'')  # type: Raw

    def assertRefused(self, pattern: 'str', func: 'Callable[..., object]', *args: 'object',
                      **kwargs: 'object') -> None:
        """``func`` raises :exc:`ProtocolError` naming :data:`ALIAS` and matching ``pattern``."""
        from pcapkit.utilities.exceptions import ProtocolError

        with mock.patch.object(type(self.proto), 'alias', new_callable=mock.PropertyMock, return_value=ALIAS):
            with self.assertRaisesRegex(ProtocolError, f'^{ALIAS}: {pattern}'):
                func(*args, **kwargs)

    def unread(self) -> 'OSPF':
        """An OSPF instance ``read()`` has not run on, so its ``alias`` raises."""
        from pcapkit.protocols.application.ospf.protocol import OSPF

        proto = object.__new__(OSPF)
        with self.assertRaises(AttributeError):
            getattr(proto, 'alias')
        return proto


class ReadVectorTests(_HelperTestCase):
    """``_read_vector`` returns the vector's octets and the offset just past them."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                data = b'\xee' + prefix + b'abc' + b'\xff'
                self.assertEqual(self.proto._read_vector(data, 1, size=size, what='v'), (b'abc', 1 + size + 3))

    def test_an_empty_vector_and_the_default_offset(self) -> None:
        self.assertEqual(self.proto._read_vector(b'\x00rest', what='v'), (b'', 1))

    def test_a_truncated_prefix_is_refused(self) -> None:
        for size in (1, 2, 3):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v length runs past the end of the buffer',
                                   self.proto._read_vector, b'\x00' * size, 1, size=size, what='v')

    def test_a_length_past_the_end_is_refused(self) -> None:
        for size, prefix in ((1, b'\x04'), (2, b'\x00\x04'), (3, b'\x00\x00\x04')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v runs past the end of the buffer',
                                   self.proto._read_vector, prefix + b'abc', size=size, what='v')


class ReadWholeVectorTests(_HelperTestCase):
    """``_read_whole_vector`` reads the one vector a buffer holds, and nothing after it."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x02'), (2, b'\x00\x02'), (3, b'\x00\x00\x02')):
            with self.subTest(size=size):
                self.assertEqual(self.proto._read_whole_vector(prefix + b'ab', size=size, what='v'), b'ab')

    def test_a_truncated_prefix_is_refused(self) -> None:
        for size in (2, 3):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v length runs past the end of the buffer',
                                   self.proto._read_whole_vector, b'\x00' * (size - 1), size=size, what='v')

    def test_a_length_past_the_end_is_refused(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v runs past the end of the buffer',
                                   self.proto._read_whole_vector, prefix + b'ab', size=size, what='v')

    def test_trailing_octets_are_refused(self) -> None:
        for size, prefix in ((1, b'\x01'), (2, b'\x00\x01'), (3, b'\x00\x00\x01')):
            with self.subTest(size=size):
                self.assertRefused('invalid format: v carries excess octets',
                                   self.proto._read_whole_vector, prefix + b'ab', size=size, what='v')


class ReadUintsTests(_HelperTestCase):
    """``_read_uints`` reads a buffer as big-endian unsigned integers of one width."""

    def test_each_width(self) -> None:
        data = bytes(range(1, 7))
        for size, expected in ((1, (1, 2, 3, 4, 5, 6)), (2, (0x0102, 0x0304, 0x0506)),
                               (3, (0x010203, 0x040506))):
            with self.subTest(size=size):
                self.assertEqual(self.proto._read_uints(data, size=size, what='list'), expected)

    def test_an_empty_list(self) -> None:
        self.assertEqual(self.proto._read_uints(b'', size=2, what='list'), ())

    def test_a_length_that_is_not_a_whole_number_of_integers_is_refused(self) -> None:
        for size, data in ((2, b'\x00\x01\x02'), (3, b'\x00\x01\x02\x03')):
            with self.subTest(size=size):
                self.assertRefused(f'invalid format: list length {len(data)} is not a multiple of {size}$',
                                   self.proto._read_uints, data, size=size, what='list')


class MakeVectorTests(_HelperTestCase):
    """``_make_vector`` writes the prefix ``_read_vector`` reads."""

    def test_each_prefix_width(self) -> None:
        for size, prefix in ((1, b'\x03'), (2, b'\x00\x03'), (3, b'\x00\x00\x03')):
            with self.subTest(size=size):
                made = type(self.proto)._make_vector(b'abc', size=size)
                self.assertEqual(made, prefix + b'abc')
                self.assertEqual(self.proto._read_whole_vector(made, size=size, what='v'), b'abc')

    def test_a_vector_too_long_for_its_prefix_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import StructError

        with self.assertRaisesRegex(StructError, '^Raw: pack failed$'):
            type(self.proto)._make_vector(bytes(256), size=1)


class MakeUintsTests(_HelperTestCase):
    """``_make_uints`` writes the integers ``_read_uints`` reads."""

    def test_each_width(self) -> None:
        class Code(enum.IntEnum):
            five = 5

        for size, expected in ((1, b'\x01\x05'), (2, b'\x00\x01\x00\x05'), (3, b'\x00\x00\x01\x00\x00\x05')):
            with self.subTest(size=size):
                made = type(self.proto)._make_uints((1, Code.five), size=size)
                self.assertEqual(made, expected)
                self.assertEqual(self.proto._read_uints(made, size=size, what='list'), (1, 5))

    def test_a_value_outside_the_width_is_refused(self) -> None:
        from pcapkit.utilities.exceptions import StructError

        for size, value in ((1, 256), (2, 0x10000), (3, 0x1000000), (2, -1)):
            with self.subTest(size=size, value=value), self.assertRaises(StructError):
                type(self.proto)._make_uints((value,), size=size)


class MakeUintTests(_HelperTestCase):
    """``_make_uint`` passes a value that fits its field, as a plain :class:`int`."""

    def test_a_value_that_fits_is_returned_as_an_int(self) -> None:
        for bits, value in ((1, 1), (2, 3), (4, 0), (16, 0xFFFF)):
            with self.subTest(bits=bits, value=value):
                self.assertEqual(self.proto._make_uint(value, bits=bits, name='field'), value)

    def test_a_bool_is_accepted_for_a_one_bit_field(self) -> None:
        for flag in (False, True):
            with self.subTest(flag=flag):
                made = self.proto._make_uint(flag, bits=1, name='flag')
                self.assertEqual(made, int(flag))
                self.assertIs(type(made), int)

    def test_a_bool_is_refused_for_a_wider_field(self) -> None:
        for bits in (2, 8):
            with self.subTest(bits=bits):
                self.assertRefused(r'invalid field: True$', self.proto._make_uint, True, bits=bits, name='field')

    def test_a_negative_value_is_refused(self) -> None:
        self.assertRefused(r'invalid field: -1$', self.proto._make_uint, -1, bits=4, name='field')

    def test_a_value_one_past_the_width_is_refused(self) -> None:
        for bits in (1, 4, 16):
            with self.subTest(bits=bits):
                self.assertRefused(rf'invalid field: {2 ** bits}$',
                                   self.proto._make_uint, 2 ** bits, bits=bits, name='field')

    def test_a_non_int_is_refused(self) -> None:
        for value, shown in (('1', "'1'"), (1.0, r'1\.0'), (None, 'None')):
            with self.subTest(value=value):
                self.assertRefused(f'invalid field: {shown}$', self.proto._make_uint, value, bits=4, name='field')

    def test_an_alias_given_prefixes_the_message_before_read(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        proto = self.unread()
        self.assertEqual(proto._make_uint(0xFFFF, bits=16, name='packet length', alias='OSPF'), 0xFFFF)
        with self.assertRaisesRegex(ProtocolError, '^OSPF: invalid packet length: 65536$'):
            proto._make_uint(0x10000, bits=16, name='packet length', alias='OSPF')


class ReadOctetsTests(_HelperTestCase):
    """``_read_octets`` returns exactly the octets asked for, or refuses."""

    def test_each_size_and_offset(self) -> None:
        data = bytes(range(10))
        for pos, size in ((0, 1), (0, 10), (3, 4), (9, 1), (10, 0)):
            with self.subTest(pos=pos, size=size):
                self.assertEqual(self.proto._read_octets(data, pos, size=size, what='f'), data[pos:pos + size])

    def test_the_default_offset(self) -> None:
        self.assertEqual(self.proto._read_octets(b'abc', size=2, what='f'), b'ab')

    def test_a_short_read_is_refused(self) -> None:
        for pos, size in ((0, 4), (2, 2), (3, 1), (4, 1)):
            with self.subTest(pos=pos, size=size):
                self.assertRefused('invalid format: f runs past the end of the buffer$',
                                   self.proto._read_octets, b'abc', pos, size=size, what='f')


class ReadUintTests(_HelperTestCase):
    """``_read_uint`` reads one unsigned integer, the inverse of ``_make_pack``."""

    def test_each_width_and_byte_order(self) -> None:
        data = b'\xee' + bytes(range(1, 9))
        for size in (1, 2, 3, 4, 8):
            for lilendian in (False, True):
                with self.subTest(size=size, lilendian=lilendian):
                    expected = int.from_bytes(data[1:1 + size], 'little' if lilendian else 'big')
                    self.assertEqual(self.proto._read_uint(data, 1, size=size, what='f', lilendian=lilendian),
                                     expected)

    def test_it_undoes_make_pack_at_the_boundaries(self) -> None:
        for size in (1, 2, 3, 4, 8):
            for value in (0, 1, (1 << (8 * size)) - 1):
                for lilendian in (False, True):
                    with self.subTest(size=size, value=value, lilendian=lilendian):
                        packed = type(self.proto)._make_pack(value, size=size, lilendian=lilendian)
                        self.assertEqual(self.proto._read_uint(packed, size=size, what='f', lilendian=lilendian),
                                         value)

    def test_a_short_read_is_refused(self) -> None:
        for size in (1, 2, 3):
            with self.subTest(size=size):
                self.assertRefused('invalid format: f runs past the end of the buffer$',
                                   self.proto._read_uint, b'\x00' * size, 1, size=size, what='f')


class ReadSintTests(_HelperTestCase):
    """``_read_sint`` reads an unsigned field's bits as two's complement."""

    def test_the_boundaries_of_each_width(self) -> None:
        for bits in (1, 8, 24):
            top = 1 << bits
            for unsigned, signed in ((0, 0), (top // 2 - 1, top // 2 - 1), (top // 2, -(top // 2)), (top - 1, -1)):
                with self.subTest(bits=bits, unsigned=unsigned):
                    self.assertEqual(self.proto._read_sint(unsigned, bits), signed)


class MakeOctetsTests(_HelperTestCase):
    """``_make_octets`` passes exactly so many octets, as :class:`bytes`."""

    def test_octets_of_the_size_are_returned_as_bytes(self) -> None:
        for size, value in ((1, b'\x01'), (2, bytearray(b'ab')), (8, bytes(8))):
            with self.subTest(size=size):
                made = self.proto._make_octets(value, size=size, name='field')
                self.assertEqual(made, bytes(value))
                self.assertIs(type(made), bytes)

    def test_a_wrong_size_is_refused(self) -> None:
        for size, value, unit in ((1, b'', '1 octet'), (1, b'ab', '1 octet'), (2, b'a', '2 octets')):
            with self.subTest(size=size, value=value):
                self.assertRefused(f'invalid field: must be {unit}, not {value!r}$',
                                   self.proto._make_octets, value, size=size, name='field')

    def test_a_non_octet_string_is_refused(self) -> None:
        for value in ('a', 1, True, None):
            with self.subTest(value=value):
                self.assertRefused(f'invalid field: must be 1 octet, not {value!r}$',
                                   self.proto._make_octets, value, size=1, name='field')

    def test_an_alias_given_prefixes_the_message_before_read(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        proto = self.unread()
        with self.assertRaisesRegex(ProtocolError, "^OSPF: invalid field: must be 1 octet, not b''$"):
            proto._make_octets(b'', size=1, name='field', alias='OSPF')


class MakeSintTests(_HelperTestCase):
    """``_make_sint`` checks a signed value and returns the bits ``_read_sint`` reads."""

    def test_the_boundaries_round_trip(self) -> None:
        for bits in (2, 8, 24):
            half = 1 << (bits - 1)
            for value in (-half, -1, 0, 1, half - 1):
                with self.subTest(bits=bits, value=value):
                    made = self.proto._make_sint(value, bits=bits, name='field')
                    self.assertTrue(0 <= made < 1 << bits)
                    self.assertEqual(self.proto._read_sint(made, bits), value)

    def test_a_negative_value_is_twos_complement(self) -> None:
        self.assertEqual(self.proto._make_sint(-1, bits=24, name='field'), 0xFFFFFF)
        self.assertEqual(self.proto._make_sint(-(1 << 23), bits=24, name='field'), 0x800000)

    def test_one_past_either_end_is_refused(self) -> None:
        for bits in (2, 8, 24):
            half = 1 << (bits - 1)
            for value in (-half - 1, half):
                with self.subTest(bits=bits, value=value):
                    self.assertRefused(rf'invalid field: {value}$', self.proto._make_sint, value, bits=bits,
                                       name='field')

    def test_a_bool_or_a_non_int_is_refused(self) -> None:
        for value, shown in ((True, 'True'), (False, 'False'), ('1', "'1'"), (1.0, r'1\.0'), (None, 'None')):
            with self.subTest(value=value):
                self.assertRefused(f'invalid field: {shown}$', self.proto._make_sint, value, bits=8, name='field')

    def test_the_unsigned_spelling_is_accepted_only_when_asked(self) -> None:
        """``allow_unsigned`` widens the range to ``-half`` to ``2 ** bits - 1``; both spellings give the same bits."""
        for bits in (2, 8, 24):
            half, top = 1 << (bits - 1), 1 << bits
            for value in (-half, -1, 0, half - 1, half, top - 1):
                with self.subTest(bits=bits, value=value):
                    self.assertEqual(self.proto._make_sint(value, bits=bits, name='field', allow_unsigned=True),
                                     value % top)
            self.assertEqual(self.proto._make_sint(-1, bits=bits, name='field', allow_unsigned=True),
                             self.proto._make_sint(top - 1, bits=bits, name='field', allow_unsigned=True))
            # without it the unsigned half stays refused, as the signed-only tests above pin at ``half``
            with self.subTest(bits=bits, value=top - 1, allow_unsigned=False):
                self.assertRefused(rf'invalid field: {top - 1}$', self.proto._make_sint, top - 1, bits=bits,
                                   name='field')

    def test_one_past_either_end_is_refused_with_the_unsigned_spelling(self) -> None:
        for bits in (2, 8, 24):
            half, top = 1 << (bits - 1), 1 << bits
            for value in (-half - 1, top):
                with self.subTest(bits=bits, value=value):
                    self.assertRefused(rf'invalid field: {value}$', self.proto._make_sint, value, bits=bits,
                                       name='field', allow_unsigned=True)
        for value, shown in ((True, 'True'), (False, 'False'), ('1', "'1'"), (1.0, r'1\.0'), (None, 'None')):
            with self.subTest(value=value):
                self.assertRefused(f'invalid field: {shown}$', self.proto._make_sint, value, bits=8, name='field',
                                   allow_unsigned=True)

    def test_an_alias_given_prefixes_the_message_before_read(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        proto = self.unread()
        self.assertEqual(proto._make_sint(-1, bits=16, name='offset', alias='PCAP-NG'), 0xFFFF)
        with self.assertRaisesRegex(ProtocolError, '^PCAP-NG: invalid offset: 32768$'):
            proto._make_sint(0x8000, bits=16, name='offset', alias='PCAP-NG')


class UintSizeTests(_HelperTestCase):
    """``_uint_size`` counts whole octets, rounding a partial one up."""

    def test_each_boundary(self) -> None:
        for value, size in ((0, 0), (1, 1), (0xFF, 1), (0x100, 2), (0xFFFF, 2), (0x10000, 3),
                            ((1 << 64) - 1, 8), (1 << 64, 9)):
            with self.subTest(value=value):
                self.assertEqual(type(self.proto)._uint_size(value), size)

    def test_a_minimum(self) -> None:
        self.assertEqual(type(self.proto)._uint_size(0, minimum=1), 1)
        self.assertEqual(type(self.proto)._uint_size(0x100, minimum=1), 2)
        self.assertEqual(type(self.proto)._uint_size(1, minimum=4), 4)


class ReadMacAddrTests(_HelperTestCase):
    """``_read_mac_addr`` writes the octets as colon-separated *hex*."""

    def test_a_mac_and_an_eui_64_address(self) -> None:
        self.assertEqual(self.proto._read_mac_addr(bytes.fromhex('00005e0053af')), '00:00:5e:00:53:af')
        self.assertEqual(self.proto._read_mac_addr(bytes.fromhex('02005efffe0053af')), '02:00:5e:ff:fe:00:53:af')


class MakeMacAddrTests(_HelperTestCase):
    """``_make_mac_addr`` reads a ``:``- or ``-``-separated address of ``size`` octets."""

    MAC = bytes.fromhex('00005e0053af')
    EUI = bytes.fromhex('02005efffe0053af')

    def test_each_spelling_of_a_mac_address(self) -> None:
        for addr in ('00:00:5e:00:53:af', '00-00-5E-00-53-AF', '00:00-5e:00-53:aF',
                     b'00:00:5e:00:53:af', bytearray(b'00-00-5e-00-53-af')):
            with self.subTest(addr=addr):
                made = self.proto._make_mac_addr(addr)
                self.assertEqual(made, self.MAC)
                self.assertIs(type(made), bytes)
        self.assertEqual(self.proto._make_mac_addr(self.proto._read_mac_addr(self.MAC)), self.MAC)

    def test_an_eui_64_address(self) -> None:
        self.assertEqual(self.proto._make_mac_addr('02:00:5e:ff:fe:00:53:af', size=8, name='EUI address'),
                         self.EUI)
        for addr in ('00:00:5e:00:53:af', '02:00:5e:ff:fe:00:53:af:00'):
            with self.subTest(addr=addr):
                self.assertRefused(f'invalid EUI address: {addr!r}$', self.proto._make_mac_addr, addr,
                                   size=8, name='EUI address')

    def test_any_number_of_octets_without_a_size(self) -> None:
        for addr, made in (('', b''), (b'', b''), ('ab', b'\xab'), ('00:00:5e:00:53:af', self.MAC),
                           ('02-00-5e-ff-fe-00-53-af', self.EUI), ('01:02:03', b'\x01\x02\x03')):
            with self.subTest(addr=addr):
                self.assertEqual(self.proto._make_mac_addr(addr, size=None), made)

    def test_a_malformed_address_is_refused(self) -> None:
        for addr in ('', '00:00:5e:00:53', '00:00:5e:00:53:af:01', '00:00:5e:00:53:a', '000:00:5e:00:53:af',
                     '00:00:5e:00:53:af:', '00::00:5e:00:53:af', '00.00.5e.00.53.af', '00:00:5e:00:53:ag',
                     '00 00 5e 00 53 af', '00005e0053af', 'é0:00:5e:00:53:af'):
            with self.subTest(addr=addr):
                self.assertRefused(f'invalid MAC address: {addr!r}$', self.proto._make_mac_addr, addr)
        for addr in (':', 'a', 'abc', 'ab:', ':ab', 'ab::cd'):
            with self.subTest(addr=addr, size=None):
                self.assertRefused(f'invalid MAC address: {addr!r}$', self.proto._make_mac_addr, addr, size=None)

    def test_a_value_of_another_type_is_refused(self) -> None:
        for addr in (True, 0, None, 1.0):
            with self.subTest(addr=addr):
                self.assertRefused(f'invalid MAC address: must be a str, bytes or bytearray, not {addr!r}$',
                                   self.proto._make_mac_addr, addr)

    def test_an_alias_given_prefixes_the_message(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, "^PCAP-NG: invalid MAC address: 'x'$"):
            self.proto._make_mac_addr('x', alias='PCAP-NG')
        proto = self.unread()
        with self.assertRaisesRegex(ProtocolError, '^ARP: invalid MAC address: must be a str, bytes or '
                                                   'bytearray, not None$'):
            proto._make_mac_addr(None, alias='ARP')


class ReadTextTests(_HelperTestCase):
    """``_read_text`` returns text and the charset that encodes it back to its octets."""

    def test_ascii_needs_no_charset(self) -> None:
        for data in (b'', b'/index.html', b'200 OK'):
            with self.subTest(data=data):
                self.assertEqual(self.proto._read_text(data), (data.decode(), None))

    def test_a_detected_charset_that_cannot_encode_falls_back_to_latin_1(self) -> None:
        """A charset Python does not know, or one the text does not fit, is passed over."""
        for charset in ('no-such-codec', 'ascii'):
            with self.subTest(charset=charset), \
                    mock.patch.object(type(self.proto), 'decode', return_value='café'), \
                    mock.patch('pcapkit.protocols.protocol.detect', return_value=charset):
                self.assertEqual(self.proto._read_text(b'caf\xe9'), ('café', 'latin-1'))

    def test_other_octets_encode_back_with_the_charset_returned(self) -> None:
        for data in (b'caf\xe9', b'\xff\xfe\xfd', b'\x80abc', 'café'.encode('cp1252') * 4):
            with self.subTest(data=data):
                text, charset = self.proto._read_text(data)
                self.assertIsNotNone(charset)
                self.assertEqual(text.encode(charset), data)


if __name__ == '__main__':
    unittest.main()
