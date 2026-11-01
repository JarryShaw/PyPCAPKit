# -*- coding: utf-8 -*-
"""GitHub issue #2501: Generic Routing Encapsulation (GRE) frames.

:class:`~pcapkit.protocols.link.gre.GRE` dissects the ``arphrd_type``
``ARPHRD_IPGRE``/``ARPHRD_IP6GRE`` payload that
:class:`~pcapkit.protocols.link.linux_sll.LinuxSLL` previously kept whole as
:class:`~pcapkit.protocols.misc.raw.Raw` (see
:attr:`LinuxSLL.__proto__ <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`). Covers the
base header [:rfc:`2784`], the optional Key and Sequence Number extensions
[:rfc:`2890`], the EtherType-keyed dispatch through
:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`, and
byte-exact round trips. The GRE-dispatch side of
``LinuxSLL1``/``LinuxSLL2`` is covered in their own test modules.

Each test imports :mod:`pcapkit` itself, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest

from tests._support import reimport_once_per_class

#: An IPv4 header (DF clear, protocol UDP) and an 8-octet UDP header.
IPV4 = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
        + bytes.fromhex('3039003500080000'))
#: An IPv6 header (next header UDP) and an 8-octet UDP header.
IPV6 = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
        + bytes.fromhex('3039003500080000'))

#: Bit positions (MSB-first, per the module docstring's diagram) of the ``C``,
#: ``K`` and ``S`` flags within the 16-bit flags-and-version word.
_C, _K, _S = 1 << 15, 1 << 13, 1 << 12


def _gre(protocol_type: int, payload: bytes, *, checksum: 'int | None' = None,
        reserved1: int = 0, key: 'int | None' = None, sequence_number: 'int | None' = None,
        reserved: int = 0, version: int = 0) -> bytes:
    """Pack a bare GRE header plus ``payload``; see the module docstring for the layout."""
    flags = version | reserved
    data = b''
    if checksum is not None:
        flags |= _C
        data += struct.pack('>HH', checksum, reserved1)
    if key is not None:
        flags |= _K
        data += struct.pack('>I', key)
    if sequence_number is not None:
        flags |= _S
        data += struct.pack('>I', sequence_number)
    return struct.pack('>HH', flags, protocol_type) + data + payload


class TestGRE(unittest.TestCase):
    """Pin the GRE layer, alone."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _assert_rebuilds(self, layer, **kwargs) -> None:  # type: ignore[no-untyped-def]
        """``layer`` rebuilds byte-exactly from its info, and from ``info.to_dict()``."""
        for data in (layer.info, layer.info.to_dict()):
            with self.subTest(layer=type(layer).__name__, data=type(data).__name__):
                self.assertEqual(type(layer).from_data(data, **kwargs).data.hex(), layer.data.hex())

    def test_base_header_dispatches_ipv4_and_ipv6(self) -> None:
        """:rfc:`2784`'s base header, no optional fields -- the common case."""
        from pcapkit.protocols.link.gre import GRE

        for protocol_type, payload, name in ((0x0800, IPV4, 'IPv4'), (0x86DD, IPV6, 'IPv6')):
            with self.subTest(protocol_type=hex(protocol_type)):
                raw = _gre(protocol_type, payload)
                parsed = GRE(raw, len(raw))
                self.assertEqual((parsed.info.checksum_present, parsed.info.key_present,
                                 parsed.info.sequence_present), (False, False, False))
                self.assertEqual(parsed.info.version, 0)
                self.assertIsNone(parsed.info.checksum)
                self.assertIsNone(parsed.info.reserved1)
                self.assertIsNone(parsed.info.key)
                self.assertIsNone(parsed.info.sequence_number)
                self.assertEqual(parsed.protocol, protocol_type)
                self.assertEqual((parsed.name, parsed.alias, parsed.length),
                                 ('Generic Routing Encapsulation', 'GRE', 4))
                self.assertEqual(type(parsed.payload).__name__, name)
                self.assertEqual(parsed.protochain.chain, f'GRE:{name}:UDP')
                self.assertEqual(parsed.data, raw)
                self._assert_rebuilds(parsed)

    def test_checksum_present_adds_checksum_and_reserved1(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, checksum=0x1234, reserved1=0)
        parsed = GRE(raw, len(raw))
        self.assertTrue(parsed.info.checksum_present)
        self.assertFalse(parsed.info.key_present)
        self.assertFalse(parsed.info.sequence_present)
        self.assertEqual(parsed.info.checksum, 0x1234)
        self.assertEqual(parsed.info.reserved1, 0)
        self.assertEqual(parsed.length, 8)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_key_present_adds_key_rfc_2890(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, key=0xDEADBEEF)
        parsed = GRE(raw, len(raw))
        self.assertTrue(parsed.info.key_present)
        self.assertFalse(parsed.info.checksum_present)
        self.assertFalse(parsed.info.sequence_present)
        self.assertEqual(parsed.info.key, 0xDEADBEEF)
        self.assertEqual(parsed.length, 8)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_sequence_present_adds_sequence_number_rfc_2890(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, sequence_number=12345)
        parsed = GRE(raw, len(raw))
        self.assertTrue(parsed.info.sequence_present)
        self.assertFalse(parsed.info.checksum_present)
        self.assertFalse(parsed.info.key_present)
        self.assertEqual(parsed.info.sequence_number, 12345)
        self.assertEqual(parsed.length, 8)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_every_optional_field_together_is_the_longest_form(self) -> None:
        """``C``, ``K`` and ``S`` all set: the 16-octet longest form."""
        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, checksum=0xBEEF, reserved1=0, key=0x11223344, sequence_number=99)
        parsed = GRE(raw, len(raw))
        self.assertEqual((parsed.info.checksum_present, parsed.info.key_present,
                         parsed.info.sequence_present), (True, True, True))
        self.assertEqual((parsed.info.checksum, parsed.info.key, parsed.info.sequence_number),
                         (0xBEEF, 0x11223344, 99))
        self.assertEqual(parsed.length, 16)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_reserved_bits_round_trip_even_when_non_zero(self) -> None:
        """Bit 1 and bits 4-12 of the flags word -- :rfc:`2784`'s ``Reserved0``
        less the ``K``/``S`` bits :rfc:`2890` carves out of it -- are carried
        verbatim rather than silently zeroed.
        """
        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, reserved=0x4FF8)
        parsed = GRE(raw, len(raw))
        self.assertEqual(parsed.info.reserved, 0x4FF8)
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_nonzero_version_is_refused(self) -> None:
        """:rfc:`2784` requires ``Ver`` to be ``0``; a nonzero version is a
        different protocol (RFC 2637's Enhanced GRE/PPTP, version 1), not
        implemented here -- refused rather than misread.
        """
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.exceptions import ProtocolError

        raw = _gre(0x0800, IPV4, version=1)
        with self.assertRaises(ProtocolError):
            GRE(raw, len(raw))

    def test_make_then_parse_base_header(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        made = GRE(payload=IPV4).data
        self.assertEqual(made, _gre(0x0800, IPV4))

        parsed = GRE(made, len(made))
        self.assertEqual(type(parsed.payload).__name__, 'IPv4')
        self._assert_rebuilds(parsed)

    def test_make_then_parse_every_optional_field(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        made = GRE(checksum=0xBEEF, key=0x11223344, sequence_number=99, payload=IPV4).data
        self.assertEqual(made, _gre(0x0800, IPV4, checksum=0xBEEF, key=0x11223344,
                                    sequence_number=99))

        parsed = GRE(made, len(made))
        self.assertEqual((parsed.info.checksum, parsed.info.key, parsed.info.sequence_number),
                         (0xBEEF, 0x11223344, 99))
        self._assert_rebuilds(parsed)

    def test_make_defaults(self) -> None:
        from pcapkit.protocols.link.gre import GRE

        self.assertEqual(GRE().data, _gre(0x0800, b''))

    def test_make_infers_presence_from_the_value_given(self) -> None:
        """As :meth:`L2TPv2.make <pcapkit.protocols.link.l2tpv2.L2TPv2.make>`
        infers ``S`` from whether ``ns``/``nr`` are given, ``C``/``K``/``S``
        here are inferred from whether ``checksum``/``key``/``sequence_number``
        are given, not from a separate flag argument.
        """
        from pcapkit.protocols.link.gre import GRE

        self.assertFalse(GRE().info.checksum_present)
        self.assertTrue(GRE(checksum=0).info.checksum_present)
        self.assertTrue(GRE(key=0).info.key_present)
        self.assertTrue(GRE(sequence_number=0).info.sequence_present)

    def test_make_rejects_reserved1_without_checksum(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            GRE(reserved1=5)

    def test_make_rejects_reserved_bits_outside_the_mask(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            GRE(reserved=0x8000)

    def test_make_rejects_what_does_not_fit(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.utilities.exceptions import ProtocolError

        for kwargs in (
            {'checksum': -1}, {'checksum': 0x1_0000}, {'checksum': True},
            {'reserved1': -1}, {'reserved1': 0x1_0000, 'checksum': 0},
            {'key': -1}, {'key': 0x1_0000_0000}, {'key': True},
            {'sequence_number': -1}, {'sequence_number': 0x1_0000_0000},
            {'version': -1}, {'version': 8}, {'version': True},
        ):
            with self.subTest(**kwargs), self.assertRaises(ProtocolError):
                GRE(**kwargs)

    def test_id_and_index(self) -> None:
        """``__index__`` is ``IPGRE``, one of the two ``arphrd_type`` keys LinuxSLL
        dispatches here (#2510); ``IP6GRE`` is the other.
        """
        from pcapkit.const.linux.arphrd import ARPHRD
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.protocols.link.linux_sll import LinuxSLL

        self.assertEqual(GRE.id(), ('GRE',))
        self.assertIs(GRE.__index__(), ARPHRD.IPGRE)
        self.assertEqual(GRE.__index__(), 778)
        for arphrd in (ARPHRD.IPGRE, ARPHRD.IP6GRE):
            with self.subTest(arphrd=arphrd):
                self.assertIs(LinuxSLL._lookup_next_layer(LinuxSLL.__proto__, arphrd), GRE)

    def test_unregistered_protocol_type_is_kept_raw(self) -> None:
        from pcapkit.protocols.link.gre import GRE
        from pcapkit.protocols.misc.raw import Raw

        raw = _gre(0x1234, IPV4)
        parsed = GRE(raw, len(raw))
        self.assertIsInstance(parsed.payload, Raw)
        self.assertEqual(parsed.protochain.chain, 'GRE:<unassigned>')
        self.assertEqual(parsed.data, raw)
        self._assert_rebuilds(parsed)

    def test_truncated_header_rebuilds_as_captured(self) -> None:
        """A capture ending inside the header must not blow up the parse, and
        rebuilds to exactly the octets captured. See
        ``tests/protocols/test_short_read_roundtrip_unit.py`` for the sweep
        that cuts this (and every other) family at every offset.
        """
        import warnings

        from pcapkit.protocols.link.gre import GRE

        raw = _gre(0x0800, IPV4, checksum=0xBEEF, key=0x11223344, sequence_number=99)
        for keep in (1, 2, 3, 4, 8, 12, 15):
            with self.subTest(keep=keep):
                cut = raw[:keep]
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = GRE(cut, len(cut))
                self.assertEqual(parsed.data, cut)
                self.assertEqual(GRE.from_data(parsed.info).data, cut)


if __name__ == '__main__':
    unittest.main()
