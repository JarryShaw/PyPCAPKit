# -*- coding: utf-8 -*-
"""MP_CAPABLE's length and its receiver's-key predicate agree on every RFC 8684 form.

GitHub issue #567, with the remaining lengths from #1042.

The sites that must agree
-------------------------

:rfc:`8684` section 3.1 gives ``MP_CAPABLE`` as **12** octets without the receiver's key and
**20** octets with it. The maker ``TCP._make_mptcp_capable``, the predicate on
``MPTCPCapable.rkey``, and the reader ``TCP._read_mptcp_capable`` all encode that split, and
the tests here guard each against its own wrong constant:

* a maker writing ``length=20 if rkey is None else 32`` -- both branches wrong, and the no-key
  branch writing the value RFC 8684 assigns to the *other* case. Measured with every site
  wrong, ``rkey=None`` packed a *20*-octet option carrying no key octets, and an explicit
  ``rkey`` packed a *32*-octet option whose last 12 octets are entirely unaccounted for by the
  RFC 8684 figure;
* a predicate of ``pkt['length'] != 32``, which packs the receiver's key for every length
  *except* 32, i.e. drops it for exactly the length such a maker uses to signal "key present",
  while a *correct* 12-octet, key-absent option satisfies ``12 != 32`` too, so the key field
  would pack, appending 8 phantom octets;
* a reader accepting only ``schema.length in (20, 32)`` and reading ``rkey`` only at 32, which
  rejects the correct forms as soon as construction reaches it (#566).

Correcting the maker alone leaves the predicate packing phantom key octets, and correcting the
predicate alone leaves both of the maker's wrong lengths (20, 32) on the wire, so the sites are
pinned together.

Coverage
--------

Byte-exact packed assertions for both RFC-defined forms -- 12 octets without the receiver's
key, 20 with it -- rather than asserting either component (the maker's arithmetic, or the
schema's predicate) in isolation, per the pattern #565 established for ``ADD_ADDR``.
:class:`TCPMPTCPCapableAllLengthsUnitTests` also splices hand-built, spec-correct octets into
a full segment through :func:`~tests.protocols.transport._mptcp.build_tcp_segment`, bypassing
the makers entirely, so the *parse* direction is pinned independently of whatever the *pack*
direction happens to produce, for all five lengths figure 4 defines -- 4, 12, 20, 22 and 24
(#1042).

"""
from __future__ import annotations

import unittest

from tests.protocols.transport._mptcp import TCP_BASE, build_tcp_segment


def make_capable(**kwargs: 'object') -> 'bytes':
    """Build an MP_CAPABLE option through the maker under test and pack it.

    Args:
        **kwargs: forwarded to :meth:`TCP._make_mptcp_capable
            <pcapkit.protocols.transport.tcp.protocol.TCP._make_mptcp_capable>`.

    Returns:
        The packed option bytes.

    """
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    from pcapkit.protocols.transport.tcp.protocol import TCP

    tcp = TCP.__new__(TCP)
    schema = tcp._make_mptcp_capable(Enum_MPTCPOption.MP_CAPABLE, **kwargs)  # pylint: disable=protected-access
    return schema.pack()


class TCPMPTCPCapableMakerUnitTests(unittest.TestCase):
    """``_make_mptcp_capable`` packs the RFC 8684 length for each form."""

    def test_no_key_packs_twelve_octets(self) -> None:
        """``rkey=None`` packs 12 octets: RFC 8684 figure 4, the key-absent form.

        Guards against packing **20** octets (the with-key value) with no key octets at all,
        as a maker writing ``length=20 if rkey is None else 32`` -- backwards relative to RFC
        8684 -- does.

        """
        packed = make_capable(skey=0x0102030405060708, rkey=None)

        self.assertEqual(len(packed), 12)
        self.assertEqual(packed[1], 12, 'the packed length octet must match the wire length')
        self.assertEqual(packed, bytes([0x1E, 0x0C, 0x00, 0x00]) + bytes.fromhex('0102030405060708'))

    def test_with_key_packs_twenty_octets(self) -> None:
        """An explicit ``rkey`` packs 20 octets: RFC 8684 figure 4, the key-present form.

        Guards against packing **32** octets, the last 12 of which are unaccounted for by RFC
        8684: a maker writing ``length=32`` beside an ``rkey`` predicate of
        ``pkt['length'] != 32`` *drops* the key for this exact length, so those 12 extra
        octets would not even be the key it claims to carry (#567).

        """
        packed = make_capable(skey=0x0102030405060708, rkey=0x1112131415161718)

        self.assertEqual(len(packed), 20)
        self.assertEqual(packed[1], 20, 'the packed length octet must match the wire length')
        self.assertEqual(
            packed,
            bytes([0x1E, 0x14, 0x00, 0x00])
            + bytes.fromhex('0102030405060708')
            + bytes.fromhex('1112131415161718'),
        )

    def test_default_rkey_of_zero_is_still_the_with_key_form(self) -> None:
        """``rkey=0`` is a *present* key of value zero, not an absent one.

        ``_make_mptcp_capable``'s own default is ``rkey=0``, not ``None`` -- this is the case
        :func:`examples.generators.options.options` actually exercises for MP_CAPABLE, and it
        must produce the 20-octet form with an all-zero receiver's key on the wire, not the
        12-octet form.

        """
        packed = make_capable(skey=0x0102030405060708)

        self.assertEqual(len(packed), 20)
        self.assertEqual(packed[-8:], bytes(8))


class TCPMPTCPCapablePublicConstructorUnitTests(unittest.TestCase):
    """Both RFC 8684 forms round-trip through the public ``TCP`` convenience constructor."""

    def test_no_key_round_trip_is_twelve_octets(self) -> None:
        """``rkey=None`` through ``TCP()`` packs a 12-octet option and reports no ``rkey``."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        tcp = TCP.from_fields(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_CAPABLE,
                'skey': 0x0102030405060708,
                'rkey': None,
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]
        packed = bytes(tcp)

        self.assertEqual(data.length, 12)
        self.assertIsNone(data.rkey)
        # NOTE: the segment is the 20-octet header plus this sole option, so the option is its last 12 octets.
        self.assertEqual(packed[-12:], bytes([0x1E, 0x0C, 0x00, 0x00]) + bytes.fromhex('0102030405060708'))

    def test_with_key_round_trip_is_twenty_octets(self) -> None:
        """An explicit ``rkey`` through ``TCP()`` packs a 20-octet option and reports it back."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        tcp = TCP.from_fields(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_CAPABLE,
                'skey': 0x0102030405060708,
                'rkey': 0x1112131415161718,
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        data = tcp.info.options[Enum_Option.Multipath_TCP]
        packed = bytes(tcp)

        self.assertEqual(data.length, 20)
        self.assertEqual(data.rkey, 0x1112131415161718)
        self.assertEqual(
            packed[-20:],
            bytes([0x1E, 0x14, 0x00, 0x00])
            + bytes.fromhex('0102030405060708')
            + bytes.fromhex('1112131415161718'),
        )


#: Every MP_CAPABLE form of :rfc:`8684` section 3.1, keyed by ``Length`` (#1042). Each value
#: is ``(octets, fields)``: hand-built wire octets, and the option fields they carry. The flag
#: octet is ``0x81`` (``A`` "checksum required" and ``H`` HMAC-SHA256) except at 22, where it
#: is ``0x01`` -- the Data-Level Length without a checksum is the checksums-off form.
ALL_LENGTHS = {
    4: (bytes([0x1E, 0x04, 0x01, 0x81]),
        {'skey': None, 'rkey': None, 'dl_len': None, 'checksum': None}),
    12: (bytes([0x1E, 0x0C, 0x01, 0x81]) + b'\xAA' * 8,
         {'skey': 0xAAAAAAAAAAAAAAAA, 'rkey': None, 'dl_len': None, 'checksum': None}),
    20: (bytes([0x1E, 0x14, 0x01, 0x81]) + b'\xAA' * 8 + b'\xBB' * 8,
         {'skey': 0xAAAAAAAAAAAAAAAA, 'rkey': 0xBBBBBBBBBBBBBBBB, 'dl_len': None,
          'checksum': None}),
    22: (bytes([0x1E, 0x16, 0x01, 0x01]) + b'\xAA' * 8 + b'\xBB' * 8 + b'\x12\x34',
         {'skey': 0xAAAAAAAAAAAAAAAA, 'rkey': 0xBBBBBBBBBBBBBBBB, 'dl_len': 0x1234,
          'checksum': None}),
    24: (bytes([0x1E, 0x18, 0x01, 0x81]) + b'\xAA' * 8 + b'\xBB' * 8 + b'\x12\x34\xCD\xEF',
         {'skey': 0xAAAAAAAAAAAAAAAA, 'rkey': 0xBBBBBBBBBBBBBBBB, 'dl_len': 0x1234,
          'checksum': b'\xCD\xEF'}),
}


class TCPMPTCPCapableAllLengthsUnitTests(unittest.TestCase):
    """All five MP_CAPABLE lengths of :rfc:`8684` section 3.1 parse and round-trip (#1042).

    Guards against ``_read_mptcp_capable`` accepting only ``length in (12, 20)``, under which
    the SYN form (4) and both first-data-ACK forms (22, 24) raise ``ProtocolError: TCP: [OptNo
    30] invalid format``, and against a schema that reads ``skey`` unconditionally and has no
    Data-Level Length or Checksum field.

    """

    def _parse(self, length: 'int') -> 'object':
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        octets, _ = ALL_LENGTHS[length]
        # NOTE: pad with NOPs to the 4-octet boundary ``build_tcp_segment`` requires.
        raw = build_tcp_segment(octets + b'\x01' * (-len(octets) % 4))
        return TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

    def _assert_parse(self, length: 'int') -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option

        _, fields = ALL_LENGTHS[length]
        data = self._parse(length)
        self.assertEqual(data.kind, Enum_Option.Multipath_TCP)
        self.assertEqual(data.length, length)
        self.assertEqual(data.subtype, Enum_MPTCPOption.MP_CAPABLE)
        self.assertEqual(data.version, 1)
        for name, value in fields.items():
            self.assertEqual(getattr(data, name), value, name)

    def _assert_round_trip(self, length: 'int') -> None:
        """``make`` through the public ``TCP()`` constructor, then ``read`` the bytes back."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        octets, fields = ALL_LENGTHS[length]
        made = TCP.from_fields(
            options=[(Enum_Option.Multipath_TCP, {
                'subtype': Enum_MPTCPOption.MP_CAPABLE, 'version': 1,
                'flag_req': bool(octets[3] & 0x80), 'flag_hsa': bool(octets[3] & 0x01),
                **fields,
            })],
            **TCP_BASE,  # type: ignore[arg-type]
        )
        packed = bytes(made)
        self.assertEqual(packed[20:20 + length], octets)

        data = TCP(packed, len(packed)).info.options[Enum_Option.Multipath_TCP]
        self.assertEqual(data.length, length)
        for name, value in fields.items():
            self.assertEqual(getattr(data, name), value, name)

    def test_parse_length_4(self) -> None:
        """SYN: only the first 4 octets, no key."""
        self._assert_parse(4)

    def test_parse_length_12(self) -> None:
        """SYN/ACK: the sender's key.

        Guards against ``ProtocolError: TCP: [OptNo 30] invalid format`` from a
        ``schema.length not in (20, 32)`` guard in ``_read_mptcp_capable`` (#566, #567),
        which 12 does not satisfy.

        """
        self._assert_parse(12)

    def test_parse_length_20(self) -> None:
        """ACK without data: both keys.

        Guards against the receiver's key silently vanishing: a ``schema.length not in (20,
        32)`` guard accepts 20, but ``rkey=schema.rkey if schema.length == 32 else None``
        then discards it anyway, since 20 is not 32 (#566, #567).

        """
        self._assert_parse(20)

    def test_parse_length_22(self) -> None:
        """First data ACK: both keys and the Data-Level Length."""
        self._assert_parse(22)

    def test_parse_length_24(self) -> None:
        """First data ACK: both keys, the Data-Level Length, and the Checksum."""
        self._assert_parse(24)

    def test_round_trip_length_4(self) -> None:
        """``skey=None`` packs the 4-octet SYN form and reads it back."""
        self._assert_round_trip(4)

    def test_round_trip_length_12(self) -> None:
        """``rkey=None`` packs the 12-octet form and reads it back."""
        self._assert_round_trip(12)

    def test_round_trip_length_20(self) -> None:
        """Both keys pack the 20-octet form and read back."""
        self._assert_round_trip(20)

    def test_round_trip_length_22(self) -> None:
        """``dl_len`` without ``checksum`` packs the 22-octet form and reads it back."""
        self._assert_round_trip(22)

    def test_round_trip_length_24(self) -> None:
        """``dl_len`` and ``checksum`` pack the 24-octet form and read back."""
        self._assert_round_trip(24)

    def test_inconsistent_fields_are_rejected(self) -> None:
        """A later field without the one before it has no RFC 8684 length, so ``make`` refuses."""
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        tcp = TCP.__new__(TCP)
        for kwargs in ({'skey': None, 'rkey': 1}, {'rkey': None, 'dl_len': 1},
                       {'dl_len': None, 'checksum': b'\x00\x00'}):
            with self.subTest(**{k: repr(v) for k, v in kwargs.items()}), \
                    self.assertRaises(ProtocolError):
                tcp._make_mptcp_capable(Enum_MPTCPOption.MP_CAPABLE, **kwargs)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
