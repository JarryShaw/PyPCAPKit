# -*- coding: utf-8 -*-
"""An unknown Multipath TCP subtype declares the length it actually packs, 3 octets at least.

GitHub issue #2272. ``TCP._make_mptcp_unknown`` sized the option as ``2 + len(data)``, one
octet short exactly when ``data`` is empty.

Where the octet goes missing
----------------------------

:class:`~pcapkit.protocols.transport.tcp.schema.MPTCPUnknown` always packs three header
octets -- ``kind`` and ``length``, declared on
:class:`~pcapkit.protocols.transport.tcp.schema.MPTCP` (#541), and its own ``test``
:class:`~pcapkit.corekit.fields.strings.BitField`, whose high nibble is the subtype and low
nibble takes ``data[0]`` -- then ``data[1:]`` as the body. The option is therefore
``3 + len(data[1:])`` octets, never fewer than the 3 (``Kind``, ``Length``, ``Subtype``)
:rfc:`8684` section 3 requires.

``2 + len(data)`` agrees for every non-empty ``data`` and declares 2 only at ``data=b''``,
where the schema still writes three octets, so the maker's own one-octet default cannot see
the defect.

The parse side sizes ``MPTCPUnknown.data``, a
:class:`~pcapkit.corekit.fields.strings.BytesField`, as ``pkt['length'] - 3``. At a declared
2 that is ``-1``: reading the segment back warns ``SchemaWarning: packet length < 0: -1`` and
raises ``ProtocolError: Field data resolved to a negative length; template='-1s'``. The
option is unreadable, not just mislabelled, so
:meth:`TCPMPTCPUnknownLengthUnitTests.test_empty_data_round_trips_through_tcp` asserts a
parse rather than an octet count.

Coverage
--------

:meth:`~TCPMPTCPUnknownLengthUnitTests.test_declared_length_matches_wire_length` asserts the
broken invariant across payload widths, so a fix that trades the empty case for a wide one
is caught. The rest pin what must *not* move: the minimum octets, the non-empty widths, and
the maker's default.

``data=b''`` and ``data=b'\\x00'`` both pack to ``1e03f0`` and read back as
``data=b'\\x00'``: the header's low nibble is always written and read, so an absent and a
zero first octet are the same on the wire. That is :rfc:`8684`'s layout, not this fix;
:meth:`~TCPMPTCPUnknownLengthUnitTests.test_empty_and_zero_data_pack_alike` records it so
the asymmetry is not mistaken for the defect.

Unit tier: every case builds its own octets and reads no capture.

"""
from __future__ import annotations

import unittest
import warnings

#: The smallest Multipath TCP option :rfc:`8684` section 3 permits: ``Kind`` ``0x1e``,
#: ``Length`` ``3``, then the subtype nibble ``0xf``
#: (:attr:`~pcapkit.const.tcp.mp_tcp_option.MPTCPOption.Reserved_for_Private_Use`) beside an
#: all-zero data nibble. This is what ``data=b''`` has to produce.
MINIMUM_UNKNOWN_OPTION = bytes([0x1E, 0x03, 0xF0])

#: Payload widths and the octets the maker must produce for each, derived by adding up what
#: :class:`~pcapkit.protocols.transport.tcp.schema.MPTCPUnknown` packs: ``kind``, ``length``,
#: the subtype/data octet, then ``data[1:]``. Only the first entry changed with #2272; the
#: rest are pinned so the fix is shown to be confined to the empty case.
UNKNOWN_PAYLOAD_CASES = (
    (b'', bytes([0x1E, 0x03, 0xF0])),
    (b'\x05', bytes([0x1E, 0x03, 0xF5])),
    (b'\x05\x06', bytes([0x1E, 0x04, 0xF5, 0x06])),
    (b'\x05\x06\x07', bytes([0x1E, 0x05, 0xF5, 0x06, 0x07])),
)

#: Header fields shared by every constructed TCP segment in this module, matching
#: :data:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.TCP_BASE`.
TCP_BASE = {
    'srcport': 50000, 'dstport': 80, 'seq_no': 1, 'ack_no': 0,
    'ns': False, 'cwr': False, 'ece': False, 'urg': False, 'ack': False,
    'psh': False, 'rst': False, 'syn': True, 'fin': False,
    'window': 8192, 'checksum': b'\x00\x00', 'urgent': 0,
    'payload': b'',
}


def make_unknown(**kwargs: 'object') -> 'bytes':
    """Build an unknown-subtype MPTCP option through its maker and pack it.

    Args:
        **kwargs: forwarded to
            :meth:`~pcapkit.protocols.transport.tcp.protocol.TCP._make_mptcp_unknown` as the option's
            own arguments. Passing none exercises the maker's default payload.

    Returns:
        The packed option bytes.

    Note:
        ``pcapkit`` is imported here, inside the function, rather than at module level, for
        the reason
        :func:`tests.protocols.transport.test_tcp_mptcp_subtype_unit.build_mptcp_option`'s own
        docstring records: another module in this suite pops ``pcapkit``'s submodules out of
        :data:`sys.modules`, so a name bound at collection time can end up pointing at a
        schema class built from a stale ``Schema`` base.

    """
    from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
    from pcapkit.protocols.transport.tcp.protocol import TCP

    tcp = TCP.__new__(TCP)
    schema = tcp._make_mptcp_unknown(  # pylint: disable=protected-access
        Enum_MPTCPOption.Reserved_for_Private_Use, **kwargs)  # type: ignore[arg-type]
    return schema.pack()


class TCPMPTCPUnknownLengthUnitTests(unittest.TestCase):
    """``_make_mptcp_unknown`` writes a ``Length`` octet that counts the octets it packs."""

    def test_declared_length_matches_wire_length(self) -> None:
        """Every payload width declares its own octet count.

        The invariant #2272 broke, and the one assertion here that fails on ``main``: at
        ``data=b''`` the option is 3 octets long and its ``Length`` octet reads 2.

        """
        for data, expected in UNKNOWN_PAYLOAD_CASES:
            with self.subTest(data=data):
                packed = make_unknown(data=data)

                self.assertEqual(len(packed), len(expected),
                                 'the option must occupy the octets the schema packs')
                self.assertEqual(packed[1], len(packed),
                                 'the declared length octet must match the wire length')

    def test_packs_the_expected_octets(self) -> None:
        """Each payload width packs byte-exactly what RFC 8684's layout gives.

        A declared length and a packed length can agree while both are wrong, so the octets
        themselves are pinned as well as their count.

        """
        for data, expected in UNKNOWN_PAYLOAD_CASES:
            with self.subTest(data=data):
                self.assertEqual(make_unknown(data=data), expected)

    def test_empty_data_packs_the_minimum_option(self) -> None:
        """``data=b''`` gives the 3-octet minimum of :rfc:`8684` section 3, ``1e03f0``."""
        self.assertEqual(make_unknown(data=b''), MINIMUM_UNKNOWN_OPTION)

    def test_default_payload_is_unchanged(self) -> None:
        """The maker's own ``data=b'\\x00'`` default still packs ``1e03f0``.

        ``2 + len(data)`` and ``3 + len(data[1:])`` agree at one octet, so the default --
        which is what every caller who names no payload gets -- must come through #2272
        untouched.

        """
        self.assertEqual(make_unknown(), MINIMUM_UNKNOWN_OPTION)

    def test_empty_and_zero_data_pack_alike(self) -> None:
        """``b''`` and ``b'\\x00'`` are the same three octets on the wire.

        Not a defect: the subtype octet's low nibble is written either way, so there is no
        encoding that distinguishes them. Recorded so the surviving asymmetry is not mistaken
        for the one #2272 fixed.

        """
        self.assertEqual(make_unknown(data=b''), make_unknown(data=b'\x00'))

    def test_empty_data_round_trips_through_tcp(self) -> None:
        """A segment built with ``data=b''`` parses back, rather than raising.

        On ``main`` this is where the mismatch bites: ``MPTCPUnknown.data`` sizes itself
        ``pkt['length'] - 3``, so a declared 2 warns ``SchemaWarning: packet length < 0: -1``
        and raises ``ProtocolError: Field data resolved to a negative length;
        template='-1s'``. Asserted through the public constructor and a real parse, so a
        pack-side fix that left the option unreadable would still fail.

        """
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP

        tcp = TCP(options=[(Enum_Option.Multipath_TCP, {
            'subtype': Enum_MPTCPOption.Reserved_for_Private_Use,
            'data': b'',
        })], **TCP_BASE)  # type: ignore[arg-type]
        raw = tcp.data

        # the option, then the one End-of-Option-List octet that pads it to a 4-octet word
        self.assertEqual(raw[20:], MINIMUM_UNKNOWN_OPTION + b'\x00')

        with warnings.catch_warnings():
            warnings.simplefilter('error')
            data = TCP(raw, len(raw)).info.options[Enum_Option.Multipath_TCP]

        self.assertEqual(data.subtype, Enum_MPTCPOption.Reserved_for_Private_Use)
        self.assertEqual(data.length, 3)
        self.assertEqual(data.data, b'\x00')


if __name__ == '__main__':
    unittest.main()
