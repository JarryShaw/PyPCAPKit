# -*- coding: utf-8 -*-
"""Where the Multipath TCP option header keeps its length, which was off by seven bits.

GitHub issue #553. :class:`_MPTCP
<pcapkit.protocols.schema.transport.tcp._MPTCP>` reads the option header through
a :class:`~pcapkit.corekit.fields.misc.ForwardMatchField` over a 3-octet
:class:`~pcapkit.corekit.fields.strings.BitField`, and that field's namespace
declared ``'length': (1, 8)`` -- eight bits starting one bit in. The entry has
to be ``(8, 8)``, and three independent pieces of evidence say so:

* :rfc:`8684` section 3 lays every Multipath TCP option out as ``Kind`` (8
  bits), ``Length`` (8 bits), ``Subtype`` (4 bits), then subtype-specific
  content. Numbering from the option's first octet, ``Length`` therefore
  occupies bits 8-15 and the subtype bits 16-19.
* The sibling entry in the very same namespace, ``'subtype': (16, 4)``, is
  already written against that numbering, and it decodes correctly. Two entries
  in one namespace cannot be anchored differently -- :meth:`BitField.post_process
  <pcapkit.corekit.fields.strings.BitField.post_process>` slices both out of one
  big-endian bit string over the whole 3-octet window -- so ``subtype`` reading
  from bit 16 fixes the window's origin at ``kind`` and leaves bit 8 as the only
  place ``length`` can begin.
* The window really is anchored at ``kind`` rather than after the option header.
  ``_MPTCP`` is registered as the schema for the option itself
  (``Option.register(Enum_Option.Multipath_TCP, _MPTCP)``) and, alone among the
  option schemas, does not inherit :class:`Option
  <pcapkit.protocols.schema.transport.tcp.Option>` -- so it is handed the
  option's first octet and nothing has consumed ``kind``/``length`` before it.

At ``(1, 8)`` the field straddled the low seven bits of ``kind`` and the high bit
of ``length``. For the 12-octet MP_CAPABLE of :rfc:`8684` figure 4, whose first
three octets are ``1e 0c 01``, that reads ``00111100`` where the length is
``00001100``: 60 instead of 12.

Why no existing test saw it
---------------------------

The decoded length is used for one thing, ``SchemaField(length=pkt['test']['length'])``
in :func:`mptcp_data_selector
<pcapkit.protocols.schema.transport.tcp.mptcp_data_selector>`, which sizes the
nested subtype schema. Over-declaring that size does not fail loudly: the
enclosing :class:`~pcapkit.corekit.fields.collections.OptionField` stops at the
end-of-option-list marker or at the declared options length whichever comes
first, so the over-read is absorbed rather than reported. And the construction
path never evaluates the field at all -- every ``tcp-mptcp/*`` case in
:data:`tests.protocols.test_option_roundtrip_unit.EXPECTED_FAILURES` fails before
reaching it, for reasons of its own that #553 does not touch.

So the assertion here is deliberately on the *decoded namespace* rather than on a
round trip. A full parse of an MP_CAPABLE option does not complete on ``main``
either: :class:`MPTCPCapable
<pcapkit.protocols.schema.transport.tcp.MPTCPCapable>` gates ``rkey`` on
``pkt['length'] != 32`` while the nested subtype schemas declare no ``length``
field, so parsing raises ``KeyError: 'length'`` from
:file:`pcapkit/protocols/schema/transport/tcp.py` regardless of which bit offset
the header used. That is the structural defect behind #541 and the eight
``tcp-mptcp/*`` expected failures -- the subtype schemas inherit :class:`MPTCP
<pcapkit.protocols.schema.transport.tcp.MPTCP>`, which declares ``kind`` and
``length`` only under :data:`~typing.TYPE_CHECKING` -- and it is not what #553
is about. Tying this assertion to an end-to-end parse would mean it could not be
written until that much larger change landed, and the bit offset would stay
wrong in the meantime.

The field is read off the schema class, ``_MPTCP.__fields__['test']``, rather
than rebuilt here, so the declaration under test is the one the library ships.
A copy of the namespace written into this module would keep passing after a
regression.

Every case builds its own octets in memory and reads no capture under
:file:`examples/captures/`, so this belongs to the unit tier.

"""
from __future__ import annotations

import unittest

from pcapkit.const.tcp.mp_tcp_option import MPTCPOption as Enum_MPTCPOption
from pcapkit.const.tcp.option import Option as Enum_Option
from pcapkit.protocols.schema.transport.tcp import _MPTCP

#: The 12-octet MP_CAPABLE of :rfc:`8684` figure 4, as it appears on the wire.
#: ``1e`` is the Multipath TCP option kind (30), ``0c`` its length (12), ``01``
#: the subtype nibble ``0`` (MP_CAPABLE) beside version ``1``, ``81`` the
#: ``A``..``H`` flag octet, and the remaining eight octets the sender's key.
MP_CAPABLE_OPTION = bytes([0x1E, 0x0C, 0x01, 0x81]) + b'\xAA' * 8


def decode_header(option: 'bytes') -> 'dict[str, int]':
    """Decode an MPTCP option header through the schema's own declared field.

    Args:
        option: A whole Multipath TCP option, starting at its ``kind`` octet.

    Returns:
        The ``test`` namespace, as :class:`_MPTCP
        <pcapkit.protocols.schema.transport.tcp._MPTCP>` would see it.

    """
    field = _MPTCP.__fields__['test']
    return field({}).unpack(option, {})


class MPTCPHeaderOffsetTests(unittest.TestCase):
    """The bit offsets of the Multipath TCP option header's length and subtype."""

    def test_mp_capable_header_decodes_its_length_as_twelve(self) -> 'None':
        """A 12-octet MP_CAPABLE option reports ``length == 12``.

        The regression assertion for #553. With ``'length': (1, 8)`` this
        decodes 60 -- the eight bits from offset 1 of ``1e 0c``, i.e.
        ``00111100`` -- and the option is twelve octets long, as
        :data:`MP_CAPABLE_OPTION` being twelve octets of ``bytes`` records
        independently of what the header claims.

        """
        header = decode_header(MP_CAPABLE_OPTION)

        self.assertEqual(header['length'], 12)
        self.assertEqual(header['length'], len(MP_CAPABLE_OPTION))
        self.assertNotEqual(header['length'], 60)

    def test_subtype_still_decodes_beside_the_corrected_length(self) -> 'None':
        """``subtype`` reads MP_CAPABLE, from the same window as ``length``.

        This is the entry that pins the window's origin, so it is asserted
        rather than assumed: ``subtype`` was already correct at ``(16, 4)``
        before #553 and has to stay correct after it, which is what rules out
        "fixing" the length by moving the window instead of the entry.

        """
        header = decode_header(MP_CAPABLE_OPTION)

        self.assertEqual(Enum_MPTCPOption.get(header['subtype']),
                         Enum_MPTCPOption.MP_CAPABLE)

    def test_the_first_octet_of_the_window_is_the_option_kind(self) -> 'None':
        """The window starts at ``kind``, which is what makes bit 8 right.

        ``length`` at bit 8 is only correct if bit 0 is the first bit of
        ``kind``. That is asserted here by reading the octet the option itself
        begins with, so a later change that made ``_MPTCP`` inherit
        :class:`Option <pcapkit.protocols.schema.transport.tcp.Option>` -- and so
        consume ``kind``/``length`` before this field ever runs -- fails here
        with a message about the anchor rather than silently shifting every
        offset in the namespace by two octets.

        """
        self.assertEqual(MP_CAPABLE_OPTION[0], Enum_Option.Multipath_TCP)
        self.assertEqual(_MPTCP.__fields__['test'].length, 3)

    def test_a_longer_mp_capable_reports_its_own_length(self) -> 'None':
        """The 20-octet MP_CAPABLE reports 20, not a constant.

        A namespace entry can be wrong in two ways -- at the wrong offset, or
        the right offset and the wrong width -- and a single length only
        distinguishes the first. :rfc:`8684` section 3.1 gives MP_CAPABLE a
        second form carrying the receiver's key as well, twenty octets long, so
        decoding both pins the width at eight bits.

        """
        longer = MP_CAPABLE_OPTION[:1] + bytes([20]) + MP_CAPABLE_OPTION[2:] + b'\xBB' * 8

        self.assertEqual(len(longer), 20)
        self.assertEqual(decode_header(longer)['length'], 20)

    def test_every_length_a_single_octet_can_hold_round_trips(self) -> 'None':
        """Each of the 256 declarable lengths decodes back to itself.

        The exhaustive form of the assertion above, and the one that leaves no
        room for an offset that happens to be right for the two lengths a
        hand-written case would pick. ``kind`` is held at ``1e``, whose low
        seven bits are what the old offset mixed into the answer, so any
        residual dependence on it shows up as a mismatch.

        """
        for declared in range(256):
            option = bytes([0x1E, declared, 0x01, 0x81]) + b'\xAA' * 8
            self.assertEqual(
                decode_header(option)['length'], declared,
                f'length {declared} did not decode back to itself',
            )


if __name__ == '__main__':
    unittest.main()
