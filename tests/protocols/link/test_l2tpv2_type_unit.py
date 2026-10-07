# -*- coding: utf-8 -*-
"""L2TPv2 reads and writes the ``T`` bit, and sets ``L``, as :rfc:`2661` says.

GitHub issue #1175: :class:`~pcapkit.const.l2tp.type.Type` had ``Control = 0``
and ``Data = 1``, the reverse of :rfc:`2661` §3.1, which sets ``T`` "to 0 for a
data message and 1 for a control message". So the control ZLB ACK
``c802000c0001000000010002`` parsed as ``Data``, and
:meth:`~pcapkit.protocols.link.l2tpv2.L2TPv2.make`'s default ``Type.Data``
wrote a control header. ``make()`` also wrote ``L=0`` for a control message
given no ``total_length``, though §3.1 requires ``L=1`` there, and a
``from_data`` rebuild zeroed a non-zero offset pad.

Every case builds its own octets in memory and reads no capture.

:class:`L2TPv2` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, for the
reason :mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

import io
import unittest

from tests._support import reimport_once_per_class

#: A control ZLB ACK: ``T``, ``L`` and ``S`` set, tunnel 1, Ns 1, Nr 2.
ZLB_ACK = bytes.fromhex('c802000c0001000000010002')

#: A data message with ``O`` set and a three-octet, non-zero offset pad.
PADDED = bytes.fromhex('0202' '0001' '0002' '0003' '010203' 'ff03')


class TestL2TPv2Type(unittest.TestCase):
    """Pin the ``T`` bit values and the ``L`` bit of a control message."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_enum_values_follow_rfc_2661(self) -> None:
        from pcapkit.const.l2tp.type import Type

        self.assertEqual(Type.Data, 0)
        self.assertEqual(Type.Control, 1)
        self.assertIs(Type(0), Type.Data)
        self.assertIs(Type(1), Type.Control)

    def test_zlb_ack_parses_as_control(self) -> None:
        from pcapkit.const.l2tp.type import Type
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        parsed = L2TPv2(io.BytesIO(ZLB_ACK), len(ZLB_ACK))
        self.assertIs(parsed.info.flags.type, Type.Control)

    def test_default_make_is_a_data_message(self) -> None:
        from pcapkit.const.l2tp.type import Type
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        made = L2TPv2(tunnel_id=1, session_id=2)
        self.assertEqual(made.data, bytes.fromhex('0002' '0001' '0002'))
        self.assertIs(made.info.flags.type, Type.Data)

    def test_make_control_sets_l_and_the_real_length(self) -> None:
        from pcapkit.const.l2tp.type import Type
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        self.assertEqual(L2TPv2(type=Type.Control, tunnel_id=1, ns=1, nr=2).data, ZLB_ACK)

        made = L2TPv2(type=Type.Control, tunnel_id=1, session_id=2, payload=b'abcd')
        self.assertEqual(made.data, bytes.fromhex('c002' '000c' '0001' '0002') + b'abcd')
        self.assertTrue(made.info.flags.len)
        self.assertEqual(made.info.length, 12)

    def test_make_writes_an_explicit_total_length_as_given(self) -> None:
        from pcapkit.const.l2tp.type import Type
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        made = L2TPv2(type=Type.Control, tunnel_id=1, ns=1, nr=2, total_length=99)
        self.assertEqual(made.info.length, 99)

    def test_make_rejects_total_length_without_the_length_field(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            L2TPv2(total_length=12, length_flag=False)

    def test_control_without_l_rebuilds_as_captured(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        raw = bytes.fromhex('8802' '0001' '0000' '0000' '0001')  # T and S, no L
        parsed = L2TPv2(io.BytesIO(raw), len(raw))
        self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_offset_pad_survives_from_data(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        parsed = L2TPv2(io.BytesIO(PADDED), len(PADDED))
        self.assertEqual(parsed.info.padding, b'\x01\x02\x03')
        self.assertEqual(L2TPv2.from_data(parsed.info).data, PADDED)


if __name__ == '__main__':
    unittest.main()
