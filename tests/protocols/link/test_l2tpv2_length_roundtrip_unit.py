# -*- coding: utf-8 -*-
"""L2TPv2 keeps the ``L`` flag and the Length field through ``from_data``.

GitHub issue #1172: :meth:`L2TPv2._make_data
<pcapkit.protocols.link.l2tpv2.L2TPv2._make_data>` returned the parsed Length
under ``length``, which is the parse length
:class:`~pcapkit.protocols.protocol.ProtocolBase` takes for itself, so it never
reached :meth:`~pcapkit.protocols.link.l2tpv2.L2TPv2.make`. The rebuild then
cleared ``L`` and omitted the two Length octets: ``c802000c0001000000010002``
came back as ``88020001000000010002``.

Every case builds its own octets in memory and reads no capture.

:class:`L2TPv2` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, for the
reason :mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit` gives.

"""

import io
import itertools
import unittest

from tests._support import reimport_once_per_class

#: A PPP frame header, as the L2TPv2 payload.
PAYLOAD = bytes.fromhex('ff030021')


def build(type_: int, len_: int, seq: int, offset: int, pad: int) -> bytes:
    """Build an L2TPv2 datagram with the given optional fields present."""
    flags = (type_ << 15) | (len_ << 14) | (seq << 11) | (offset << 9) | 2
    hdr_len = 6 + 2 * (len_ + 2 * seq + offset) + pad
    body = b''
    if len_:
        body += (hdr_len + len(PAYLOAD)).to_bytes(2, 'big')
    body += (7).to_bytes(2, 'big') + (9).to_bytes(2, 'big')
    if seq:
        body += (3).to_bytes(2, 'big') + (4).to_bytes(2, 'big')
    if offset:
        body += pad.to_bytes(2, 'big') + bytes(pad)
    return flags.to_bytes(2, 'big') + body + PAYLOAD


#: Every combination of ``T``, ``L``, ``S`` and ``O``; with ``O``, both an
#: empty and a three-octet (zero) offset pad.
COMBINATIONS = [
    (t, l, s, o, pad)
    for t, l, s, o in itertools.product((0, 1), repeat=4)
    for pad in ((0, 3) if o else (0,))
]


class TestL2TPv2LengthRoundTrip(unittest.TestCase):
    """Pin that the Length field survives a ``from_data`` rebuild."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_issue_reproduction(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        raw = bytes.fromhex('c802000c0001000000010002')  # ZLB ACK: T, L and S set
        parsed = L2TPv2(raw)
        self.assertTrue(parsed.info.flags.len)
        self.assertEqual(parsed.info.length, 12)
        self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_every_flag_combination_round_trips(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        self.assertEqual(len(COMBINATIONS), 24)
        for t, l, s, o, pad in COMBINATIONS:
            raw = build(t, l, s, o, pad)
            with self.subTest(T=t, L=l, S=s, O=o, pad=pad, raw=raw.hex()):
                parsed = L2TPv2(io.BytesIO(raw), len(raw))
                self.assertEqual(L2TPv2.from_data(parsed.info).data, raw)

    def test_make_data_passes_the_length_as_total_length(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        values = L2TPv2._make_data(L2TPv2(build(1, 1, 1, 0, 0)).info)
        self.assertNotIn('length', values)
        self.assertEqual(values['total_length'], 16)

        values = L2TPv2._make_data(L2TPv2(build(0, 0, 0, 0, 0)).info)
        self.assertIsNone(values['total_length'])

    def test_make_sets_l_flag_only_with_total_length(self) -> None:
        from pcapkit.protocols.link.l2tpv2 import L2TPv2

        # ``type`` is passed as the raw ``T`` bit so the octets do not depend on
        # how :class:`~pcapkit.const.l2tp.type.Type` names it.
        with_len = L2TPv2(type=0, tunnel_id=7, session_id=9, total_length=12,
                          payload=PAYLOAD)
        self.assertEqual(with_len.data, build(0, 1, 0, 0, 0))
        self.assertTrue(with_len.info.flags.len)
        self.assertEqual(with_len.info.length, 12)

        without = L2TPv2(type=0, tunnel_id=7, session_id=9, payload=PAYLOAD)
        self.assertEqual(without.data, build(0, 0, 0, 0, 0))
        self.assertFalse(without.info.flags.len)
        self.assertIsNone(without.info.length)


if __name__ == '__main__':
    unittest.main()
