# -*- coding: utf-8 -*-
"""The TCP Quick-Start Response option (kind 27), read and constructed.

GitHub issue #1119 found two defects in this option:

* :meth:`TCP._read_mode_qs <pcapkit.protocols.transport.tcp.TCP._read_mode_qs>`
  read one octet past the option before checking its length, so every Quick-Start
  Response failed with ``StructError: unpack: empty buffer``, whether or not a
  payload followed.
* :meth:`TCP._make_mode_qs <pcapkit.protocols.transport.tcp.TCP._make_mode_qs>`
  computed the rate code as ``floor(log2(rate / 40))``. That is negative for
  ``0 < rate < 40`` kbps, and a negative code cannot pack into the 4-bit field.

:rfc:`4782` Section 4.2 gives the option layout, and Section 3.1 the rate
encoding: ``40 kbps * 2 ** N``, where ``N = 0`` means a rate of zero. Section 4.3
lets a response report a lower rate than the one requested, so a rate below the
smallest non-zero code (80 kbps) is rounded down to ``N = 0`` rather than refused.

Every case builds its own octets in memory, so this belongs to the unit tier.

:mod:`pcapkit` is resolved at call time, after
:func:`~tests._support.reimport_once_per_class`, not at module load: a
:class:`TCP` bound at load builds option schemas of whatever import was live
then, and once an earlier module has purged it, :meth:`ListField.pack
<pcapkit.corekit.fields.collections.ListField.pack>` checks them against the new
import's ``Schema`` and raises ``Field options has invalid value``.

"""
from __future__ import annotations

import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from pcapkit.const.tcp.option import Option
    from pcapkit.protocols.transport.tcp import TCP


def qs() -> 'Option':
    """Quick-Start Response option kind, per :rfc:`4782`."""
    from pcapkit.const.tcp.option import Option
    return Option.Quick_Start_Response


def build(rate: 'int', payload: 'bytes' = b'') -> 'bytes':
    """Construct a segment that carries one Quick-Start Response option."""
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(srcport=1, dstport=2, payload=payload,
               options=[(qs(), {'rate': rate, 'diff': 3, 'nonce': 0x1234})]).data


def parse(raw: 'bytes') -> 'TCP':
    """Parse ``raw`` as a TCP segment."""
    from pcapkit.protocols.transport.tcp import TCP
    return TCP(raw, len(raw))


class QuickStartResponseTests(unittest.TestCase):
    """Quick-Start Response against :rfc:`4782` Sections 3.1 and 4.2."""

    def setUp(self) -> 'None':
        reimport_once_per_class(self)

    def test_wire_octets_parse(self) -> 'None':
        """Hand-built option octets parse, with and without a payload."""
        QS = qs()
        option = bytes([27, 8, 0x04, 3]) + (0x1234 << 2).to_bytes(4, 'big')
        header = bytes.fromhex('0001000200000000000000007010ffff00000000')
        for payload in (b'', b'xyz'):
            with self.subTest(payload=payload):
                tcp = parse(header + option + payload)
                opt = tcp.info.options[QS]
                self.assertEqual(opt.length, 8)
                self.assertEqual(opt.req_rate, 640)
                self.assertEqual(opt.ttl_diff, 3)
                self.assertEqual(opt.nonce, 0x1234)
                self.assertEqual(bytes(tcp.payload.data), payload)

    def test_round_trip(self) -> 'None':
        """Construct, parse and construct again gives identical octets."""
        from pcapkit.protocols.transport.tcp import TCP

        QS = qs()
        for rate in (0, 80, 640, 1_310_720):
            for payload in (b'', b'xyz'):
                with self.subTest(rate=rate, payload=payload):
                    raw = build(rate, payload)
                    tcp = parse(raw)
                    self.assertEqual(tcp.info.options[QS].req_rate, rate)
                    again = TCP(srcport=1, dstport=2, payload=payload,
                                options=tcp.info.options).data
                    self.assertEqual(again, raw)
                    self.assertEqual(bytes(tcp.payload.data), payload)

    def test_rate_rounds_down_to_a_representable_code(self) -> 'None':
        """A rate is floored to ``40 * 2 ** N``, and below 80 kbps to ``N = 0``."""
        QS = qs()
        for rate, code in ((1, 0), (20, 0), (39, 0), (40, 0), (79, 0), (80, 1), (159, 1), (160, 2)):
            with self.subTest(rate=rate):
                raw = build(rate)
                self.assertEqual(raw[20:24], bytes([27, 8, code, 3]))
                self.assertEqual(parse(raw).info.options[QS].req_rate, 40 * 2 ** code if code else 0)


if __name__ == '__main__':
    unittest.main()
