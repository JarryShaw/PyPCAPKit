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
encoding: ``40 kbps * 2 ** N``, where ``N = 0`` means a rate of zero. A rate
between two codes rounds down to the lower one. The owner ruled on #2617 that a
rate the field cannot carry -- above zero but under the 80 kbps of ``N = 1``, or
past ``N = 15`` -- raises ``ProtocolError`` rather than being written as zero,
which is what #1119's fix had done.

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

    def test_rate_parses_as_an_int(self) -> 'None':
        """``req_rate`` is an :class:`int`, as annotated, not a float. See #2167."""
        QS = qs()
        for rate in (0, 80, 640, 1_310_720):
            with self.subTest(rate=rate):
                req_rate = parse(build(rate)).info.options[QS].req_rate
                self.assertIs(type(req_rate), int)
                self.assertEqual(req_rate, rate)

    def test_rate_rounds_down_to_a_representable_code(self) -> 'None':
        """A rate is floored to ``40 * 2 ** N``."""
        QS = qs()
        for rate, code in ((0, 0), (80, 1), (159, 1), (160, 2), (2_621_439, 15)):
            with self.subTest(rate=rate):
                raw = build(rate)
                self.assertEqual(raw[20:24], bytes([27, 8, code, 3]))
                self.assertEqual(parse(raw).info.options[QS].req_rate, 40 * 2 ** code if code else 0)

    def test_a_rate_the_field_cannot_carry_is_refused(self) -> 'None':
        """Under 80 kbps but not zero, negative, or past ``N = 15``: refused, not zeroed (#2617)."""
        from pcapkit.utilities.exceptions import ProtocolError

        for rate in (-1, 1, 20, 39, 40, 79, 2_621_440):
            with self.subTest(rate=rate):
                with self.assertRaisesRegex(ProtocolError, rf'^TCP: invalid Quick-Start rate: {rate}$'):
                    build(rate)

    def test_a_field_value_outside_its_bits_is_refused(self) -> 'None':
        """The nonce (30 bits), ``Resv.`` (4) and ``R`` (2): refused, not wrapped or leaked (#2617)."""
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        for keyword, what, values in (('nonce', 'nonce', (-1, 1 << 30, True)),
                                      ('reserved', 'reserved', (-1, 16, True)),
                                      ('nonce_reserved', 'nonce reserved', (-1, 4, True))):
            for value in values:
                with self.subTest(field=keyword, value=value):
                    with self.assertRaisesRegex(ProtocolError, rf'^TCP: invalid Quick-Start {what}: {value!r}$'):
                        TCP(srcport=1, dstport=2, options=[(qs(), {'rate': 80, keyword: value})])

    def test_ttl_diff_is_taken_modulo_256(self) -> 'None':
        """:rfc:`4782` Section 3.1 defines TTL Diff modulo 256, so its octet wraps."""
        from pcapkit.protocols.transport.tcp import TCP

        for diff, octet in ((255, 0xff), (256, 0x00), (300, 0x2c), (-1, 0xff)):
            with self.subTest(diff=diff):
                raw = TCP(srcport=1, dstport=2, options=[(qs(), {'rate': 80, 'diff': diff})]).data
                self.assertEqual(raw[23], octet)


if __name__ == '__main__':
    unittest.main()
