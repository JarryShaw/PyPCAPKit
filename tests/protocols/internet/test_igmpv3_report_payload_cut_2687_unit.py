# -*- coding: utf-8 -*-
"""An IGMPv3 Report cut inside its Additional Data packs back as captured (#2687).

``Report.post_process`` gives the octets past the counted records to ``payload``
(:rfc:`3376#section-4.2.11`), but the short read ``Schema.unpack`` recorded named
``records``, so packing the schema cut ``records`` and blanked the ``payload``
holding the captured octets. The protocol path rebuilds a cut layer from its info
instead, which hid it, so every case here is on the schema.

Every case builds its own octets.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class

#: A ``MODE_IS_INCLUDE`` record for 239.1.1.1 with the one source 10.0.0.1.
RECORD = bytes.fromhex('01000001' 'ef010101' '0a000001')


def _report(count: int, body: bytes) -> bytes:
    """An IGMPv3 Report counting ``count`` records, then ``body``; its checksum is zero."""
    return bytes([0x22, 0]) + bytes(4) + count.to_bytes(2, 'big') + body


#: ``(case, message, where its counted records end)``
SHAPES = (
    ('one record and extra octets', _report(1, RECORD + bytes.fromhex('cafebabe')), 8 + len(RECORD)),
    ('no records and extra octets', _report(0, bytes.fromhex('ca000000' 'deadbeef' '01020304')), 8),
    ('additional data holding a whole record', _report(1, RECORD + RECORD), 8 + len(RECORD)),
)


class ReportPayloadCutTests(unittest.TestCase):
    """At every cut inside the Additional Data, with the message's own length
    declared and one past it (#2687)."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def cases(self):
        """Yield ``(case, declared, cut, records_end)`` for every cut inside the Additional Data."""
        for case, message, records_end in SHAPES:
            for declared in (len(message), len(message) + 4):
                for keep in range(records_end + 1, len(message) + 1):
                    yield case, declared, message[:keep], records_end

    def test_unpack_then_pack_gives_the_capture(self) -> None:
        from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3

        for case, declared, cut, records_end in self.cases():
            with self.subTest(case, declared=declared, keep=len(cut)), warnings.catch_warnings():
                # a cut field warns that its length runs past the data, which is the point
                warnings.simplefilter('ignore')
                schema = IGMPv3.unpack(cut, declared)
                self.assertEqual(schema.body.payload, cut[records_end:])
                self.assertEqual(schema.pack(), cut)
                self.assertEqual(schema.pack(), cut)

    def test_from_dict_of_to_dict_gives_the_capture(self) -> None:
        from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3

        for case, declared, cut, _ in self.cases():
            with self.subTest(case, declared=declared, keep=len(cut)), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                schema = IGMPv3.from_dict(IGMPv3.unpack(cut, declared).to_dict())
                self.assertEqual(schema.pack(), cut)

    def test_the_cut_is_recorded_on_the_payload(self) -> None:
        """The short read names ``payload`` and the octets of it captured; a
        message captured whole records none."""
        from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3

        for case, declared, cut, records_end in self.cases():
            with self.subTest(case, declared=declared, keep=len(cut)), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                report = IGMPv3.unpack(cut, declared).body
                record = None if len(cut) == declared else ('payload', len(cut) - records_end)
                self.assertEqual(report.__dict__.get('__short_read__'), record)

    def test_a_cut_inside_the_records_stays_on_the_records(self) -> None:
        """The control: the data ends inside a record, so the cut stays on ``records``."""
        from pcapkit.protocols.schema.internet.igmpv3 import IGMPv3

        message = SHAPES[0][1]
        for keep in range(9, 8 + len(RECORD)):
            with self.subTest(keep=keep), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                schema = IGMPv3.unpack(message[:keep], len(message))
                self.assertEqual(schema.body.__dict__.get('__short_read__'), ('records', keep - 8))
                self.assertEqual(schema.body.payload, b'')
                self.assertEqual(schema.pack(), message[:keep])


if __name__ == '__main__':
    unittest.main()
