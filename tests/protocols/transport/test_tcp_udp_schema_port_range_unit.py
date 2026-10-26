# -*- coding: utf-8 -*-
"""A TCP or UDP schema built directly rejects a port outside ``0``-``65535``.

GitHub issue #2314. :meth:`~pcapkit.corekit.fields.numbers.NumberField.pre_process`
masks a value to the field's width, which is the documented schema contract
(#1488), so ``Schema_UDP(srcport=70000, ...)`` packed ``0x1170`` with no error.
The owner ruled that the masking stays and that the ports get their range check
from :class:`~pcapkit.corekit.fields.numbers.PortEnumField`, the field the
schemas carry them on. These tests pin that an out-of-range port is rejected on
both ports of both schemas, and that the boundary ports still close byte-exact.

"""
import unittest
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): a hand-picked round trip over the ``int`` boundaries of a
#: two-octet field.
__tier__ = 'ALL'

#: Ports the issue measured masking, one past each end and well past the top.
OUT_OF_RANGE = (-1, 65536, 70000)

#: The two ends of a two-octet port.
BOUNDARIES = (0, 65535)


class SchemaPortRangeTests(unittest.TestCase):
    """Out-of-range ports, and the boundary round trip, on the TCP and UDP schemas."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _udp(**ports: 'int') -> 'Any':
        from pcapkit.protocols.schema.transport.udp import UDP

        values = {'srcport': 1024, 'dstport': 53, 'len': 8, 'checksum': b'\x00\x00', 'payload': b''}
        values.update(ports)
        return UDP(**values)

    @staticmethod
    def _tcp(**ports: 'int') -> 'Any':
        from pcapkit.protocols.schema.transport.tcp import TCP

        flags = dict.fromkeys(('cwr', 'ece', 'urg', 'ack', 'psh', 'rst', 'syn', 'fin'), 0)
        values = {'srcport': 1024, 'dstport': 80, 'seq': 0, 'ack': 0,
                  'offset': {'offset': 5, 'reserved': 0, 'ns': 0}, 'flags': flags,
                  'window': 0, 'checksum': b'\x00\x00', 'urgent': 0, 'options': [], 'payload': b''}
        values.update(ports)
        return TCP(**values)

    def test_an_out_of_range_port_is_rejected_on_packing(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        for name, build in (('UDP', self._udp), ('TCP', self._tcp)):
            for field in ('srcport', 'dstport'):
                for port in OUT_OF_RANGE:
                    with self.subTest(schema=name, field=field, port=port):
                        with self.assertRaisesRegex(FieldValueError, rf'port {port} is outside 0-65535'):
                            build(**{field: port}).pack()

    def test_the_boundary_ports_round_trip_byte_exact(self) -> None:
        from pcapkit.protocols.schema.transport.tcp import TCP
        from pcapkit.protocols.schema.transport.udp import UDP

        for name, schema, build in (('UDP', UDP, self._udp), ('TCP', TCP, self._tcp)):
            for srcport in BOUNDARIES:
                for dstport in BOUNDARIES:
                    with self.subTest(schema=name, srcport=srcport, dstport=dstport):
                        octets = build(srcport=srcport, dstport=dstport).pack()
                        self.assertEqual(octets[:4], srcport.to_bytes(2, 'big') + dstport.to_bytes(2, 'big'))
                        parsed = schema.unpack(octets)
                        self.assertEqual((parsed.srcport.port, parsed.dstport.port), (srcport, dstport))
                        self.assertEqual(parsed.pack(), octets)


if __name__ == '__main__':
    unittest.main()
