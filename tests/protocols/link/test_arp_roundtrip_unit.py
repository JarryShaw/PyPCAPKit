# -*- coding: utf-8 -*-
"""ARP, InARP, RARP and DRARP rebuild every header they parse byte for byte.

GitHub issues:

* #1204: :class:`~pcapkit.protocols.link.arp.InARP` and
  :class:`~pcapkit.protocols.application.rarp.DRARP` did not pass
  ``schema=``/``data=``, so they fell back to the ``Raw`` schema and could not
  parse any input.
* #1205: an Ethernet hardware address whose ``hlen`` is not 6 was read as
  colon-joined hex, but :meth:`ARP._make_addr_resolve
  <pcapkit.protocols.link.arp.ARP._make_addr_resolve>` accepted only a
  6-octet MAC.
* #1206: the protocol address was decoded as IPv4 or IPv6 by its length alone,
  ignoring ``ptype``/``plen``, so a mismatched pair either decoded as the other
  version or raised a bare :exc:`ValueError`.

Every case builds its own octets in memory and reads no capture.

The classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load (c.f.
``tests/protocols/link/test_ethernet_mac_roundtrip_unit.py``).

"""

import importlib
import unittest

from tests._support import reimport_once_per_class

#: ``(module, class)`` for every ARP-family class.
CLASSES = (
    ('pcapkit.protocols.link.arp', 'ARP'),
    ('pcapkit.protocols.link.arp', 'InARP'),
    ('pcapkit.protocols.application.rarp', 'RARP'),
    ('pcapkit.protocols.application.rarp', 'DRARP'),
)


def _header(ptype: str, hlen: int, plen: int, oper: str) -> bytes:
    """Ethernet-htype header with distinct, non-zero addresses."""
    return bytes.fromhex('0001' + ptype + f'{hlen:02x}{plen:02x}' + oper
                         + '01' * hlen + 'a1' * plen + '02' * hlen + 'b2' * plen)


class TestARPRoundTrip(unittest.TestCase):
    """Parse, then ``from_data``, reproduces the original octets."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _cls(self, module: str, name: str) -> type:
        return getattr(importlib.import_module(module), name)

    def assertRoundTrips(self, cls: type, data: bytes) -> None:
        parsed = cls(data)
        self.assertEqual(cls.from_data(parsed.info).data, data)

    def test_subclasses_use_arp_schema(self) -> None:
        """#1204: InARP and DRARP inherit ARP's schema and data classes."""
        from pcapkit.protocols.data.link.arp import ARP as Data_ARP
        from pcapkit.protocols.schema.link.arp import ARP as Schema_ARP

        for module, name in CLASSES:
            with self.subTest(cls=name):
                cls = self._cls(module, name)
                self.assertIs(cls.__schema__, Schema_ARP)
                self.assertIs(cls.__data__, Data_ARP)

    def test_subclasses_round_trip(self) -> None:
        """#1204: the issue's repro parses and rebuilds for InARP and DRARP."""
        for module, name, oper in (('pcapkit.protocols.link.arp', 'InARP', '0008'),
                                   ('pcapkit.protocols.application.rarp', 'DRARP', '0005')):
            with self.subTest(cls=name):
                cls = self._cls(module, name)
                data = bytes.fromhex('000108000604' + oper + '001122334455' '0a000001'
                                     '66778899aabb' '0a000002')
                parsed = cls(data)
                self.assertEqual(str(parsed.info.spa), '10.0.0.1')
                self.assertRoundTrips(cls, data)

    def test_ethernet_hlen_other_than_six(self) -> None:
        """#1205: any Ethernet ``hlen`` that parses also rebuilds."""
        for module, name in CLASSES:
            for hlen in (0, 1, 8, 20):
                with self.subTest(cls=name, hlen=hlen):
                    cls = self._cls(module, name)
                    self.assertRoundTrips(cls, _header('0800', hlen, 4, '0001'))

    def test_ethernet_issue_repro_round_trips(self) -> None:
        """#1205: the issue's parsed hlen-8 and hlen-0 headers rebuild."""
        from pcapkit.protocols.link.arp import ARP

        for hlen, data in (
            (8, bytes.fromhex('0001080008040001' + '01' * 8 + '0a000001' + '02' * 8 + '0a000002')),
            (0, bytes.fromhex('0001080000040001' '0a000001' '0a000002')),
        ):
            with self.subTest(hlen=hlen):
                parsed = ARP(data)
                self.assertEqual(parsed.info.hlen, hlen)
                self.assertRoundTrips(ARP, data)

    def test_ethernet_make_without_hlen_requires_six_octets(self) -> None:
        """#1205: with ``htype`` Ethernet and no ``hlen``, a MAC is 6 octets."""
        from pcapkit.utilities.exceptions import ProtocolError

        for module, name in CLASSES:
            cls = self._cls(module, name)
            for addr in ('00:11:22:33:44', '', '00:11:22:33:44:55:66'):
                with self.subTest(cls=name, addr=addr):
                    with self.assertRaises(ProtocolError):
                        cls(htype=1, sha=addr, tha=addr, spa='10.0.0.1', tpa='10.0.0.2')
            with self.subTest(cls=name, addr='six octets'):
                proto = cls(htype=1, sha='00:11:22:33:44:55', tha='66:77:88:99:aa:bb',
                            spa='10.0.0.1', tpa='10.0.0.2')
                self.assertEqual(proto.info.hlen, 6)

    def test_make_accepts_any_octets_with_explicit_hlen_or_other_htype(self) -> None:
        """#1205: an explicit ``hlen``, or a non-Ethernet ``htype``, takes any count."""
        from pcapkit.const.arp.hardware import Hardware

        for module, name in CLASSES:
            cls = self._cls(module, name)
            for hlen, addr in ((5, '00:11:22:33:44'), (0, ''), (8, '01:01:01:01:01:01:01:01')):
                with self.subTest(cls=name, hlen=hlen):
                    proto = cls(htype=1, hlen=hlen, sha=addr, tha=addr,
                                spa='10.0.0.1', tpa='10.0.0.2')
                    self.assertEqual(proto.info.hlen, hlen)
                    self.assertEqual(proto.info.sha, addr)
            with self.subTest(cls=name, htype='Fibre_Channel'):
                proto = cls(htype=Hardware.Fibre_Channel, sha='aabbcc', tha='ddeeff',
                            spa='10.0.0.1', tpa='10.0.0.2')
                self.assertEqual(proto.info.hlen, 3)

    def test_ethernet_mac_still_validated(self) -> None:
        """#1205: a malformed MAC string is still rejected."""
        from pcapkit.const.arp.hardware import Hardware
        from pcapkit.protocols.link.arp import ARP
        from pcapkit.utilities.exceptions import ProtocolError

        arp = object.__new__(ARP)
        self.assertEqual(arp._make_addr_resolve('01:02:03:04:05:06:07:08', Hardware.Ethernet),
                         bytes.fromhex('0102030405060708'))
        self.assertEqual(arp._make_addr_resolve('', Hardware.Ethernet), b'')
        for addr in ('not-a-mac', '0102', '01:2', '01:02:', ':01'):
            with self.subTest(addr=addr):
                with self.assertRaises(ProtocolError):
                    arp._make_addr_resolve(addr, Hardware.Ethernet)

    def test_protocol_address_follows_ptype_and_plen(self) -> None:
        """#1206: IP decoding requires ``ptype`` and ``plen`` to agree."""
        import ipaddress

        cases = (
            ('0800', 4, ipaddress.IPv4Address),
            ('86dd', 16, ipaddress.IPv6Address),
            ('0800', 16, str),
            ('0800', 5, str),
            ('0800', 0, str),
            ('86dd', 4, str),
        )
        for module, name in CLASSES:
            for ptype, plen, kind in cases:
                with self.subTest(cls=name, ptype=ptype, plen=plen):
                    cls = self._cls(module, name)
                    data = _header(ptype, 6, plen, '0001')
                    parsed = cls(data)
                    self.assertIsInstance(parsed.info.spa, kind)
                    self.assertIsInstance(parsed.info.tpa, kind)
                    self.assertRoundTrips(cls, data)


if __name__ == '__main__':
    unittest.main()
