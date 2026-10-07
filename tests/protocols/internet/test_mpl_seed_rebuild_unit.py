# -*- coding: utf-8 -*-
"""HOPOPT and IPv6-Opts rebuild every MPL seed-id kind byte for byte.

GitHub issue #1185: ``_make_opt_mpl`` inferred the ``S`` field from
``seed.bit_length()``. The reader stores the IPv6 source address as the seed
when ``S`` is 0 (:rfc:`7731#section-6.1`), so rebuilding such an option raised
:exc:`AttributeError`. And a 64- or 128-bit seed with a small value was
rebuilt with a narrower ``S``, changing the octets.

Every case builds its own octets in memory and reads no capture. The protocol
classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, as in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import ipaddress
import struct
import unittest

from tests._support import reimport_once_per_class

#: Extension headers carrying one MPL option (type 0x6D), next header 59, one
#: per seed-id kind. Flags ``M`` set, sequence 7. The 64- and 128-bit seeds are
#: 5, which fits in 16 bits, so the ``S`` field alone sets their width.
HEADERS = {
    0: bytes.fromhex('3b006d0220070000'),
    1: bytes.fromhex('3b006d046007beef'),
    2: bytes.fromhex('3b016d0aa007' '0000000000000005' '0000'),
    3: bytes.fromhex('3b026d12e007' '00000000000000000000000000000005' '0000'),
}

SRC = ipaddress.IPv6Address('2001:db8::1')
DST = ipaddress.IPv6Address('2001:db8::2')


def _classes() -> 'dict[str, tuple[type, int, str]]':
    from pcapkit.protocols.internet.hopopt import HOPOPT
    from pcapkit.protocols.internet.ipv6_opts import IPv6_Opts
    return {'HOPOPT': (HOPOPT, 0, 'hopopt'), 'IPv6_Opts': (IPv6_Opts, 60, 'opts')}


class TestMPLSeedRebuild(unittest.TestCase):
    """Pin the MPL option rebuild for each ``S`` value."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_standalone_header_rebuilds_byte_for_byte(self) -> None:
        for name, (cls, _, _) in _classes().items():
            for kind, octets in HEADERS.items():
                with self.subTest(proto=name, S=kind):
                    parsed = cls(octets, len(octets), extension=True)
                    opt = list(parsed.info.options.values())[0]
                    self.assertEqual(opt.seed_type, kind)
                    self.assertEqual(cls.from_data(parsed.info).data, octets)

    def test_source_address_seed_rebuilds_inside_ipv6(self) -> None:
        from pcapkit.protocols.internet.ipv6 import IPv6

        for name, (cls, nh, key) in _classes().items():
            with self.subTest(proto=name):
                octets = HEADERS[0]
                packet = (struct.pack('!IHBB', 6 << 28, len(octets), nh, 64)
                          + SRC.packed + DST.packed + octets)
                info = IPv6(packet, len(packet)).info[key]
                opt = list(info.options.values())[0]
                self.assertEqual(opt.seed_id, SRC)
                self.assertEqual(cls.from_data(info).data, octets)

    def test_address_seed_keyword_selects_source_address_kind(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.reg.transtype import TransType

        for name, (cls, _, _) in _classes().items():
            with self.subTest(proto=name):
                built = cls(options=[(Option.MPL_Option, {'seed': SRC, 'seq': 7, 'max': True})],
                            next=TransType.IPv6_NoNxt, payload=b'')
                self.assertEqual(built.data, HEADERS[0])

    def test_seed_that_does_not_fit_its_kind_is_rejected(self) -> None:
        from pcapkit.const.ipv6.option import Option
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.utilities.exceptions import ProtocolError

        for name, (cls, _, _) in _classes().items():
            for kwargs in ({'seed_type': 1, 'seed': 0x10000}, {'seed_type': 2}, {'seed': 1 << 128}):
                with self.subTest(proto=name, kwargs=kwargs):
                    with self.assertRaises(ProtocolError):
                        cls(options=[(Option.MPL_Option, kwargs)], next=TransType.IPv6_NoNxt, payload=b'')


if __name__ == '__main__':
    unittest.main()
