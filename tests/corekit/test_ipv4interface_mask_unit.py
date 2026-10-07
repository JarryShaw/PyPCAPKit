# -*- coding: utf-8 -*-
"""IPv4 interface fields keep the mask octets they read.

GitHub issue #1294: :meth:`IPv4InterfaceField.post_process
<pcapkit.corekit.fields.ipaddress.IPv4InterfaceField.post_process>` built the
value with :func:`ipaddress.ip_interface`, which reads a hostmask-shaped mask
such as ``0.0.0.255`` as ``/24``. The field then packed ``255.255.255.0``, so
a pcapng ``if_IPv4addr`` option did not rebuild byte for byte.

A string keeps the stdlib's meaning wherever :func:`ipaddress.ip_interface`
accepts it; only a string it rejects is read with a literal mask, and the
:func:`str` of a kept mask is always such a string.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, for the reason given in
:mod:`tests.protocols.link.test_ethernet_mac_roundtrip_unit`.

"""

import copy
import ipaddress
import pickle
import random
import unittest

from tests._support import reimport_once_per_class

#: Address ``10.0.0.1`` followed by four mask octets.
MASKS = {
    'hostmask /24': '0a000001' '000000ff',
    'hostmask /1': '0a000001' '7fffffff',
    'non-contiguous': '0a000001' 'ff00ff00',
    'netmask /24': '0a000001' 'ffffff00',
    'netmask /0': '0a000001' '00000000',
    'netmask /32': '0a000001' 'ffffffff',
}


class TestIPv4InterfaceMask(unittest.TestCase):
    """Pin the mask octets of :class:`IPv4InterfaceField` across a round trip."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unpack_then_pack_keeps_the_mask_octets(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        for name, hexstr in MASKS.items():
            with self.subTest(mask=name):
                raw = bytes.fromhex(hexstr)
                value = field.unpack(raw, {})
                self.assertIsInstance(value, ipaddress.IPv4Interface)
                self.assertEqual(value.ip, ipaddress.IPv4Address('10.0.0.1'))
                self.assertEqual(value.netmask.packed, raw[4:])
                self.assertEqual(field.pack(value, {}), raw)

    def test_string_form_of_every_mask_packs_to_the_same_octets(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        netmasks = [(0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF for n in range(33)]
        hostmasks = [(1 << n) - 1 for n in range(33)]
        rng = random.Random(1294)
        masks = sorted(set(netmasks + hostmasks + [rng.getrandbits(32) for _ in range(100_000)]))
        self.assertGreater(len(masks), 100_000)

        failures = []
        for mask in masks:
            raw = bytes.fromhex('0a000001') + mask.to_bytes(4, 'big')
            text = str(field.unpack(raw, {}))
            if field.pack(text, {}) != raw:
                failures.append((raw.hex(), text))
        self.assertEqual(failures, [])

    def test_string_form_never_means_something_else_to_the_stdlib(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        for name, hexstr in MASKS.items():
            with self.subTest(mask=name):
                raw = bytes.fromhex(hexstr)
                text = str(field.unpack(raw, {}))
                try:
                    stdlib = ipaddress.ip_interface(text)
                except ValueError:
                    continue
                self.assertEqual(stdlib.ip.packed + stdlib.netmask.packed, raw)
        self.assertEqual(str(field.unpack(bytes.fromhex(MASKS['hostmask /24']), {})),
                         '10.0.0.1/0x000000ff')
        self.assertEqual(str(field.unpack(bytes.fromhex(MASKS['non-contiguous']), {})),
                         '10.0.0.1/255.0.255.0')

    def test_strings_the_stdlib_accepts_keep_the_stdlib_meaning(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        texts = ['10.0.0.1']
        for n in range(33):
            texts.append(f'10.0.0.1/{n}')
            texts.append(f'10.0.0.1/{ipaddress.IPv4Address((0xFFFFFFFF << (32 - n)) & 0xFFFFFFFF)}')
            texts.append(f'10.0.0.1/{ipaddress.IPv4Address((1 << n) - 1)}')
        for text in texts:
            with self.subTest(text=text):
                stdlib = ipaddress.ip_interface(text)
                self.assertEqual(field.pack(text, {}), stdlib.ip.packed + stdlib.netmask.packed)
        # the stdlib reads the hostmask spelling of /24 as /24
        self.assertEqual(field.pack('10.0.0.1/0.0.0.255', {}), bytes.fromhex(MASKS['netmask /24']))

    def test_strings_the_stdlib_rejects(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField
        from pcapkit.utilities.exceptions import FieldValueError

        field = IPv4InterfaceField()
        literal = {
            '10.0.0.1/255.0.255.0': MASKS['non-contiguous'],
            '10.0.0.1/0x000000ff': MASKS['hostmask /24'],
            '10.0.0.1/0XFFFFFF00': MASKS['netmask /24'],
        }
        for text, hexstr in literal.items():
            with self.subTest(text=text):
                with self.assertRaises(ValueError):
                    ipaddress.ip_interface(text)
                self.assertEqual(field.pack(text, {}), bytes.fromhex(hexstr))
        malformed = ['10.0.0.1/33', '10.0.0.1/1.2.3', '10.0.0.1/0xfff', '10.0.0.1/0x0000000g',
                     '10.0.0.1/0x 000ff', '10.0.0.1/', '10.0.0/24', 'not-an-interface',
                     '::1/0x000000ff', '10.0.0.1/0.0.0.255/1']
        for text in malformed:
            with self.subTest(text=text):
                with self.assertRaises(FieldValueError):
                    field.pack(text, {})

    def test_ordering_agrees_with_equality(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        values = [field.unpack(bytes.fromhex(hexstr), {}) for hexstr in MASKS.values()]
        values += [field.unpack(bytes.fromhex('0a000002' '000000ff'), {}),
                   ipaddress.IPv4Interface('10.0.0.5/8'), ipaddress.IPv4Interface('10.0.0.3/32')]
        for a in values:
            for b in values:
                with self.subTest(a=str(a), b=str(b)):
                    self.assertEqual([a < b, a == b, a > b].count(True), 1)
                    self.assertEqual(a < b, b > a)
                    self.assertEqual(a <= b, b >= a)
                    self.assertEqual(a <= b, a < b or a == b)
                    self.assertEqual(a >= b, a > b or a == b)
                    for c in values:
                        if a < b < c:
                            self.assertLess(a, c)

    def test_contiguous_netmask_stays_a_plain_interface(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        value = IPv4InterfaceField().unpack(bytes.fromhex(MASKS['netmask /24']), {})
        self.assertIs(type(value), ipaddress.IPv4Interface)
        self.assertEqual(value, ipaddress.IPv4Interface('10.0.0.1/24'))

    def test_kept_mask_survives_copy_pickle_and_compares_by_mask(self) -> None:
        from pcapkit.corekit.fields.ipaddress import IPv4InterfaceField

        field = IPv4InterfaceField()
        value = field.unpack(bytes.fromhex(MASKS['hostmask /24']), {})
        self.assertEqual(str(value), '10.0.0.1/0x000000ff')
        self.assertEqual(value.hostmask, ipaddress.IPv4Address('255.255.255.0'))
        for clone in (copy.copy(value), copy.deepcopy(value), pickle.loads(pickle.dumps(value))):
            self.assertEqual(clone, value)
            self.assertEqual(hash(clone), hash(value))
            self.assertEqual(clone.netmask, value.netmask)
        # the stdlib reading of the same octets is a different value
        self.assertNotEqual(value, ipaddress.IPv4Interface('10.0.0.1/24'))
        self.assertNotEqual(value, field.unpack(bytes.fromhex(MASKS['hostmask /1']), {}))

    def test_pcapng_if_ipv4addr_option_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.schema.misc.pcapng import IF_IPv4AddrOption

        option = bytes.fromhex('0400' '0800') + bytes.fromhex(MASKS['hostmask /24'])
        schema = IF_IPv4AddrOption.unpack(option)
        self.assertEqual(schema.interface.netmask, ipaddress.IPv4Address('0.0.0.255'))
        self.assertEqual(schema.pack(), option)


if __name__ == '__main__':
    unittest.main()
