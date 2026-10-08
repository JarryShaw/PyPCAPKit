# -*- coding: utf-8 -*-
"""A header length declared past the data, and TS address keys given as strings.

GitHub issue #1404: an IPv4 ``ihl`` or a TCP Data Offset declaring more header
than the data holds read the missing octets as zeros, and ``from_data`` rebuilt
them -- 34 octets in and 38 out for an Ethernet frame whose IPv4 ``ihl`` is 6
with only 20 header octets present. Such a header now raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError`, so its parent keeps the
octets as a :class:`~pcapkit.protocols.misc.raw.Raw` payload and rebuilds them
byte for byte.

GitHub issue #1402: ``IPv4.make()`` called :func:`int` on each key of a TS
option's ``timestamp`` mapping, so a dotted-quad string key raised a bare
:exc:`ValueError`. The keys are now converted as addresses, and a :obj:`bool`
key is rejected with :exc:`~pcapkit.utilities.exceptions.FieldValueError`.

Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

_ETH = bytes.fromhex('0123456789ab fedcba987654 0800')


def _ipv4(ihl: int, proto: int, body: bytes) -> bytes:
    """An IPv4 header declaring ``ihl``, followed by ``body``."""
    return (bytes([0x40 | ihl, 0]) + struct.pack('>H', 20 + len(body))
            + bytes.fromhex('00010000 40') + bytes([proto]) + bytes(2)
            + bytes.fromhex('0a000001 0a000002') + body)


def _tcp(offset: int, opts: bytes = b'') -> bytes:
    """A TCP header declaring ``offset``, followed by ``opts``."""
    return struct.pack('>HHIIBBHHH', 1, 2, 0, 0, offset << 4, 0x10, 0, 0, 0) + opts


#: Layers whose declared header length runs past the data: (module, class, octets).
SHORT = {
    # issue #1404: options declared, none present
    'IPv4 ihl=6, 20 octets': ('pcapkit.protocols.internet.ipv4', 'IPv4', _ipv4(6, 253, b'')),
    'IPv4 ihl=7, 24 octets': ('pcapkit.protocols.internet.ipv4', 'IPv4', _ipv4(7, 253, bytes.fromhex('01010101'))),
    'TCP offset=6, 20 octets': ('pcapkit.protocols.transport.tcp', 'TCP', _tcp(6)),
    'TCP offset=10, 28 octets': ('pcapkit.protocols.transport.tcp', 'TCP', _tcp(10, bytes.fromhex('0101010101010101'))),
}

#: Each short layer inside its parent: (parent module, parent class, frame).
IN_PARENT = {
    'IPv4 ihl=6, 20 octets': ('pcapkit.protocols.link.ethernet', 'Ethernet', _ETH + SHORT['IPv4 ihl=6, 20 octets'][2]),
    'IPv4 ihl=7, 24 octets': ('pcapkit.protocols.link.ethernet', 'Ethernet', _ETH + SHORT['IPv4 ihl=7, 24 octets'][2]),
    'TCP offset=6, 20 octets': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                                _ipv4(5, 6, SHORT['TCP offset=6, 20 octets'][2])),
    'TCP offset=10, 28 octets': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                                 _ipv4(5, 6, SHORT['TCP offset=10, 28 octets'][2])),
}


class TestHeaderLengthOverrun(unittest.TestCase):
    """Pin the rejection of a header length running past the end of its data."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _protocol(module: str, name: str) -> type:
        import importlib

        return getattr(importlib.import_module(module), name)

    def test_a_short_header_raises_protocol_error(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for case, (module, name, data) in SHORT.items():
            with self.subTest(case=case):
                protocol = self._protocol(module, name)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(ProtocolError, 'header length .* runs past the end of the data'):
                        protocol(data, len(data))

    def test_a_short_header_is_kept_as_captured_by_its_parent(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for case, (module, name, frame) in IN_PARENT.items():
            with self.subTest(case=case):
                protocol = self._protocol(module, name)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = protocol(frame, len(frame))
                self.assertIsInstance(parsed.payload, Raw)
                self.assertEqual(parsed.payload.data, SHORT[case][2])
                self.assertEqual(protocol.from_data(parsed.info).data, frame)

    def test_a_complete_header_still_rebuilds_byte_for_byte(self) -> None:
        # the same option areas, every declared octet present
        for module, name, data in (('pcapkit.protocols.internet.ipv4', 'IPv4', _ipv4(6, 253, bytes(4))),
                                   ('pcapkit.protocols.transport.tcp', 'TCP', _tcp(6, bytes(4)))):
            with self.subTest(name=name):
                protocol = self._protocol(module, name)
                parsed = protocol(data, len(data))
                self.assertEqual(protocol.from_data(parsed.info).data, data)


class TestTimestampAddressKeys(unittest.TestCase):
    """Pin the conversion of a TS option's address keys on ``make()``."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def _make(self, key: object) -> bytes:
        from datetime import timedelta

        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.protocols.internet.ipv4 import IPv4

        return IPv4(options=[(OptionNumber.TS, {'timestamp': {key: timedelta(milliseconds=1)}})],
                    protocol=253).data

    def test_a_string_key_builds_like_an_address_key(self) -> None:
        from ipaddress import IPv4Address

        from pcapkit.protocols.internet.ipv4 import IPv4

        expected = self._make(IPv4Address('1.2.3.4'))
        data = self._make('1.2.3.4')
        self.assertEqual(data, expected)
        self.assertEqual(data[20:32], bytes.fromhex('44240d01 01020304 00000001'))
        self.assertEqual(IPv4(data, len(data)).data, data)

    def test_a_string_key_in_parsed_data_rebuilds(self) -> None:
        from datetime import timedelta
        from ipaddress import IPv4Address

        from pcapkit.corekit.multidict import OrderedMultiDict
        from pcapkit.protocols.internet.ipv4 import IPv4

        data = self._make(IPv4Address('1.2.3.4'))
        parsed = IPv4(data, len(data))
        option = next(iter(parsed.info.options.values()))
        option.__update__(timestamp=OrderedMultiDict([('1.2.3.4', timedelta(milliseconds=1))]))
        self.assertEqual(IPv4.from_data(parsed.info).data, data)

    def test_a_bool_key_raises_field_value_error(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaisesRegex(FieldValueError, 'timestamp address: must not be a bool'):
            self._make(True)

    def test_an_invalid_key_raises_field_value_error(self) -> None:
        from pcapkit.utilities.exceptions import FieldValueError

        with self.assertRaisesRegex(FieldValueError, 'timestamp address'):
            self._make('1.2.3')


if __name__ == '__main__':
    unittest.main()
