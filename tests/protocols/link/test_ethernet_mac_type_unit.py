# -*- coding: utf-8 -*-
"""Ethernet rejects a non-string MAC address with an in-library error.

GitHub issue #2222: :meth:`Ethernet._make_mac_addr
<pcapkit.protocols.link.ethernet.Ethernet._make_mac_addr>` passed a
:obj:`bool`, :class:`int`, :obj:`None` or :class:`float` straight to the MAC
pattern, which raised a bare :class:`TypeError` that neither
:class:`~pcapkit.utilities.exceptions.ProtocolError` nor :class:`ValueError`
catches. Anything not a :class:`str`, :class:`bytes` or :class:`bytearray`,
a :obj:`bool` included, raises
:class:`~pcapkit.utilities.exceptions.ProtocolError`.

Every case builds its own frame in memory and reads no capture.

"""

import unittest

from pcapkit.protocols.link.ethernet import Ethernet
from pcapkit.utilities.exceptions import ProtocolError


class TestEthernetMacAddressType(unittest.TestCase):
    """Pin the error raised for each non-string MAC address type."""

    def test_non_string_raises_protocol_error(self) -> None:
        for field in ('dst', 'src'):
            for value in (True, False, 5, None, 1.5):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ProtocolError) as context:
                        Ethernet(**{field: value})
                    self.assertEqual(
                        str(context.exception),
                        f'Ethernet: invalid MAC address: must be a str, bytes or bytearray, '
                        f'not {value!r}')

    def test_malformed_string_message(self) -> None:
        with self.assertRaises(ProtocolError) as context:
            Ethernet(dst='not-a-mac')
        self.assertEqual(str(context.exception), "Ethernet: invalid MAC address: 'not-a-mac'")

    def test_supported_forms_still_pack(self) -> None:
        raw = bytes.fromhex('0123456789ab')
        for value in ('01:23:45:67:89:ab', b'01-23-45-67-89-ab',
                      bytearray(b'01:23:45:67:89:ab')):
            with self.subTest(value=value):
                self.assertEqual(Ethernet(dst=value).data[:6], raw)


if __name__ == '__main__':
    unittest.main()
