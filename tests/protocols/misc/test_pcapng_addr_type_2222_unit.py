# -*- coding: utf-8 -*-
"""GitHub issue #2222: PCAP-NG rejects a non-string MAC or EUI address.

:meth:`PCAPNG._make_mac_addr
<pcapkit.protocols.misc.pcapng.PCAPNG._make_mac_addr>` and
:meth:`PCAPNG._make_eui_addr
<pcapkit.protocols.misc.pcapng.PCAPNG._make_eui_addr>` passed a :obj:`bool`,
:class:`int`, :obj:`None` or :class:`float` straight to the address pattern,
which raised a bare :class:`TypeError`. Anything not a :class:`str`,
:class:`bytes` or :class:`bytearray`, a :obj:`bool` included, raises
:class:`~pcapkit.utilities.exceptions.ProtocolError`.
Each case reaches the maker through the ``if_MACaddr`` or ``if_EUIaddr``
option of an Interface Description Block.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
from typing import TYPE_CHECKING

from tests.protocols.misc.test_pcapng_roundtrip2_unit import PCAPNGTestCase

if TYPE_CHECKING:
    from typing import Any


class TestPCAPNGAddressType(PCAPNGTestCase):
    """Pin the error raised for each non-string ``if_MACaddr``/``if_EUIaddr`` value."""

    def _idb(self, option: 'str', interface: 'Any') -> 'Any':
        """Build an Interface Description Block carrying one address option."""
        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.reg.linktype import LinkType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        return PCAPNG(num=2, sct=1, ctx=self._context(), type=BlockType.Interface_Description_Block,
                      block={'linktype': LinkType.ETHERNET, 'snaplen': 65535,
                             'options': [(OptionType[option], {'interface': interface})]})

    OPTIONS = ('if_MACaddr', 'if_EUIaddr')

    #: Address kind each option's error message names.
    KINDS = {'if_MACaddr': 'MAC', 'if_EUIaddr': 'EUI'}

    def test_non_string_raises_protocol_error(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for option in self.OPTIONS:
            for value in (True, False, 5, None, 1.5):
                with self.subTest(option=option, value=value):
                    with self.assertRaises(ProtocolError) as context:
                        self._idb(option, value)
                    self.assertEqual(
                        str(context.exception),
                        f'PCAP-NG: invalid {self.KINDS[option]} address: must be a str, bytes '
                        f'or bytearray, not {value!r}')

    def test_malformed_string_message(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for option in self.OPTIONS:
            with self.subTest(option=option):
                with self.assertRaises(ProtocolError) as context:
                    self._idb(option, 'bad')
                self.assertEqual(str(context.exception),
                                 f"PCAP-NG: invalid {self.KINDS[option]} address: 'bad'")

    def test_supported_forms_still_pack(self) -> None:
        from pcapkit.const.pcapng.option_type import OptionType

        cases = {
            'if_MACaddr': ('01:23:45:67:89:ab', '01-23-45-67-89-ab'),
            'if_EUIaddr': ('02:34:56:ff:fe:78:9a:bc', '02-34-56-ff-fe-78-9a-bc'),
        }
        for option, (text, dashed) in cases.items():
            for value in (text, dashed.encode(), bytearray(text.encode())):
                with self.subTest(option=option, value=value):
                    block = self._idb(option, value)
                    self.assertEqual(block.info.options[OptionType[option]].interface, text)


if __name__ == '__main__':
    unittest.main()
