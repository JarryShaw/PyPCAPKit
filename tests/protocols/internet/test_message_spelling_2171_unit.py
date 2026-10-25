# -*- coding: utf-8 -*-
"""Two user-facing messages are spelt correctly.

GitHub issue #2171: :meth:`TSOption.post_process
<pcapkit.protocols.schema.internet.ipv4.TSOption.post_process>` warned of an
"unknown timestmap flag", and :meth:`MH._make_opt_mnp
<pcapkit.protocols.internet.mh.MH._make_opt_mnp>` raised on an "invalid movile
network prefix".

Classes are imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import unittest
import warnings

from tests._support import reimport_once_per_class


class TestMessageSpelling(unittest.TestCase):
    """Pin the spelling of the IPv4 timestamp warning and the MH prefix error."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_unknown_timestamp_flag_warning(self) -> None:
        from pcapkit.const.ipv4.option_number import OptionNumber
        from pcapkit.const.ipv4.ts_flag import TSFlag
        from pcapkit.protocols.schema.internet.ipv4 import TSOption
        from pcapkit.utilities.warnings import ProtocolWarning

        option = TSOption(type=OptionNumber.TS, length=12, pointer=13,
                          flags={'oflw': 0, 'flag': TSFlag.get(2)}, ts_data=[1, 2])
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            option.pack()
        messages = [str(w.message) for w in caught if issubclass(w.category, ProtocolWarning)]
        self.assertEqual(len(messages), 1, messages)
        self.assertIn('unknown timestamp flag: 2', messages[0])

    def test_invalid_mobile_network_prefix_error(self) -> None:
        from pcapkit.const.mh.option import Option
        from pcapkit.protocols.internet.mh import MH
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(MH)
        with self.assertRaisesRegex(ProtocolError, "invalid mobile network prefix: '192.0.2.0/24'"):
            proto._make_opt_mnp(Option.Mobile_Network_Prefix_Option, prefix='192.0.2.0/24')


if __name__ == '__main__':
    unittest.main()
