# -*- coding: utf-8 -*-
"""GitHub issue #2863: a ``Raw`` rebuilt from its ``info`` keeps its ``error`` and ``protocol``.

:meth:`Raw._make_data <pcapkit.protocols.misc.raw.protocol.Raw._make_data>` passed on
``packet`` alone, so ``Raw.from_data(info).info`` lost the message saying why the
octets are kept raw and the code they arrived with, and its protocol chain named
``Raw`` rather than that code. The octets rebuilt byte for byte all the same.

Every case builds its own octets in memory and reads no capture.

"""

import unittest
import unittest.mock
import warnings
from typing import TYPE_CHECKING

from tests._support import reimport_once_per_class

if TYPE_CHECKING:
    from typing import Any

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: An IPv4 header whose Protocol field is 6, TCP, then eight octets, too few for TCP.
CUT_TCP = bytes.fromhex('4500001c00000000400600000a0000010a000002') + bytes(8)

#: Ethernet, then IPv4 carrying one octet of TCP, the second layer after Ethernet.
LIMITED = bytes(12) + b'\x08\x00' + bytes.fromhex('45000015000000004006000000000000' '00000000' '00')


class TestRawFromDataInfo(unittest.TestCase):
    """Pin ``from_data(info).info == info`` for ``Raw``, from its data model and its dict."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # a failed parse warns, which is not what these cases pin
        catcher = warnings.catch_warnings()
        catcher.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def assertRebuilds(self, raw: 'Any') -> None:  # pylint: disable=invalid-name
        """``raw`` rebuilt from its data model and its dict: the octets, the info and the chain."""
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.warnings import UnknownFieldWarning

        for form, data in (('info', raw.info), ('to_dict', raw.info.to_dict())):
            with self.subTest(form=form), warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter('always')
                rebuilt = Raw.from_data(data)
                self.assertEqual(rebuilt.data.hex(), raw.data.hex())
                self.assertEqual(rebuilt.info, raw.info)
                self.assertIs(type(rebuilt.info.protocol), type(raw.info.protocol))
                self.assertEqual(str(rebuilt.protochain), str(raw.protochain))
                self.assertEqual([item for item in caught if issubclass(item.category, UnknownFieldWarning)], [])

    def test_a_failed_parse(self) -> None:
        """Against the octets: IPv4's Protocol field, and the eight octets past its header."""
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.misc.raw.protocol import Raw

        raw = IPv4(CUT_TCP, len(CUT_TCP)).payload
        self.assertIs(type(raw), Raw)
        self.assertIs(raw.info.protocol, TransType.TCP)
        self.assertIsInstance(raw.info.error, str)
        self.assertEqual(raw.data, CUT_TCP[20:])
        self.assertRebuilds(raw)

    def test_a_layer_past_the_frame_limit(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.link.ethernet.protocol import Ethernet
        from pcapkit.utilities import config

        with unittest.mock.patch.object(config, 'FRAME_LAYER_LIMIT', 1):
            raw = Ethernet(LIMITED).payload.payload
            self.assertTrue(raw._past_layer_limit)  # pylint: disable=protected-access
            self.assertIs(raw.info.protocol, TransType.TCP)
            self.assertIsInstance(raw.info.error, str)
            self.assertRebuilds(raw)

    def test_an_unregistered_port_stays_an_int(self) -> None:
        # the port UDP looked up, derived from its registry rather than pinned
        from pcapkit.protocols.transport.udp.protocol import UDP

        port = next(port for port in range(1024, 65536) if port not in UDP.__proto__)
        octets = UDP.build(srcport=port, dstport=port, payload=b'xyz').data
        raw = UDP(octets, len(octets)).payload
        self.assertEqual(raw.info.protocol, port)
        self.assertIs(type(raw.info.protocol), int)
        self.assertRebuilds(raw)

    def test_construction_takes_a_member_or_an_int(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.misc.raw.protocol import Raw

        for alias in (TransType.TCP, 6, None):
            with self.subTest(alias=alias):
                raw = Raw.build(packet=b'abc', error='kept raw', alias=alias)
                self.assertEqual(raw.data, b'abc')
                self.assertEqual((raw.info.protocol, raw.info.error), (alias, 'kept raw'))
                self.assertIs(type(raw.info.protocol), type(alias))
                self.assertRebuilds(raw)

    def test_a_hand_written_dict(self) -> None:
        # what it carries is kept, and a missing ``error`` or ``protocol`` is None
        from pcapkit.protocols.misc.raw.protocol import Raw

        rebuilt = Raw.from_data({'packet': b'abc', 'error': 'kept raw', 'protocol': 6})
        self.assertEqual((rebuilt.data, rebuilt.info.protocol, rebuilt.info.error), (b'abc', 6, 'kept raw'))
        rebuilt = Raw.from_data({'packet': b'abc'})
        self.assertEqual((rebuilt.data, rebuilt.info.protocol, rebuilt.info.error), (b'abc', None, None))


if __name__ == '__main__':
    unittest.main()
