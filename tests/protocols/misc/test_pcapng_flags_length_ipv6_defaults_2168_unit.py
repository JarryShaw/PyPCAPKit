# -*- coding: utf-8 -*-
"""GitHub issue #2168: flags-option length messages and IPv6 NRB maker defaults.

* The ``epb_flags`` and ``pack_flags`` length checks reject anything but 4
  octets, yet their error said "expected 8".
* ``_make_option_ns_dnsipv6`` and ``_make_record_ipv6`` defaulted to IPv4
  addresses, so making either with no address raised
  :exc:`~pcapkit.utilities.exceptions.FieldValueError`. They default to
  ``2001:4860:4860::8888`` and ``::1``, the IPv6 counterparts of the IPv4
  makers' ``8.8.8.8`` and ``127.0.0.1``.

:mod:`pcapkit` is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`.

"""

import struct
import unittest
import warnings

from tests.protocols.misc.test_pcapng_roundtrip2_unit import H, PCAPNGTestCase, _epb_with_options

#: Test tier (#1958): hand-picked error-message and make-default cases, not a sweep.
__tier__ = 'ALL'


def _pb_with_option(option: 'bytes') -> 'bytes':
    """An obsolete Packet Block on interface 0 carrying ``abcd`` and ``option``."""
    body = H('0000 0000 00000000 00000000 04000000 04000000 61626364') + option + bytes(4)
    length = len(body) + 12
    return struct.pack('<II', 2, length) + body + struct.pack('<I', length)


class TestPCAPNGFlagsLengthMessage(PCAPNGTestCase):
    """Pin the length the flags-option errors report."""

    def test_epb_flags_reports_expected_4(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        octets = _epb_with_options(H('0200 0800 0000000000000000'))
        with self.assertRaisesRegex(ProtocolError, r'\[epb_flags\] invalid length \(expected 4, got 8\)'):
            self._parse(octets)

    def test_pack_flags_reports_expected_4(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        octets = _pb_with_option(H('0200 0800 0000000000000000'))
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')  # the Packet Block is obsolete
            with self.assertRaisesRegex(ProtocolError, r'\[pack_flags\] invalid length \(expected 4, got 8\)'):
                self._parse(octets)


class TestPCAPNGIPv6MakeDefaults(PCAPNGTestCase):
    """Pin the IPv6 addresses the NRB makers use when given none."""

    def test_record_ipv6_defaults_to_loopback(self) -> None:
        from ipaddress import IPv6Address

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Name_Resolution_Block,
                       block={'records': [(RecordType.nrb_record_ipv6, {'names': ['a']}),
                                          (RecordType.nrb_record_end, {})]})
        record = self._parse(block.data, context).info.records[RecordType.nrb_record_ipv6]
        self.assertEqual(record.ip, IPv6Address('::1'))
        self.assertRebuilds(block.data, context)

    def test_ns_dnsip6addr_defaults_to_dns_server(self) -> None:
        from ipaddress import IPv6Address

        from pcapkit.const.pcapng.block_type import BlockType
        from pcapkit.const.pcapng.option_type import OptionType
        from pcapkit.const.pcapng.record_type import RecordType
        from pcapkit.protocols.misc.pcapng import PCAPNG

        context = self._context()
        block = PCAPNG(num=2, sct=1, ctx=context, type=BlockType.Name_Resolution_Block,
                       block={'records': [(RecordType.nrb_record_ipv4, {'names': ['a']}),
                                          (RecordType.nrb_record_end, {})],
                              'options': [(OptionType.ns_dnsIP6addr, {}),
                                          (OptionType.opt_endofopt, {})]})
        option = self._parse(block.data, context).info.options[OptionType.ns_dnsIP6addr]
        self.assertEqual(option.ip, IPv6Address('2001:4860:4860::8888'))
        self.assertRebuilds(block.data, context)


if __name__ == '__main__':
    unittest.main()
