# -*- coding: utf-8 -*-
"""Multipath TCP options rebuild byte for byte.

GitHub issues #1212, #1213, #1214, #1215, #1216, #1217 and #1220, all found by
the transport round-trip audit (#1202). Each case wraps one option in a TCP
header and checks that :meth:`~pcapkit.protocols.protocol.ProtocolBase.from_data`
over the parsed segment reproduces it:

* #1212 -- the reserved bits of MP_JOIN, DSS, REMOVE_ADDR, MP_PRIO, MP_FAIL and
  MP_FASTCLOSE were written back as zero;
* #1213 -- MP_FAIL had no room for its 12 reserved bits, so the DSN was read
  one octet early;
* #1214 -- an unknown subtype read ``length - 2`` octets after the subtype
  octet, one past the option;
* #1215 -- DSS chose the Data ACK and DSN widths from the values instead of the
  ``a``/``m`` flags;
* #1216 -- DSS assumed a checksum whenever ``M`` was set;
* #1217 -- ADD_ADDR in the :rfc:`8684` layout (``E`` flag, optional HMAC) did
  not parse;
* #1220 -- MP_CAPABLE dropped the ``C`` flag and bits ``D`` to ``G``.

Every case builds its own octets in memory and reads no capture. :class:`TCP`
is imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import unittest

from tests._support import reimport_once_per_class

#: TCP header without its offset/flags octets: ports 1234 and 80, sequence 1,
#: acknowledgement 2; the window, checksum and urgent pointer follow them.
HEAD = bytes.fromhex('04d2' '0050' '00000001' '00000002')
TAIL = bytes.fromhex('03e8' 'abcd' '0000')

SYN, ACK = 0x02, 0x10

#: ``name -> (TCP flags, option octets)``; the octets are padded with leading
#: NOPs to a multiple of 4.
OPTIONS = {
    # 1212
    'join-syn-reserved': (SYN, '1e0c1e01 00000002 00000003'),
    'join-synack-reserved': (SYN | ACK, '1e101e01 0102030405060708 00000003'),
    'join-ack-reserved': (ACK, '1e1810ff' + '11' * 20),
    'dss-reserved-subtype-octet': (ACK, '1e082e01 00000005'),
    'dss-reserved-flags-octet': (ACK, '1e0820e1 00000005'),
    'remove-addr-reserved': (ACK, '01 1e044f01 01 01 01'),
    'mp-prio-reserved': (ACK, '01 1e035e'),
    'mp-fastclose-reserved': (ACK, '1e0c7fff 0000000000000009'),
    # 1213
    'mp-fail': (ACK, '1e0c6000 0000000000000007'),
    'mp-fail-reserved': (ACK, '1e0c6abc 0000000000000007'),
    # 1214
    'unknown-subtype': (ACK, '1e048001'),
    'unknown-subtype-longer': (ACK, '1e06f1020304 0101'),
    # 1215
    'dss-wide-small-ack': (ACK, '1e0c2003 0000000000000005'),
    'dss-wide-small-dsn': (ACK, '1e14200c 0000000000000005 00000006 0007 abcd'),
    # 1216
    'dss-no-checksum': (ACK, '1e0e2004 00000005 00000006 0007 0101'),
    'dss-checksum': (ACK, '1e102004 00000005 00000006 0007 abcd'),
    # 1217
    'add-addr-echo': (ACK, '1e083101 c0000201'),
    'add-addr-hmac': (ACK, '1e103001 c0000201 0001020304050607'),
    'add-addr-hmac-port': (ACK, '0101 1e123001 c0000201 01bb 0001020304050607'),
    'add-addr-ipv6-hmac-port': (ACK, '0101 1e1e3001 20010db8000000000000000000000001 01bb 0001020304050607'),
    'add-addr-rfc6824-ipv4-port': (ACK, '0101 1e0a3401 c0000201 01bb'),
    'add-addr-rfc6824-ipv6': (ACK, '1e143601 20010db8000000000000000000000001'),
    # 1220
    'mp-capable-all-flags': (SYN, '1e0c01ff 0000000000000001'),
    'mp-capable-c-flag': (SYN, '1e0c0121 0000000000000001'),
}


def segment(flags: int, option: str) -> bytes:
    """Wrap option octets in a TCP header with a matching data offset."""
    opt = bytes.fromhex(option.replace(' ', ''))
    assert len(opt) % 4 == 0, option
    return HEAD + bytes([(5 + len(opt) // 4) << 4, flags]) + TAIL + opt


class TestMPTCPRoundTrip(unittest.TestCase):
    """Pin the wire form of every Multipath TCP subtype the audit flagged."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def parse(self, name: str) -> 'tuple[bytes, object]':
        from pcapkit.protocols.transport.tcp import TCP

        raw = segment(*OPTIONS[name])
        return raw, TCP(raw, len(raw))

    def mptcp(self, name: str) -> 'object':
        from pcapkit.const.tcp.option import Option

        _, tcp = self.parse(name)
        return tcp.info.options[Option.Multipath_TCP]

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP

        for name in OPTIONS:
            with self.subTest(option=name):
                raw, tcp = self.parse(name)
                self.assertEqual(TCP.from_data(tcp.info).data.hex(), raw.hex())

    def test_reserved_bits_are_kept(self) -> None:
        cases = {
            'join-syn-reserved': 0b111,
            'join-synack-reserved': 0b111,
            'join-ack-reserved': 0x0ff,
            'dss-reserved-subtype-octet': 0b1110000,
            'dss-reserved-flags-octet': 0b0000111,
            'remove-addr-reserved': 0xf,
            'mp-prio-reserved': 0b111,
            'mp-fastclose-reserved': 0xfff,
            'mp-fail-reserved': 0xabc,
        }
        for name, reserved in cases.items():
            with self.subTest(option=name):
                self.assertEqual(self.mptcp(name).reserved, reserved)

    def test_mp_fail_reads_the_dsn_after_the_reserved_bits(self) -> None:
        self.assertEqual(self.mptcp('mp-fail').dsn, 7)
        self.assertEqual(self.mptcp('mp-fail-reserved').dsn, 7)

    def test_unknown_subtype_stays_inside_the_option(self) -> None:
        opt = self.mptcp('unknown-subtype')
        self.assertEqual(opt.length, 4)
        self.assertEqual(opt.data, b'\x00\x01')
        self.assertEqual(self.mptcp('unknown-subtype-longer').data, bytes.fromhex('01020304'))

    def test_dss_width_follows_the_flags(self) -> None:
        ack = self.mptcp('dss-wide-small-ack')
        self.assertTrue(ack.ack_wide)
        self.assertEqual(ack.ack, 5)
        dsn = self.mptcp('dss-wide-small-dsn')
        self.assertTrue(dsn.dsn_wide)
        self.assertEqual((dsn.dsn, dsn.ssn, dsn.dl_len, dsn.checksum), (5, 6, 7, b'\xab\xcd'))

    def test_dss_checksum_follows_the_length(self) -> None:
        bare = self.mptcp('dss-no-checksum')
        self.assertEqual((bare.dsn, bare.ssn, bare.dl_len), (5, 6, 7))
        self.assertIsNone(bare.checksum)
        self.assertEqual(self.mptcp('dss-checksum').checksum, b'\xab\xcd')

    def test_add_addr_rfc8684_layout(self) -> None:
        import ipaddress

        echo = self.mptcp('add-addr-echo')
        self.assertEqual((echo.version, echo.echo, echo.reserved), (4, True, 0))
        self.assertEqual(echo.addr, ipaddress.ip_address('192.0.2.1'))
        self.assertIsNone(echo.hmac)

        full = self.mptcp('add-addr-ipv6-hmac-port')
        self.assertEqual((full.version, full.echo, full.port), (6, False, 443))
        self.assertEqual(full.hmac, bytes.fromhex('0001020304050607'))

        legacy = self.mptcp('add-addr-rfc6824-ipv4-port')
        self.assertEqual((legacy.version, legacy.port, legacy.hmac), (4, 443, None))

    def test_add_addr_rejects_an_unknown_length(self) -> None:
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import FieldError

        raw = segment(ACK, '1e093001 c0000201 01 010101')
        with self.assertRaises(FieldError):
            TCP(raw, len(raw))

    def test_mp_capable_keeps_c_and_d_to_g(self) -> None:
        flags = self.mptcp('mp-capable-all-flags').flags
        self.assertEqual((flags.req, flags.ext, flags.deny_join, flags.reserved, flags.hsa),
                         (True, True, True, 0xf, True))
        flags = self.mptcp('mp-capable-c-flag').flags
        self.assertEqual((flags.deny_join, flags.reserved), (True, 0))

    def test_makers_build_the_new_forms(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.transport.tcp import TCP

        tcp = TCP.__new__(TCP)
        self.assertEqual(tcp._make_mptcp_dss(  # pylint: disable=protected-access
            MPTCPOption.DSS, ack_wide=True, ack=5).pack().hex(), '1e0c20030000000000000005')
        self.assertEqual(tcp._make_mptcp_dss(  # pylint: disable=protected-access
            MPTCPOption.DSS, dsn=5, ssn=6, dl_len=7).pack().hex(), '1e0e200400000005000000060007')
        self.assertEqual(tcp._make_mptcp_addaddr(  # pylint: disable=protected-access
            MPTCPOption.ADD_ADDR, addr_id=1, addr='192.0.2.1',
            hmac=bytes(range(8))).pack().hex(), '1e103001c00002010001020304050607')
        self.assertEqual(tcp._make_mptcp_addaddr(  # pylint: disable=protected-access
            MPTCPOption.ADD_ADDR, echo=True, addr_id=1, addr='192.0.2.1').pack().hex(), '1e083101c0000201')
        self.assertEqual(tcp._make_mptcp_fail(  # pylint: disable=protected-access
            MPTCPOption.MP_FAIL, dsn=7).pack().hex(), '1e0c60000000000000000007')
        self.assertEqual(tcp._make_mptcp_capable(  # pylint: disable=protected-access
            MPTCPOption.MP_CAPABLE, version=1, flag_deny_join=True, flag_hsa=True, skey=1, rkey=None
        ).pack().hex(), '1e0c01210000000000000001')

    def test_add_addr_maker_rejects_a_bad_hmac(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        tcp = TCP.__new__(TCP)
        for kwargs in ({'echo': True, 'hmac': bytes(8)}, {'hmac': bytes(7)}, {'hmac': bytes(9)}):
            with self.subTest(**{key: repr(value) for key, value in kwargs.items()}):
                with self.assertRaises(ProtocolError):
                    tcp._make_mptcp_addaddr(  # pylint: disable=protected-access
                        MPTCPOption.ADD_ADDR, addr='192.0.2.1', **kwargs)

    def test_dss_maker_rejects_a_wide_value_in_a_narrow_field(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import MPTCPOption
        from pcapkit.protocols.transport.tcp import TCP
        from pcapkit.utilities.exceptions import ProtocolError

        tcp = TCP.__new__(TCP)
        with self.assertRaises(ProtocolError):
            tcp._make_mptcp_dss(MPTCPOption.DSS, ack_wide=False, ack=1 << 40)  # pylint: disable=protected-access


if __name__ == '__main__':
    unittest.main()
