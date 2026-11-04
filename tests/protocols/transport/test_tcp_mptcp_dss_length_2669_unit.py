# -*- coding: utf-8 -*-
"""A Multipath TCP DSS option takes only the length its flags give.

GitHub issue #2669. The DSS schema is handed the octets its ``Length``
declares, and the flags say which fields it holds. A length short of them read
the rest as zeros, and one past them left octets no field took; either way the
rebuild wrote the length the flags give, so the segment came back different.
DSS refuses a length :rfc:`8684` does not give it, as every other registered
Multipath TCP subtype does.

Every flag combination is tried at every length, against :rfc:`8684` section 3.3
figure 9, and complete DSS options are changed in one octet at a time; each
segment must be refused or rebuild byte for byte.

Every case builds its own octets in memory and reads no capture.

"""

import itertools
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): a sweep over the DSS flags and lengths.
__tier__ = 'LATEST'


def _tcp(options: bytes) -> bytes:
    """An ACK segment carrying ``options``, padded with NOPs to a 4-octet boundary."""
    options += b'\x01' * (-len(options) % 4)
    return struct.pack('>HHIIBBHHH', 50000, 80, 1, 0, (5 + len(options) // 4) << 4, 0x10, 8192, 0, 0) + options


def _rfc_length(A: int, a: int, M: int, m: int) -> int:
    """The DSS length of :rfc:`8684` section 3.3 figure 9, without the checksum."""
    return 4 + ((8 if a else 4) if A else 0) + ((8 if m else 4) + 4 + 2 if M else 0)


def _mutants(packet: bytes):
    """Each one-octet change to the options, over a spread of values."""
    for pos in range(20, len(packet)):
        octet = packet[pos]
        values = {0x00, 0xff, octet ^ 0x01, octet ^ 0x80, (octet + 1) & 0xff, (octet - 1) & 0xff}
        for value in sorted(values - {octet}):
            yield pos, packet[:pos] + bytes([value]) + packet[pos + 1:]


class TestTCPMPTCPDSSLength(unittest.TestCase):
    """Pin the DSS lengths parsed, and byte-exact rebuilds of the rest."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def test_every_flag_combination_at_every_length(self) -> None:
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import BaseError

        for F, m, M, a, A in itertools.product((0, 1), repeat=5):
            flags = F << 4 | m << 3 | M << 2 | a << 1 | A
            rfc = _rfc_length(A, a, M, m)
            lengths = {rfc, rfc + 2} if M else {rfc}
            for length in range(41):
                # the octets past the declared length read as NOPs
                option = bytes([0x1e, length, 0x20, flags]) + b'\x01' * (max(length, rfc + 2) - 4)
                raw = _tcp(option)
                with self.subTest(flags=f'{flags:#04x}', length=length):
                    try:
                        tcp = TCP(raw, len(raw))
                    except BaseError:
                        self.assertNotIn(length, lengths)
                        continue
                    self.assertIn(length, lengths)
                    dss = tcp.info.options[Enum_Option.Multipath_TCP]
                    self.assertEqual(dss.length, length)
                    self.assertEqual(dss.ack is not None, bool(A))
                    self.assertEqual(dss.dsn is not None, bool(M))
                    self.assertEqual(dss.checksum is not None, length == rfc + 2)
                    self.assertEqual(TCP.from_data(tcp.info).data, raw)
                    self.assertEqual(TCP.from_data(tcp.info.to_dict()).data, raw)

    def test_every_option_changed_in_one_octet(self) -> None:
        from pcapkit.const.tcp.mp_tcp_option import \
            MPTCPOption as Enum_MPTCPOption
        from pcapkit.const.tcp.option import Option as Enum_Option
        from pcapkit.protocols.transport.tcp.protocol import TCP
        from pcapkit.utilities.exceptions import BaseError

        shapes = (
            {'ack': 1},
            {'ack': 1, 'ack_wide': True},
            {'dsn': 2, 'ssn': 3, 'dl_len': 4},
            {'dsn': 2, 'dsn_wide': True, 'ssn': 3, 'dl_len': 4, 'checksum': b'\x12\x34'},
            {'ack': 1, 'dsn': 2, 'ssn': 3, 'dl_len': 4, 'checksum': b'\x12\x34'},
            {'ack': 1, 'ack_wide': True, 'dsn': 2, 'dsn_wide': True, 'ssn': 3, 'dl_len': 4},
        )
        tail = [(Enum_Option.No_Operation, {}), (Enum_Option.No_Operation, {}),
                (Enum_Option.Timestamps, {'value': 5, 'reply': 6})]
        for shape in shapes:
            option = (Enum_Option.Multipath_TCP, dict(shape, subtype=Enum_MPTCPOption.DSS))
            for options in ([option], [option] + tail):
                whole = TCP(srcport=50000, dstport=80, ack=True, options=options).data
                for pos, raw in _mutants(whole):
                    with self.subTest(shape=shape, pos=pos, raw=raw.hex()):
                        try:
                            tcp = TCP(raw, len(raw))
                        except BaseError:
                            continue
                        self.assertEqual(tcp.data, raw)
                        self.assertEqual(TCP.from_data(tcp.info).data, raw)
                        self.assertEqual(TCP.from_data(tcp.info.to_dict()).data, raw)


if __name__ == '__main__':
    unittest.main()
