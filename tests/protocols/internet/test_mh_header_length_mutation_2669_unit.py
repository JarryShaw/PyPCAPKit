# -*- coding: utf-8 -*-
"""A whole Mobility Header whose Header Len is short of its message is refused.

GitHub issue #2669. The message is handed ``Header Len * 8 + 2`` octets, and a
message type whose fixed fields need more read the rest as zeros. The rebuild
then wrote a longer Header Len, the zeros, and the octets past it again: a
Home Test declaring 16 of its 24 octets came back as 32, and its 64-octet IPv6
packet as 72. :rfc:`6275#section-9.2` has such a message discarded, as IPv6
Routing type 2 and HIP refuse a header length short of their fields.

A capture that ends inside the header is a cut rather than a short Header Len:
it is kept, and rebuilt with the Header Len it declared.

Every registered message type is built whole, each octet of it changed in turn,
and the result must be refused or rebuild byte for byte, alone and inside IPv6;
each is cut at every offset of its message, too.

Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): a sweep over every registered message type.
__tier__ = 'LATEST'

#: A Home Test of :rfc:`6275#section-6.1.5`: 18 octets of message data, so
#: Header Len 2.
HOME_TEST = bytes([59, 2, 3, 0, 0, 0]) + struct.pack('!H', 7) + b'C' * 8 + b'T' * 8


def _ipv6(body: bytes, length: 'int | None' = None) -> bytes:
    """An IPv6 header declaring ``length`` octets of payload, ``len(body)`` by default."""
    length = len(body) if length is None else length
    return (bytes([0x60, 0, 0, 0]) + struct.pack('!HBB', length, 135, 64)
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + body)


def _mutants(packet: bytes):
    """Each one-octet change: a spread of values, and Header Len from 0 to 31 too."""
    for pos, octet in enumerate(packet):
        values = {0x00, 0xff, octet ^ 0x01, octet ^ 0x80, (octet + 1) & 0xff, (octet - 1) & 0xff}
        if pos == 1:
            values.update(range(32))
        for value in sorted(values - {octet}):
            yield pos, packet[:pos] + bytes([value]) + packet[pos + 1:]


class TestMHHeaderLengthMutation(unittest.TestCase):
    """Pin byte-exact rebuilds of MH messages changed in one octet or cut short."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        catcher = warnings.catch_warnings()
        catcher.__enter__()
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def _rebuilds(self, raw: bytes, packet: bytes) -> None:
        """``packet`` holds ``raw`` inside IPv6, and rebuilds byte for byte."""
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        ipv6 = IPv6(packet, len(packet))
        self.assertEqual(IPv6.from_data(ipv6.info).data, packet)
        self.assertEqual(IPv6.from_data(ipv6.info.to_dict()).data, packet)
        for ext in ipv6.extension_headers.values():
            self.assertEqual(type(ext).from_data(ext.info).data, ext.data)
            self.assertEqual(type(ext).from_data(ext.info.to_dict()).data, ext.data)

    def test_home_test_short_header_length(self) -> None:
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.protocols.misc.raw.protocol import Raw
        from pcapkit.utilities.exceptions import ProtocolError

        mh = MH(HOME_TEST, len(HOME_TEST))
        self.assertEqual(mh.info.length, 24)
        self.assertEqual(mh.info.token, b'T' * 8)

        for length in (0, 1):
            raw = HOME_TEST[:1] + bytes([length]) + HOME_TEST[2:]
            with self.subTest(header_len=length):
                with self.assertRaisesRegex(ProtocolError, 'invalid header length'):
                    MH(raw, len(raw))

                packet = _ipv6(raw)
                ipv6 = IPv6(packet, len(packet))
                self.assertIsInstance(ipv6.payload, Raw)
                self.assertRegex(str(ipv6.payload.info.error), 'invalid header length')
                self.assertEqual(IPv6.from_data(ipv6.info).data, packet)

    def test_short_header_length_cut_inside_it(self) -> None:
        # Header Len 1 declares 16 of the 24 octets; a capture ending before
        # the 16th is a cut, whose rebuild keeps Header Len 1
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import ProtocolError

        whole = HOME_TEST[:1] + b'\x01' + HOME_TEST[2:]
        for keep in range(3, len(whole) + 1):
            raw = whole[:keep]
            with self.subTest(keep=keep):
                if keep >= 16:
                    with self.assertRaisesRegex(ProtocolError, 'invalid header length'):
                        MH(raw, len(raw))
                else:
                    mh = MH(raw, len(raw))
                    self.assertEqual(mh.info.length, 16)
                    self.assertEqual(MH.from_data(mh.info).data, raw)
                    self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)
                self._rebuilds(raw, _ipv6(raw, len(whole)))

    def test_every_message_cut_inside_it(self) -> None:
        # a valid Header Len cut short is kept: only a field reading past the
        # declared header, not past the capture, is refused
        from pcapkit.protocols.internet.ipv6.protocol import IPv6
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import BaseError

        for code in sorted(MH.__message__, key=int):
            whole = MH(type=code, next=59, chksum=b'\x00\x00', data={}).data
            options = MH(whole, len(whole)).info.get('options')
            for keep in range(6, len(whole)):
                raw = whole[:keep]
                with self.subTest(type=code.name, keep=keep):
                    try:
                        mh = MH(raw, len(raw))
                    except BaseError as exc:
                        # a cut in or before mobility options, which their field refuses
                        self.assertTrue(options, exc)
                        self.assertNotIn('invalid header length', str(exc))
                        parsed = False
                    else:
                        self.assertEqual(MH.from_data(mh.info).data, raw)
                        self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)
                        parsed = True

                    packet = _ipv6(raw, len(whole))
                    self._rebuilds(raw, packet)
                    if parsed and keep >= 8:
                        ipv6 = IPv6(packet, len(packet))
                        self.assertIn(135, [int(key) for key in ipv6.extension_headers])

    def test_every_message_changed_in_one_octet(self) -> None:
        from pcapkit.protocols.internet.mh.protocol import MH
        from pcapkit.utilities.exceptions import BaseError

        for code in sorted(MH.__message__, key=int):
            whole = MH(type=code, next=59, chksum=b'\x00\x00', data={}).data
            for pos, raw in _mutants(whole):
                with self.subTest(type=code.name, pos=pos, raw=raw.hex()):
                    try:
                        mh = MH(raw, len(raw))
                    except BaseError:
                        pass
                    else:
                        self.assertEqual(mh.data, raw)
                        self.assertEqual(MH.from_data(mh.info).data, raw)
                        self.assertEqual(MH.from_data(mh.info.to_dict()).data, raw)
                    self._rebuilds(raw, _ipv6(raw))


if __name__ == '__main__':
    unittest.main()
