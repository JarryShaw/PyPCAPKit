# -*- coding: utf-8 -*-
"""A cut ICMP error message rebuilds from its unused octets. C.f. #2819.

The unused octets of an ICMPv6 Destination Unreachable or Time Exceeded message
(RFC 4443, sections 3.1 and 3.3), and of an ICMP Destination Unreachable, Time Exceeded
or Parameter Problem message (RFC 792), are a padding field, which keeps only the
octets a capture cut left. The maker refused that short value, so ``from_data(info)``
raised where the parse had succeeded. It zero-fills the octets the cut left out through
``Protocol._fill_short_read``, and the rebuild is cut back to the octets captured.

Each message is built here against the RFC layouts, with the other error messages of
each protocol beside it, and cut at every octet of the four after its header behind an
IP header declaring the whole message; this module is unit-tier and reads no capture.

"""

import io
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The quoted invoking packet.
QUOTED = b'invoking-packet'

#: ICMPv6 error messages: type, code, checksum, the four octets after them, and the
#: quoted packet. The unused octets are not zero, so a rebuild that zero-filled an
#: octet the capture kept would differ.
ICMPV6 = {
    'destination-unreachable': bytes.fromhex('0103' 'abcd' 'a1a2a3a4') + QUOTED,
    'packet-too-big':          bytes.fromhex('0200' 'abcd' '000005dc') + QUOTED,
    'time-exceeded':           bytes.fromhex('0301' 'abcd' 'a1a2a3a4') + QUOTED,
    'parameter-problem':       bytes.fromhex('0401' 'abcd' '00000028') + QUOTED,
}

#: ICMP error messages, laid out as :data:`ICMPV6`'s; Parameter Problem's pointer
#: octet comes before its three unused octets.
ICMPV4 = {
    'destination-unreachable': bytes.fromhex('0301' 'abcd' 'a1a2a3a4') + QUOTED,
    'time-exceeded':           bytes.fromhex('0b01' 'abcd' 'a1a2a3a4') + QUOTED,
    'parameter-problem':       bytes.fromhex('0c02' 'abcd' '05' 'a1a2a3') + QUOTED,
}

#: The fields each message holds after its header, as RFC 4443 and RFC 792 lay them out.
FIELDS = {
    ('ICMPv6', 'destination-unreachable'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMPv6', 'packet-too-big'): {'mtu': 1500},
    ('ICMPv6', 'time-exceeded'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMPv6', 'parameter-problem'): {'pointer': 40},
    ('ICMP', 'destination-unreachable'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMP', 'time-exceeded'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMP', 'parameter-problem'): {'pointer': 5, 'unused': b'\xa1\xa2\xa3'},
}


def ipv6(payload: bytes, length: int) -> bytes:
    """An IPv6 header carrying ICMPv6 and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([58, 64])
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + payload)


def ipv4(payload: bytes, length: int) -> bytes:
    """An IPv4 header carrying ICMP and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('4500') + (20 + length).to_bytes(2, 'big')
            + bytes.fromhex('0000' '4000' '40' '01' '0000' '0a000001' '0a000002') + payload)


class CutUnusedOctetsTests(unittest.TestCase):
    """Each error message cut after its header rebuilds as captured."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        # a cut message warns that its length runs past the data, which is the point
        catcher = warnings.catch_warnings()
        catcher.__enter__()  # pylint: disable=unnecessary-dunder-call
        self.addCleanup(catcher.__exit__, None, None, None)
        warnings.simplefilter('ignore')

    def messages(self) -> 'list[tuple[str, str, bytes, type, type, object]]':
        """Each message: alias, name, octets, class, the IP class and the wrapper giving its octets."""
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        return [*(('ICMPv6', name, packet, ICMPv6, IPv6, ipv6) for name, packet in ICMPV6.items()),
                *(('ICMP', name, packet, ICMPv4, IPv4, ipv4) for name, packet in ICMPV4.items())]

    def parse(self, ip: type, wrap: object, part: bytes, length: int) -> object:
        """The ICMP layer of ``part`` behind an IP header declaring ``length`` octets."""
        frame = wrap(part, length)  # type: ignore[operator]
        return ip(io.BytesIO(frame), len(frame)).payload  # type: ignore[call-arg]

    def test_fields_sit_where_the_rfcs_put_them(self) -> None:
        for alias, name, packet, cls, ip, wrap in self.messages():
            with self.subTest(protocol=alias, message=name):
                layer = self.parse(ip, wrap, packet, len(packet))
                self.assertIsInstance(layer, cls)
                for key, value in FIELDS[alias, name].items():
                    self.assertEqual(layer.info[key], value)  # type: ignore[attr-defined]
                self.assertEqual(layer.info.data, QUOTED)  # type: ignore[attr-defined]

    def test_cuts_rebuild_as_captured(self) -> None:
        # the issue's cuts: inside the four octets after the header, and at their end
        for alias, name, packet, cls, ip, wrap in self.messages():
            for cut in range(4, 9):
                part = packet[:cut]
                with self.subTest(protocol=alias, message=name, cut=cut):
                    layer = self.parse(ip, wrap, part, len(packet))
                    self.assertIsInstance(layer, cls)
                    self.assertEqual(layer.info.get('__short_read__'), ('data', cut - 4))  # type: ignore[attr-defined]
                    for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):  # type: ignore[attr-defined]
                        with self.subTest(path=path):
                            rebuilt = cls.from_data(data)  # type: ignore[attr-defined]
                            self.assertEqual(rebuilt.data.hex(), part.hex())
                            self.assertEqual(rebuilt.info, layer.info)  # type: ignore[attr-defined]

    def test_unused_octets_the_cut_did_not_leave_are_refused(self) -> None:
        # A model whose unused octets are not those its cut left is checked as a
        # caller's value is: one cut past them, one cut inside them with another
        # width, and one parsed whole.
        from pcapkit.utilities.exceptions import ProtocolError

        for alias, name, packet, cls, ip, wrap in self.messages():
            size = len(FIELDS[alias, name].get('unused', b''))
            if not size:
                continue
            start = packet.index(FIELDS[alias, name]['unused'])
            for cut, value in ((len(packet) - 1, b'\xa1'), (len(packet) - 1, b''), (start + 2, b''),
                               (start + 2, b'\xa1'), (len(packet), b'\xa1'), (len(packet), bytes(5))):
                with self.subTest(protocol=alias, message=name, cut=cut, width=len(value)):
                    layer = self.parse(ip, wrap, packet[:cut], len(packet))
                    layer.info.__update__({'unused': value})  # type: ignore[attr-defined]
                    with self.assertRaises(ProtocolError) as caught:
                        cls.from_data(layer.info)  # type: ignore[attr-defined]
                    self.assertEqual(str(caught.exception),
                                     f'{alias}: invalid unused octets: must be {size} octets, not {value!r}')


if __name__ == '__main__':
    unittest.main()
