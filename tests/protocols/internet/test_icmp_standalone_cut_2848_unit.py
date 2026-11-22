# -*- coding: utf-8 -*-
"""An ICMP message cut inside its fixed fields is a short read on its own. C.f. #2848.

Parsed on its own, an ICMP message is given the octets captured as its length, so a
field the data ends inside left less than nothing for the ``data`` field after it,
which was refused with ``Field data resolved to a negative length``. Behind an IP header
declaring the whole message the same cut was a short read. Outside a frame the body is
now read with ``__data_end__``, under which ``Schema.unpack`` reads a field sized by what
is left as empty past the cut, and quietly; ICMP hoists the body's record onto its header,
as ICMPv6 does, so the rebuild is cut back to the capture.

Each message is built here against RFC 4443 and RFC 792, its fixed fields not zero so
that a rebuild zero-filling an octet the capture kept would differ, and cut at every
octet of its header and fixed fields; this module is unit-tier and reads no capture.

"""

import io
import unittest
import warnings
from unittest import mock

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: The quoted invoking packet, or the echoed data.
QUOTED = b'invoking-packet'

#: ICMPv6 messages: type, code, checksum, the four octets after them, and the rest.
ICMPV6 = {
    'destination-unreachable': bytes.fromhex('0103' 'abcd' 'a1a2a3a4') + QUOTED,
    'packet-too-big':          bytes.fromhex('0200' 'abcd' '000005dc') + QUOTED,
    'time-exceeded':           bytes.fromhex('0301' 'abcd' 'a1a2a3a4') + QUOTED,
    'parameter-problem':       bytes.fromhex('0401' 'abcd' '00000028') + QUOTED,
    'echo-request':            bytes.fromhex('8000' 'abcd' '1234' '5678') + QUOTED,
    'echo-reply':              bytes.fromhex('8100' 'abcd' '1234' '5678') + QUOTED,
}

#: ICMP messages, laid out as :data:`ICMPV6`'s; Parameter Problem's pointer octet
#: comes before its three unused octets.
ICMPV4 = {
    'destination-unreachable': bytes.fromhex('0301' 'abcd' 'a1a2a3a4') + QUOTED,
    'time-exceeded':           bytes.fromhex('0b01' 'abcd' 'a1a2a3a4') + QUOTED,
    'parameter-problem':       bytes.fromhex('0c02' 'abcd' '05' 'a1a2a3') + QUOTED,
    'echo-request':            bytes.fromhex('0800' 'abcd' '1234' '5678') + QUOTED,
    'echo-reply':              bytes.fromhex('0000' 'abcd' '1234' '5678') + QUOTED,
}

#: The fields each message holds after its header, as RFC 4443 and RFC 792 lay them out.
FIELDS = {
    ('ICMPv6', 'destination-unreachable'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMPv6', 'packet-too-big'): {'mtu': 1500},
    ('ICMPv6', 'time-exceeded'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMPv6', 'parameter-problem'): {'pointer': 40},
    ('ICMPv6', 'echo-request'): {'id': 0x1234, 'seq': 0x5678},
    ('ICMPv6', 'echo-reply'): {'id': 0x1234, 'seq': 0x5678},
    ('ICMP', 'destination-unreachable'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMP', 'time-exceeded'): {'unused': b'\xa1\xa2\xa3\xa4'},
    ('ICMP', 'parameter-problem'): {'pointer': 5, 'unused': b'\xa1\xa2\xa3'},
    ('ICMP', 'echo-request'): {'id': 0x1234, 'seq': 0x5678},
    ('ICMP', 'echo-reply'): {'id': 0x1234, 'seq': 0x5678},
}

#: The short read each cut records: inside the header, then inside the body, which
#: the header's ``data`` holds.
RECORDS = {1: ('code', 0), 2: ('checksum', 0), 3: ('checksum', 1),
           **{cut: ('data', cut - 4) for cut in range(4, 8)}}


def ipv6(payload: bytes, length: int) -> bytes:
    """An IPv6 header carrying ICMPv6 and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('60000000') + length.to_bytes(2, 'big') + bytes([58, 64])
            + bytes(15) + b'\x01' + bytes(15) + b'\x02' + payload)


def ipv4(payload: bytes, length: int) -> bytes:
    """An IPv4 header carrying ICMP and declaring ``length`` payload octets, then ``payload``."""
    return (bytes.fromhex('4500') + (20 + length).to_bytes(2, 'big')
            + bytes.fromhex('0000' '4000' '40' '01' '0000' '0a000001' '0a000002') + payload)


class StandaloneCutTests(unittest.TestCase):
    """Each message cut inside its fixed fields parses on its own and rebuilds as captured."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def messages(self) -> 'list[tuple[str, str, bytes, type, type, object]]':
        """Each message: alias, name, octets, class, the IP class and the wrapper giving its octets."""
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
        from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
        from pcapkit.protocols.internet.ipv4.protocol import IPv4
        from pcapkit.protocols.internet.ipv6.protocol import IPv6

        return [*(('ICMPv6', name, packet, ICMPv6, IPv6, ipv6) for name, packet in ICMPV6.items()),
                *(('ICMP', name, packet, ICMPv4, IPv4, ipv4) for name, packet in ICMPV4.items())]

    def parse(self, cls: type, part: bytes) -> object:
        """``part`` parsed on its own as ``cls``, any warning raised as an error past the header.

        A cut inside the header warns that its length fell below zero, as every
        protocol's does on its own; the body's fields past a cut warn nothing.

        """
        with warnings.catch_warnings():
            warnings.simplefilter('error' if len(part) >= 4 else 'ignore')
            return cls(io.BytesIO(part), len(part))  # type: ignore[call-arg]

    def test_fields_sit_where_the_rfcs_put_them(self) -> None:
        for alias, name, packet, cls, _, _ in self.messages():
            with self.subTest(protocol=alias, message=name):
                layer = self.parse(cls, packet)
                for key, value in FIELDS[alias, name].items():
                    self.assertEqual(layer.info[key], value)  # type: ignore[attr-defined]
                self.assertEqual(layer.info.data, QUOTED)  # type: ignore[attr-defined]
                self.assertIsNone(layer.info.get('__short_read__'))  # type: ignore[attr-defined]

    def test_cuts_are_quiet_short_reads_that_rebuild_as_captured(self) -> None:
        for alias, name, packet, cls, _, _ in self.messages():
            for cut, record in RECORDS.items():
                part = packet[:cut]
                with self.subTest(protocol=alias, message=name, cut=cut):
                    layer = self.parse(cls, part)
                    self.assertEqual(layer.info.get('__short_read__'), record)  # type: ignore[attr-defined]
                    for path, data in (('model', layer.info), ('dict', layer.info.to_dict())):  # type: ignore[attr-defined]
                        with self.subTest(path=path):
                            rebuilt = cls.from_data(data)  # type: ignore[attr-defined]
                            self.assertEqual(rebuilt.data.hex(), part.hex())
                            self.assertEqual(rebuilt.info, layer.info)  # type: ignore[attr-defined]

    def test_a_cut_records_what_it_does_behind_ip(self) -> None:
        # behind IP the message is the length the IP header declares, so only the
        # record and the fixed fields compare
        for alias, name, packet, cls, ip, wrap in self.messages():
            for cut in range(4, 8):
                part = packet[:cut]
                with self.subTest(protocol=alias, message=name, cut=cut):
                    with warnings.catch_warnings():
                        warnings.simplefilter('ignore')
                        frame = wrap(part, len(packet))  # type: ignore[operator]
                        behind = ip(io.BytesIO(frame), len(frame)).payload  # type: ignore[call-arg]
                    alone = self.parse(cls, part)
                    self.assertIsInstance(behind, cls)
                    for key in ('__short_read__', *FIELDS[alias, name]):
                        self.assertEqual(alone.info.get(key), behind.info.get(key), key)  # type: ignore[attr-defined]

    def test_a_message_its_ip_header_declares_short_is_still_refused(self) -> None:
        # inside a frame the IP header says where the message ends, so fixed fields
        # running past it are malformed, not cut, and the message is kept raw
        from pcapkit.protocols.misc.raw.protocol import Raw

        for alias, name, packet, _, ip, wrap in self.messages():
            for cut in range(4, 8):
                with self.subTest(protocol=alias, message=name, cut=cut), warnings.catch_warnings():
                    warnings.simplefilter('error')
                    frame = wrap(packet[:cut], cut)  # type: ignore[operator]
                    layer = ip(io.BytesIO(frame), len(frame)).payload  # type: ignore[call-arg]
                    self.assertIsInstance(layer, Raw)
                    self.assertRegex(str(layer.info.error),  # type: ignore[attr-defined]
                                     r'^Field data resolved to a negative length')

    def test_a_cut_icmp_message_reads_its_checksum_truncated(self) -> None:
        from pcapkit.corekit.checksum.internet import ChecksumStatus
        from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
        from pcapkit.utilities import config

        for name, packet in ICMPV4.items():
            for cut in range(4, 8):
                with self.subTest(message=name, cut=cut), mock.patch.object(config, 'CHECKSUM_VERIFY', True):
                    layer = self.parse(ICMPv4, packet[:cut])
                    self.assertIs(layer.info.checksum_status, ChecksumStatus.TRUNCATED)  # type: ignore[attr-defined]


class SchemaRemainderTests(unittest.TestCase):
    """A field sized by what is left reads nothing past a cut in a length ending with the data."""

    def setUp(self) -> None:
        reimport_once_per_class(self)
        from pcapkit.corekit.fields.numbers import UInt32Field
        from pcapkit.corekit.fields.strings import BytesField
        from pcapkit.protocols.schema import Schema

        class Body(Schema):
            """A fixed field, then a field sized by what is left."""

            fixed: 'int' = UInt32Field()
            rest: 'bytes' = BytesField(length=lambda pkt: pkt['__length__'])

        self.Body = Body

    def test_a_cut_in_a_length_ending_with_the_data_reads_the_rest_as_empty(self) -> None:
        for count in range(4):
            with self.subTest(count=count), warnings.catch_warnings():
                warnings.simplefilter('error')
                body = self.Body.unpack(b'\x01\x02\x03'[:count], count, {'__data_end__': True})
                self.assertEqual(body.__dict__['__short_read__'], ('fixed', count))
                self.assertEqual(body.rest, b'')

    def test_a_cut_in_any_other_length_is_still_refused(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            with self.assertRaisesRegex(ProtocolError, r"^Field rest resolved to a negative length; template='-2s'$"):
                self.Body.unpack(b'\x01\x02', 2)

    def test_an_overrun_of_a_length_ending_with_the_data_is_still_refused(self) -> None:
        # the data holds the fixed field, so nothing was cut: its four octets
        # overrun the two the schema was given
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaisesRegex(ProtocolError, r"^Field rest resolved to a negative length; template='-2s'$"):
            self.Body.unpack(bytes(8), 2, {'__data_end__': True})


if __name__ == '__main__':
    unittest.main()
