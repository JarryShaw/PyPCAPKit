# -*- coding: utf-8 -*-
"""A PCAP frame hands its dissector the captured length, not the on-wire one.

This pins the length argument :meth:`Frame.read
<pcapkit.protocols.misc.pcap.frame.Frame.read>` passes to ``_decode_next_layer``
(#2236). The dissector is handed ``frame.cap_len``, the octets present, so a
frame the snapshot length cut inside its IPv4 header reports the truncation as a
:class:`~pcapkit.utilities.warnings.SchemaWarning` ``packet length < 0``. Handed
the on-wire ``frame.len`` instead, the schema believes the octets it lacks are
there and the truncation passes silently.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Little-endian global header: v2.4, snaplen 65535, Ethernet.
GLOBAL = bytes.fromhex('d4c3b2a1' '0200' '0400' '00000000' '00000000' 'ffff0000' '01000000')
#: An Ethernet header carrying IPv4, followed by the first 10 of the 20 octets of
#: an IPv4 header, i.e. a frame cut inside its IPv4 header.
PACKET = (bytes(6) + bytes(range(1, 7)) + b'\x08\x00'
          + bytes.fromhex('4500008c000100004011'))
#: The on-wire length of the frame the snapshot length cut down to :data:`PACKET`.
ORIG_LEN = 154


def _record(orig_len: 'int') -> 'bytes':
    """A record holding :data:`PACKET` whose header claims ``orig_len`` on the wire."""
    return struct.pack('<IIII', 1_500_000_000, 7, len(PACKET), orig_len) + PACKET


class TestFrameReadCapLen(unittest.TestCase):
    """Pin that the dissector sees the captured octets of a truncated frame."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def schema_warnings(self, orig_len: 'int') -> 'list[str]':
        """The :class:`SchemaWarning` messages from parsing the record for ``orig_len``."""
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.utilities.warnings import SchemaWarning

        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter('always')
            frame = Frame(io.BytesIO(_record(orig_len)), num=1, header=Header(GLOBAL).info)
        self.assertEqual(frame.info.cap_len, len(PACKET))
        self.assertEqual(frame.info.len, orig_len)
        return [str(item.message) for item in caught if issubclass(item.category, SchemaWarning)]

    def test_truncated_ipv4_header_warns_whatever_the_on_wire_length(self) -> None:
        """The cut IPv4 header warns, the same as for an uncut frame of the same octets.

        IPv4 is handed the 10 octets Ethernet leaves of the captured 24, so its
        header runs the remaining length to ``-10``. Were the on-wire 154 handed
        over instead, IPv4 would be told of 140 octets and warn of nothing.
        """
        truncated = self.schema_warnings(ORIG_LEN)
        self.assertIn('packet length < 0: -10', truncated)
        self.assertEqual(truncated, self.schema_warnings(len(PACKET)))


if __name__ == '__main__':
    unittest.main()
