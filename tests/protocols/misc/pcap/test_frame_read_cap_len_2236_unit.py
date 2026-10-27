# -*- coding: utf-8 -*-
"""A PCAP frame hands its dissector the captured length, not the on-wire one.

This pins the length argument :meth:`Frame.read
<pcapkit.protocols.misc.pcap.frame.Frame.read>` passes to ``_decode_next_layer``
(#2236): ``frame.cap_len``, the octets present, never the on-wire ``frame.len``.
A frame the snapshot length cut inside its IPv4 header keeps IPv4 as
:class:`~pcapkit.protocols.misc.raw.Raw`, whose ``error`` names the cut, and the
trial parse's ``packet length < 0`` warnings go with the layer (#2308). The
dissection reads the same for either length, so the argument is read where it
is passed.

Every case builds its own octets and reads no capture. Classes are imported
inside each test, after :func:`~tests._support.reimport_once_per_class`.

"""

import io
import struct
import unittest
import unittest.mock
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

    def test_truncated_ipv4_header_is_raw_with_its_error(self) -> None:
        """The cut IPv4 header is kept as ``Raw`` naming the cut, with no warning.

        IPv4 is handed the 10 octets Ethernet leaves of the captured 24, short
        of its 20-octet header, so the trial parse raises and is replaced. Its
        warnings, ``packet length < 0`` down to ``-10``, describe the IPv4 layer
        the result does not have, and are dropped with it.
        """
        from pcapkit.protocols.misc.pcap.frame import Frame
        from pcapkit.protocols.misc.pcap.header import Header
        from pcapkit.protocols.misc.raw import Raw
        from pcapkit.utilities.warnings import SchemaWarning

        decode = unittest.mock.patch.object(Frame, '_decode_next_layer', autospec=True,
                                            side_effect=Frame._decode_next_layer)  # pylint: disable=protected-access
        with warnings.catch_warnings(record=True) as caught, decode as spy:
            warnings.simplefilter('always')
            frame = Frame(io.BytesIO(_record(ORIG_LEN)), num=1, header=Header(GLOBAL).info)
        self.assertEqual((frame.info.cap_len, frame.info.len), (len(PACKET), ORIG_LEN))
        self.assertEqual(spy.call_args.args[3], len(PACKET))

        ipv4 = frame.payload.payload
        self.assertIsInstance(ipv4, Raw)
        self.assertEqual(ipv4.info.error, 'IPv4: header length 20 runs past the end of the data (10 octets)')
        self.assertEqual([str(item.message) for item in caught if issubclass(item.category, SchemaWarning)], [])


if __name__ == '__main__':
    unittest.main()
