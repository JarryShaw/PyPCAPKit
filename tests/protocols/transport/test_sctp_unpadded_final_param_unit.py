"""#1479 -- a final SCTP parameter or error cause sent without its padding parses and rebuilds.

:rfc:`9260#section-3.2` lets the last chunk of a packet omit its padding, and in
a chunk carrying a parameter or cause list that is the last item's padding. The
nested list's span counted that padding whether or not it was there, so the last
item read past the data and parsing raised :exc:`ProtocolError`. The span is now
clamped to the octets present.

"""
from __future__ import annotations

import importlib.util
import struct
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: SCTP common header with a zero checksum.
COMMON = struct.pack('!HHII', 5000, 5001, 0xdeadbeef, 0)
#: INIT and INIT ACK chunk fixed part.
INIT_HEAD = struct.pack('!IIHHI', 1, 1000, 10, 10, 1)


def tlv(type_: int, value: bytes, pad: 'bytes | None' = None) -> bytes:
    """A parameter or cause, zero-padded to four octets unless ``pad`` is given."""
    length = 4 + len(value)
    pad = bytes(-length % 4) if pad is None else pad
    return struct.pack('!HH', type_, length) + value + pad


def chunk(type_: int, value: bytes) -> bytes:
    """A chunk whose ``length`` covers ``value`` exactly, with no padding after it."""
    return struct.pack('!BBH', type_, 0, 4 + len(value)) + value


HOST = tlv(11, b'abcd\x00', pad=b'')
CAUSE = tlv(12, b'abc', pad=b'')

#: Packets whose final parameter or cause has no padding, by name.
SHORT = {
    'init-sole-hostname': COMMON + chunk(1, INIT_HEAD + HOST),
    'init-ipv4-then-hostname': COMMON + chunk(1, INIT_HEAD + tlv(5, b'\x0a\x00\x00\x01') + HOST),
    'init-two-hostnames': COMMON + chunk(1, INIT_HEAD + tlv(11, b'abcd\x00') + HOST),
    'init-final-type-0x8000': COMMON + chunk(1, INIT_HEAD + tlv(0x8000, b'a', pad=b'')),
    'init-ack-hostname': COMMON + chunk(2, INIT_HEAD + HOST),
    'abort-sole-cause': bytes.fromhex('13881389deadbeef000000000600000b000c0007616263'),
    'abort-two-causes': COMMON + chunk(6, tlv(12, b'a') + CAUSE),
    'error-sole-cause': COMMON + chunk(9, CAUSE),
    'error-two-causes': COMMON + chunk(9, tlv(12, b'a') + CAUSE),
    'heartbeat': COMMON + chunk(4, tlv(1, b'a', pad=b'')),
    'heartbeat-ack': COMMON + chunk(5, tlv(1, b'a', pad=b'')),
}


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SCTPUnpaddedFinalParameterUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parses_and_rebuilds_through_data(self) -> None:
        """#1479: the packet parses and ``.data`` is the octets as captured."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in SHORT.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP(raw).data.hex(), raw.hex())

    def test_rebuilds_from_info(self) -> None:
        """#1479: ``from_data(info)`` writes no padding the final item lacked."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in SHORT.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info).data.hex(), raw.hex())

    def test_rebuilds_from_to_dict(self) -> None:
        """#1479: the record survives ``info.to_dict()``."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in SHORT.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info.to_dict()).data.hex(), raw.hex())

    def test_only_the_final_item_records_short_padding(self) -> None:
        """#1479: the final item keeps ``padding=b''``; the one before it keeps none."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, field in (('init-two-hostnames', 'parameters'), ('abort-two-causes', 'error')):
            with self.subTest(case=name):
                last = list(SCTP(SHORT[name]).info.chunks.items(multi=True))[-1][1]
                items = [item for _, item in last[field].items(multi=True)]
                self.assertEqual(len(items), 2)
                self.assertNotIn('padding', items[0])
                self.assertEqual(items[1].padding, b'')

    def test_issue_init_repro_parses(self) -> None:
        """#1479: the INIT from the issue parses, its host name read in full."""
        from pcapkit.protocols.transport.sctp import SCTP

        raw = bytes.fromhex('13881389deadbeef000000000100001d00000001000003e8000a000a'
                            '00000001000b00096162636465')
        init = list(SCTP(raw).info.chunks.items(multi=True))[-1][1]
        host = list(init.parameters.items(multi=True))[-1][1]
        self.assertEqual(host.name, b'abcde')
        self.assertEqual(host.padding, b'')


if __name__ == '__main__':
    unittest.main()
