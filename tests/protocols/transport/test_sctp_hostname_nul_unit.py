"""#1482 -- an SCTP Host Name parameter without a NUL terminator rebuilds as captured.

:rfc:`9260#section-3.3.2.1.4` requires the host name to be null-terminated.
The reader accepts a name as captured, but the maker rejected an unterminated
one, so ``from_data(info)`` raised on a packet that parsed. The terminator
check now applies only to a ``name`` keyword, not to a parsed record.

"""
from __future__ import annotations

import importlib.util
import unittest

from tests._support import reimport_once_per_class

RUNTIME_DEPS = ('tbtrim', 'aenum', 'chardet', 'dictdumper')
HAS_RUNTIME = all(importlib.util.find_spec(name) is not None for name in RUNTIME_DEPS)

#: INIT chunk ending in a Host Name parameter, by name.
PACKETS = {
    # The repro from #1482: ``abcdefgh``, no terminator.
    'unterminated': bytes.fromhex('13881389deadbeef000000000100002000000001000003e8'
                                  '000a000a00000001000b000c6162636465666768'),
    # ``abcdefg\0``, terminated.
    'terminated': bytes.fromhex('13881389deadbeef000000000100002000000001000003e8'
                                '000a000a00000001000b000c6162636465666700'),
}

#: INIT carrying ``abcde`` unterminated, then ABORT and HEARTBEAT chunks. Every
#: cut from offset 44 to 66 parses; the full 67 octets are #1481's case.
MULTI = bytes.fromhex('13881389deadbeef000000000100002000000001000003e8000a000a00000001'
                      '000b000961626364650000000600000c000c0007616263000400000b0001000778797a')


@unittest.skipUnless(HAS_RUNTIME, 'runtime dependencies not installed')
class SCTPHostNameNulUnitTests(unittest.TestCase):
    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_parses_as_captured(self) -> None:
        """#1482: the parse reproduces the input and keeps the name verbatim."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in PACKETS.items():
            with self.subTest(case=name):
                packet = SCTP(raw)
                self.assertEqual(packet.data.hex(), raw.hex())
                param = packet.info.chunks[Chunk.Initiation].parameters[Parameter.Host_Name_Address]
                self.assertEqual(param.name, raw[-8:])

    def test_rebuilds_from_info(self) -> None:
        """#1482: ``from_data(info)`` writes back the captured octets."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in PACKETS.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info).data.hex(), raw.hex())

    def test_rebuilds_from_to_dict(self) -> None:
        """#1482: the record survives ``info.to_dict()``."""
        from pcapkit.protocols.transport.sctp import SCTP

        for name, raw in PACKETS.items():
            with self.subTest(case=name):
                self.assertEqual(SCTP.from_data(SCTP(raw).info.to_dict()).data.hex(), raw.hex())

    def test_rebuilds_every_cut_after_the_init_chunk(self) -> None:
        """#1482: a packet cut anywhere after its INIT chunk rebuilds as captured."""
        from pcapkit.protocols.transport.sctp import SCTP

        for size in range(44, 67):
            raw = MULTI[:size]
            with self.subTest(size=size):
                info = SCTP(raw).info
                self.assertEqual(SCTP.from_data(info).data.hex(), raw.hex())
                self.assertEqual(SCTP.from_data(info.to_dict()).data.hex(), raw.hex())

    def test_make_still_requires_a_terminator(self) -> None:
        """#1482: a ``name`` keyword without a terminator is still rejected."""
        from pcapkit.const.sctp.chunk import Chunk
        from pcapkit.const.sctp.parameter import Parameter
        from pcapkit.protocols.transport.sctp import SCTP
        from pcapkit.utilities.exceptions import ProtocolError

        with self.assertRaises(ProtocolError):
            SCTP(chunks=[(Chunk.Initiation, {
                'init_tag': 1,
                'parameters': [(Parameter.Host_Name_Address, {'name': b'abcdefgh'})],
            })])

        data = SCTP(chunks=[(Chunk.Initiation, {
            'init_tag': 1,
            'parameters': [(Parameter.Host_Name_Address, {'name': b'abcdefg\x00'})],
        })]).data
        self.assertEqual(data[-12:].hex(), '000b000c6162636465666700')


if __name__ == '__main__':
    unittest.main()
