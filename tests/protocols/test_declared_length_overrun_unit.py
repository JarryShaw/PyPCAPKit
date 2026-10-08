# -*- coding: utf-8 -*-
"""An option declaring more octets than are present is rejected, not zero-filled.

GitHub issue #1325: :meth:`OptionField.unpack
<pcapkit.corekit.fields.collections.OptionField.unpack>` let an option schema
read past the end of its data, and every field reading off the end padded the
missing octets with zeros. A HIP ``ACK`` declaring 256 octets with 4 present
parsed as 64 update IDs and rebuilt to 304 octets; an MH ``PadN`` declaring 3
octets with none present rebuilt 24 octets from 16.

Such an option now raises :exc:`~pcapkit.utilities.exceptions.ProtocolError`.
Inside a parent layer the octets are kept as captured -- raw extension data
under IPv6, a :class:`~pcapkit.protocols.misc.raw.Raw` payload elsewhere -- and
the parent rebuilds byte for byte.

An option that begins at the end of the data reads nothing at all, and is still
left to the end-of-option-list handling an over-long option area relies on.

Every case builds its own octets in memory and reads no capture.

"""

import struct
import unittest
import warnings

from tests._support import reimport_once_per_class


def _hip(params: bytes) -> bytes:
    """A HIP ``I1`` header (40 octets) carrying ``params``."""
    return (bytes([59, (40 + len(params)) // 8 - 1, 1, 0x11, 0, 0, 0, 0])
            + b'\x11' * 16 + b'\x22' * 16 + params)


def _ext6(opts: bytes) -> bytes:
    """An IPv6 options extension header carrying ``opts``."""
    return bytes([59, (2 + len(opts)) // 8 - 1]) + opts


def _sctp(chunks: bytes) -> bytes:
    """An SCTP common header carrying ``chunks``."""
    return struct.pack('>HHII', 1, 2, 0, 0) + chunks


def _tcp(opts: bytes) -> bytes:
    """A TCP header carrying ``opts``."""
    return struct.pack('>HHIIBBHHH', 1, 2, 0, 0, (5 + len(opts) // 4) << 4, 0x10, 0, 0, 0) + opts


def _ipv4(opts: bytes, ihl: int, proto: int = 253, payload: bytes = b'') -> bytes:
    """An IPv4 header declaring ``ihl`` and carrying ``opts`` and ``payload``."""
    return (bytes([0x40 | ihl, 0]) + struct.pack('>H', 20 + len(opts) + len(payload))
            + bytes.fromhex('00010000 40') + bytes([proto]) + bytes(2)
            + bytes.fromhex('0a000001 0a000002') + opts + payload)


def _ipv6(proto: int, payload: bytes) -> bytes:
    """An IPv6 header carrying ``payload`` as next header ``proto``."""
    return (bytes.fromhex('60000000') + struct.pack('>H', len(payload)) + bytes([proto, 64])
            + b'\x11' * 16 + b'\x22' * 16 + payload)


#: Option areas whose last option declares more octets than the area holds.
OVERRUNS = {
    # issue #1325: ACK declaring 0x0100 octets, 4 present
    'HIP ACK': ('pcapkit.protocols.internet.hip', 'HIP', _hip(bytes.fromhex('01c10100 00000000'))),
    # issue #1325: PadN declaring 3 octets, none present
    'MH PadN': ('pcapkit.protocols.internet.mh', 'MH',
                bytes.fromhex('3b010000 00000000 010400000000 0103')),
    'HOPOPT PadN': ('pcapkit.protocols.internet.hopopt', 'HOPOPT', _ext6(bytes.fromhex('010700000000'))),
    'IPv6-Opts PadN': ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts', _ext6(bytes.fromhex('010700000000'))),
    'SCTP INIT parameter': ('pcapkit.protocols.transport.sctp', 'SCTP', _sctp(
        bytes.fromhex('01000020 00000001 00010000 00010001 00000001 000c0010 00050000'))),
    # an unassigned kind declaring 12 octets, 8 present
    'TCP unassigned': ('pcapkit.protocols.transport.tcp', 'TCP', _tcp(bytes.fromhex('4f0caabb ccddeeff'))),
    # an unassigned option declaring 12 octets, 8 present in a 16-octet area
    'IPv4 unassigned': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                        _ipv4(bytes.fromhex('1f0caabb ccddeeff'), ihl=9)),
}

#: The same option areas with every option complete.
CONTROLS = {
    'HIP ACK': ('pcapkit.protocols.internet.hip', 'HIP', _hip(bytes.fromhex('01c10004 00000001'))),
    'MH PadN': ('pcapkit.protocols.internet.mh', 'MH',
                bytes.fromhex('3b010000 00000000 0106000000000000')),
    'HOPOPT PadN': ('pcapkit.protocols.internet.hopopt', 'HOPOPT', _ext6(bytes.fromhex('010400000000'))),
    'IPv6-Opts PadN': ('pcapkit.protocols.internet.ipv6_opts', 'IPv6_Opts', _ext6(bytes.fromhex('010400000000'))),
    'SCTP INIT parameter': ('pcapkit.protocols.transport.sctp', 'SCTP', _sctp(
        bytes.fromhex('0100001c 00000001 00010000 00010001 00000001 000c0008 00050006'))),
    'TCP unassigned': ('pcapkit.protocols.transport.tcp', 'TCP', _tcp(bytes.fromhex('4f08aabb ccddeeff'))),
    'IPv4 unassigned': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                        _ipv4(bytes.fromhex('1f08aabb ccddeeff'), ihl=7)),
}

#: Each overrun inside a parent layer: (parent module, parent class, frame).
IN_PARENT = {
    'HIP ACK': ('pcapkit.protocols.internet.ipv6', 'IPv6', _ipv6(139, OVERRUNS['HIP ACK'][2])),
    'MH PadN': ('pcapkit.protocols.internet.ipv6', 'IPv6', _ipv6(135, OVERRUNS['MH PadN'][2])),
    'HOPOPT PadN': ('pcapkit.protocols.internet.ipv6', 'IPv6', _ipv6(0, OVERRUNS['HOPOPT PadN'][2])),
    'IPv6-Opts PadN': ('pcapkit.protocols.internet.ipv6', 'IPv6', _ipv6(60, OVERRUNS['IPv6-Opts PadN'][2])),
    'SCTP INIT parameter': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                            _ipv4(b'', ihl=5, proto=132, payload=OVERRUNS['SCTP INIT parameter'][2])),
    'TCP unassigned': ('pcapkit.protocols.internet.ipv4', 'IPv4',
                       _ipv4(b'', ihl=5, proto=6, payload=OVERRUNS['TCP unassigned'][2])),
    'IPv4 unassigned': ('pcapkit.protocols.link.ethernet', 'Ethernet',
                        bytes.fromhex('0123456789ab fedcba987654 0800') + OVERRUNS['IPv4 unassigned'][2]),
}


class TestDeclaredLengthOverrun(unittest.TestCase):
    """Pin the rejection of an option running past the end of its data."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    @staticmethod
    def _protocol(module: str, name: str) -> type:
        import importlib

        return getattr(importlib.import_module(module), name)

    def test_an_overrunning_option_raises_protocol_error(self) -> None:
        from pcapkit.utilities.exceptions import ProtocolError

        for case, (module, name, data) in OVERRUNS.items():
            with self.subTest(case=case):
                protocol = self._protocol(module, name)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    with self.assertRaisesRegex(ProtocolError, 'runs past the end of the data'):
                        protocol(data, len(data))

    def test_a_complete_option_still_rebuilds_byte_for_byte(self) -> None:
        for case, (module, name, data) in CONTROLS.items():
            with self.subTest(case=case):
                protocol = self._protocol(module, name)
                parsed = protocol(data, len(data))
                self.assertEqual(protocol.from_data(parsed.info).data, data)

    def test_an_overrunning_layer_is_kept_as_captured_by_its_parent(self) -> None:
        from pcapkit.protocols.misc.raw import Raw

        for case, (module, name, frame) in IN_PARENT.items():
            with self.subTest(case=case):
                protocol = self._protocol(module, name)
                with warnings.catch_warnings():
                    warnings.simplefilter('ignore')
                    parsed = protocol(frame, len(frame))

                if name == 'IPv6':
                    # an extension header is kept as raw extension data
                    self.assertIn('runs past the end of the data', str(parsed.info.ext.error))
                else:
                    # any other layer is kept as a raw payload, as captured
                    self.assertIsInstance(parsed.payload, Raw)
                    self.assertIn('runs past the end of the data', str(parsed.payload.info.error))
                    self.assertEqual(parsed.payload.data, OVERRUNS[case][2])
                self.assertEqual(protocol.from_data(parsed.info).data, frame)

    def test_an_option_area_declared_past_the_data_still_ends_at_eool(self) -> None:
        from pcapkit.protocols.internet.ipv4 import IPv4

        # ``ihl`` declares 20 octets of options with none present: the first
        # option begins at the end of the data, so it is end-of-option-list.
        data = bytes.fromhex('4a00001800010000400600000a0000010a000002')
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(data, len(data))
        self.assertEqual(parsed.info.src.compressed, '10.0.0.1')


if __name__ == '__main__':
    unittest.main()
