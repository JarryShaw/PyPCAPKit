# -*- coding: utf-8 -*-
"""ICMPv6 (RFC 4443) messages rebuild byte for byte through ``from_data``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: As much of an invoking packet as :rfc:`4443` quotes -- just 40 distinct
#: octets, so a byte-for-byte mismatch is easy to spot.
QUOTED = bytes(range(40))

#: Each entry is ``type || code || checksum`` followed by that type's own
#: body, built by hand against :rfc:`4443`.
ICMPV6_PACKETS = {
    'destination-unreachable': bytes.fromhex('0103' 'abcd' '00000000') + QUOTED,
    'packet-too-big':          bytes.fromhex('0200' 'abcd' '00000500') + QUOTED,
    'time-exceeded':           bytes.fromhex('0301' 'abcd' '00000000') + QUOTED,
    'parameter-problem':       bytes.fromhex('0401' 'abcd' '00000028') + QUOTED,
    'echo-request':            bytes.fromhex('8000' '1234' '0001' '0002') + b'abcd',
    'echo-reply':              bytes.fromhex('8100' '4321' '0003' '0004') + b'wxyz',
    'unknown-type-router-sol': bytes.fromhex('8500' '0000') + bytes(8),
}


class ICMPv6RoundTripTests(unittest.TestCase):
    """Pin the byte-for-byte rebuild of every ICMPv6 message type covered."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        for name, packet in ICMPV6_PACKETS.items():
            with self.subTest(packet=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv6(io.BytesIO(packet), len(packet))
                self.assertEqual(ICMPv6.from_data(parsed.info).data, packet,
                                 f'{name} did not rebuild byte for byte')

    def test_destination_unreachable_code_is_parsed(self) -> None:
        from pcapkit.const.icmpv6.destination_unreachable_code import DestinationUnreachableCode
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        packet = ICMPV6_PACKETS['destination-unreachable']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv6(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.code, DestinationUnreachableCode.address_unreachable)
        self.assertEqual(parsed.info.data, QUOTED)

    def test_packet_too_big_mtu_is_parsed(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        packet = ICMPV6_PACKETS['packet-too-big']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv6(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.mtu, 0x500)
        self.assertEqual(parsed.info.data, QUOTED)

    def test_parameter_problem_pointer_is_32_bit(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        packet = ICMPV6_PACKETS['parameter-problem']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv6(io.BytesIO(packet), len(packet))

        # Unlike ICMPv4's Parameter Problem, ICMPv6's Pointer is a full
        # 32-bit offset into the invoking packet, not an 8-bit one.
        self.assertEqual(parsed.info.pointer, 40)

    def test_echo_fields_are_parsed(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        packet = ICMPV6_PACKETS['echo-request']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv6(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.id, 1)
        self.assertEqual(parsed.info.seq, 2)
        self.assertEqual(parsed.info.data, b'abcd')

    def test_unknown_type_keeps_raw_body(self) -> None:
        """Router Solicitation (Neighbor Discovery) is unimplemented."""
        from pcapkit.protocols.data.internet.icmpv6 import Unknown
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        packet = ICMPV6_PACKETS['unknown-type-router-sol']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv6(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.info, Unknown)
        self.assertEqual(parsed.info.data, bytes(8))

    def test_make_builds_echo_from_scratch(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        proto = object.__new__(ICMPv6)
        schema = proto.make(type=128, code=0, checksum=b'\x124',
                            body={'id': 1, 'seq': 2, 'data': b'abcd'})
        self.assertEqual(schema.pack(), ICMPV6_PACKETS['echo-request'])

    def test_construct_with_no_arguments(self) -> None:
        """``ICMPv6()`` builds a default Echo Request rather than raising."""
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        proto = ICMPv6()
        self.assertEqual(bytes(proto), bytes.fromhex('8000000000000000'))

    def test_icmpv6_over_ipv4_dispatches_without_crashing(self) -> None:
        """ICMPv6 reached over IPv4 (protocol 58) dispatches cleanly.

        This is an unusual but legitimate framing (protocol 58 directly over
        IPv4, without an enclosing IPv6 header), and must not crash the
        whole layer down to :class:`~pcapkit.protocols.misc.raw.Raw`.
        """
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.protocols.internet.ipv4 import IPv4

        icmpv6_body = ICMPV6_PACKETS['echo-request']
        header = bytearray(bytes.fromhex(
            '45' '00' '0000' '0000' '0000' '40' '3a' '0000'
            '7f000001' '7f000001'
        ))  # protocol 0x3a = 58 = ICMPv6
        header[2:4] = struct.pack('>H', 20 + len(icmpv6_body))
        packet = bytes(header) + icmpv6_body

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, ICMPv6)
        self.assertEqual(parsed.payload.info.id, 1)

    def test_dispatches_from_ipv6(self) -> None:
        """IPv6's next-header dispatch reaches :class:`ICMPv6`."""
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.protocols.internet.ipv6 import IPv6

        icmpv6_body = ICMPV6_PACKETS['echo-request']
        header = bytearray(40)
        header[0] = 0x60
        header[4:6] = struct.pack('>H', len(icmpv6_body))
        header[6] = 58  # next header = ICMPv6
        header[7] = 64  # hop limit
        header[8:24] = (b'\x00' * 15) + b'\x01'
        header[24:40] = (b'\x00' * 15) + b'\x02'
        packet = bytes(header) + icmpv6_body

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv6(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, ICMPv6)
        self.assertEqual(parsed.payload.info.id, 1)

    def test_id_index_and_length_hint(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.icmp import ICMP
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        self.assertEqual(ICMPv6.id(), ('ICMPv6',))
        self.assertEqual(ICMP.id(), ('ICMP', 'ICMPv6'))
        self.assertTrue(issubclass(ICMPv6, ICMP))
        self.assertFalse(issubclass(ICMPv6, ICMPv4))
        self.assertEqual(ICMPv6.__index__(), TransType.IPv6_ICMP)
        self.assertEqual(object.__new__(ICMPv6).__length_hint__(), 4)

    def test_register_type_warns_on_override(self) -> None:
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.warnings import RegistryWarning

        original = ICMPv6.__type__[Type.Echo_Request]
        try:
            with self.assertWarns(RegistryWarning):
                ICMPv6.register_type(Type.Echo_Request, 'none')
            self.assertEqual(ICMPv6.__type__[Type.Echo_Request], 'none')

            # Re-registering the same entry is a silent no-op.
            with warnings.catch_warnings():
                warnings.simplefilter('error', RegistryWarning)
                ICMPv6.register_type(Type.Echo_Request, 'none')
        finally:
            ICMPv6.__type__[Type.Echo_Request] = original

    def test_name_property(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        self.assertEqual(object.__new__(ICMPv6).name,
                         'Internet Control Message Protocol for IPv6')

    def test_make_rejects_bytes_body_that_fails_to_parse(self) -> None:
        """Parameter Problem's body needs at least four octets."""
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv6)
        with self.assertRaises(ProtocolError), warnings.catch_warnings():
            warnings.simplefilter('ignore')
            proto.make(type=4, code=0, checksum=b'\x00\x00', body=b'\x01')

    def test_make_rejects_an_unsupported_body_type(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv6)
        with self.assertRaises(ProtocolError):
            proto.make(type=128, code=0, checksum=b'\x00\x00', body=12345)  # type: ignore[arg-type]

    def test_make_accepts_a_pre_built_schema_body(self) -> None:
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.protocols.schema.internet.icmpv6 import Echo as Schema_Echo

        proto = object.__new__(ICMPv6)
        pre_built = Schema_Echo(id=1, seq=2, data=b'abcd')
        schema = proto.make(type=128, code=0, checksum=b'\x124', body=pre_built)
        self.assertEqual(schema.pack(), ICMPV6_PACKETS['echo-request'])

    def test_register_type_accepts_a_callable_pair(self) -> None:
        """A ``(parser, constructor)`` pair bypasses the ``_read/_make_data_type_*`` lookup."""
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.data.internet.icmpv6 import Unknown as Data_Unknown
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        def custom_parser(schema, *, header, length):  # pylint: disable=unused-argument
            return Data_Unknown(type=header.type, code=header.code, checksum=header.checksum,
                               length=length, data=b'custom-parsed')

        def custom_constructor(type, message=None, **kwargs):  # pylint: disable=redefined-builtin,unused-argument
            from pcapkit.protocols.schema.internet.icmpv6 import Unknown as Schema_Unknown
            return Schema_Unknown(data=b'custom-made')

        # ``.get`` rather than ``[...]``: a defaultdict lookup by subscript
        # would insert the default and make the registration below warn about
        # "already registered" for a code that, from the caller's side, never
        # was.
        original = ICMPv6.__type__.get(Type.Router_Renumbering)
        try:
            ICMPv6.register_type(Type.Router_Renumbering, (custom_parser, custom_constructor))

            packet = bytes.fromhex('8a00' '0000') + bytes(12)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv6(io.BytesIO(packet), len(packet))
            self.assertEqual(parsed.info.data, b'custom-parsed')

            proto = object.__new__(ICMPv6)
            schema = proto.make(type=Type.Router_Renumbering, code=0, checksum=b'\x00\x00', body={})
            self.assertEqual(schema.data.data, b'custom-made')
        finally:
            if original is None:
                ICMPv6.__type__.pop(Type.Router_Renumbering, None)
            else:
                ICMPv6.__type__[Type.Router_Renumbering] = original

    def test_make_error_messages_use_the_shared_alias(self) -> None:
        """The shared make path words its errors with ``alias``, which is ``ICMPv6`` here."""
        from pcapkit.protocols.internet.icmpv6 import ICMPv6
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv6)
        with warnings.catch_warnings(), self.assertRaises(ProtocolError) as ctx:
            warnings.simplefilter('ignore')
            proto.make(type=128, code=0, checksum=b'\x00\x00', body=b'\x01')
        self.assertEqual(str(ctx.exception),
                         'ICMPv6: [TypeNo 128] message body 01 does not parse as this type')
        with warnings.catch_warnings(), self.assertRaises(ProtocolError) as ctx:
            warnings.simplefilter('ignore')
            proto.make(type=128, code=0, checksum=b'\x00\x00', body=12345)  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception), "ICMPv6: invalid message body type: <class 'int'>")

    def test_register_type_writes_icmpv6_type_registry_only(self) -> None:
        """``ICMPv6.register_type`` writes ICMPv6's own ``__type__``, never ICMPv4's."""
        from pcapkit.const.icmpv6.type import Type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.icmpv6 import ICMPv6

        code = Type.Router_Renumbering
        original = ICMPv6.__type__.get(code)
        try:
            ICMPv6.register_type(code, 'none')
            self.assertEqual(ICMPv6.__type__[code], 'none')
            self.assertIsNone(ICMPv4.__type__.get(code))
        finally:
            if original is None:
                ICMPv6.__type__.pop(code, None)
            else:
                ICMPv6.__type__[code] = original


if __name__ == '__main__':
    unittest.main()
