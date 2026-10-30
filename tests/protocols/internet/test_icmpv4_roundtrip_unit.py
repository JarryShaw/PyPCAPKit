# -*- coding: utf-8 -*-
"""ICMP (RFC 792) messages rebuild byte for byte through ``from_data``.

Every case builds its own octets in memory and reads no capture. Classes are
imported inside each test, after
:func:`~tests._support.reimport_once_per_class`, not at module load, so that
they belong to the :mod:`pcapkit` import that is live when the test runs.

"""

import io
import struct
import unittest
import warnings

from tests._support import reimport_once_per_class

#: Test tier (#1958): hand-picked round-trip cases, not a sweep.
__tier__ = 'ALL'

#: Internet header plus the first eight octets of the original datagram's
#: payload, as the Destination Unreachable / Time Exceeded / Parameter
#: Problem bodies quote it. Not a real IP header -- just 20 distinct octets,
#: so a byte-for-byte mismatch is easy to spot.
QUOTED = bytes(range(20))

#: Each entry is ``type || code || checksum`` followed by that type's own
#: body, built by hand against :rfc:`792`.
ICMP_PACKETS = {
    'echo-request':            bytes.fromhex('0800' '1234' '0001' '0002') + b'abcd',
    'echo-reply':               bytes.fromhex('0000' '4321' '0003' '0004') + b'wxyz',
    'destination-unreachable':  bytes.fromhex('0301' 'abcd' 'deadbeef') + QUOTED,
    'time-exceeded':            bytes.fromhex('0b01' 'abcd' '11223344') + QUOTED,
    'parameter-problem':        bytes.fromhex('0c02' 'abcd' '05' 'f0f0f0') + QUOTED,
    'unknown-type':             bytes.fromhex('2a00' '0000') + b'extended-echo-body',
    'empty-body':               bytes.fromhex('0800' '0000' '0000' '0000'),
}


class ICMPv4RoundTripTests(unittest.TestCase):
    """Pin the byte-for-byte rebuild of every ICMP message type covered."""

    def setUp(self) -> None:
        reimport_once_per_class(self)

    def test_from_data_rebuilds_byte_for_byte(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        for name, packet in ICMP_PACKETS.items():
            with self.subTest(packet=name), warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv4(io.BytesIO(packet), len(packet))
                self.assertEqual(ICMPv4.from_data(parsed.info).data, packet,
                                 f'{name} did not rebuild byte for byte')

    def test_echo_request_fields_are_parsed(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        packet = ICMP_PACKETS['echo-request']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv4(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.id, 1)
        self.assertEqual(parsed.info.seq, 2)
        self.assertEqual(parsed.info.data, b'abcd')
        self.assertEqual(parsed.info.checksum, b'\x124')

    def test_destination_unreachable_fields_are_parsed(self) -> None:
        from pcapkit.const.icmp.destination_unreachable_code import DestinationUnreachableCode
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        packet = ICMP_PACKETS['destination-unreachable']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv4(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.code, DestinationUnreachableCode.Host_Unreachable)
        self.assertEqual(parsed.info.unused, bytes.fromhex('deadbeef'))
        self.assertEqual(parsed.info.data, QUOTED)

    def test_parameter_problem_pointer_is_parsed(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        packet = ICMP_PACKETS['parameter-problem']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv4(io.BytesIO(packet), len(packet))

        self.assertEqual(parsed.info.pointer, 5)
        self.assertEqual(parsed.info.unused, bytes.fromhex('f0f0f0'))
        self.assertEqual(parsed.info.data, QUOTED)

    def test_unknown_type_keeps_raw_body(self) -> None:
        from pcapkit.protocols.data.internet.icmpv4 import Unknown
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        packet = ICMP_PACKETS['unknown-type']
        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = ICMPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.info, Unknown)
        self.assertEqual(parsed.info.data, b'extended-echo-body')

    def test_make_builds_echo_from_scratch(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        proto = object.__new__(ICMPv4)
        schema = proto.make(type=8, code=0, checksum=b'\x124',
                            body={'id': 1, 'seq': 2, 'data': b'abcd'})
        self.assertEqual(schema.pack(), ICMP_PACKETS['echo-request'])

    def test_make_accepts_raw_bytes_body(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        proto = object.__new__(ICMPv4)
        body = struct.pack('>HH', 1, 2) + b'abcd'
        schema = proto.make(type=8, code=0, checksum=b'\x124', body=body)
        self.assertEqual(schema.pack(), ICMP_PACKETS['echo-request'])

    def test_construct_with_no_arguments(self) -> None:
        """``ICMPv4()`` builds a default Echo Request rather than raising."""
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        proto = ICMPv4()
        # Type 8 (Echo), code 0, an uncomputed (zero) RFC 792 checksum over
        # an all-zero 4-octet id/seq body, then that same body: this class
        # does not compute or verify the checksum (#2470).
        self.assertEqual(bytes(proto), bytes.fromhex('0800000000000000'))

    def test_dispatches_from_ipv4(self) -> None:
        """IPv4's protocol-number dispatch reaches :class:`ICMPv4`."""
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.internet.ipv4 import IPv4

        icmp_body = ICMP_PACKETS['echo-request']
        header = bytearray(bytes.fromhex(
            '45' '00' '0000' '0000' '0000' '40' '01' '0000'
            '7f000001' '7f000001'
        ))
        header[2:4] = struct.pack('>H', 20 + len(icmp_body))
        packet = bytes(header) + icmp_body

        with warnings.catch_warnings():
            warnings.simplefilter('ignore')
            parsed = IPv4(io.BytesIO(packet), len(packet))

        self.assertIsInstance(parsed.payload, ICMPv4)
        self.assertEqual(parsed.payload.info.id, 1)

    def test_id_index_and_length_hint(self) -> None:
        from pcapkit.const.reg.transtype import TransType
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        self.assertEqual(ICMPv4.id(), ('ICMP',))
        self.assertEqual(ICMPv4.__index__(), TransType.ICMP)
        self.assertEqual(object.__new__(ICMPv4).__length_hint__(), 4)

    def test_register_type_warns_on_override(self) -> None:
        from pcapkit.const.icmp.type import Type
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.utilities.warnings import RegistryWarning

        original = ICMPv4.__type__[Type.Echo]
        try:
            with self.assertWarns(RegistryWarning):
                ICMPv4.register_type(Type.Echo, 'none')
            self.assertEqual(ICMPv4.__type__[Type.Echo], 'none')

            # Re-registering the same entry is a silent no-op.
            with warnings.catch_warnings():
                warnings.simplefilter('error', RegistryWarning)
                ICMPv4.register_type(Type.Echo, 'none')
        finally:
            ICMPv4.__type__[Type.Echo] = original

    def test_name_property(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        self.assertEqual(object.__new__(ICMPv4).name, 'Internet Control Message Protocol')

    def test_make_rejects_bytes_body_that_fails_to_parse(self) -> None:
        """Parameter Problem's body needs at least four octets."""
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv4)
        with self.assertRaises(ProtocolError):
            proto.make(type=12, code=0, checksum=b'\x00\x00', body=b'\x01')

    def test_make_rejects_an_unsupported_body_type(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv4)
        with self.assertRaises(ProtocolError):
            proto.make(type=8, code=0, checksum=b'\x00\x00', body=12345)  # type: ignore[arg-type]

    def test_make_accepts_a_pre_built_schema_body(self) -> None:
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.protocols.schema.internet.icmpv4 import Echo as Schema_Echo

        proto = object.__new__(ICMPv4)
        pre_built = Schema_Echo(id=1, seq=2, data=b'abcd')
        schema = proto.make(type=8, code=0, checksum=b'\x124', body=pre_built)
        self.assertEqual(schema.pack(), ICMP_PACKETS['echo-request'])

    def test_register_type_accepts_a_callable_pair(self) -> None:
        """A ``(parser, constructor)`` pair bypasses the ``_read/_make_data_type_*`` lookup."""
        from pcapkit.const.icmp.type import Type
        from pcapkit.protocols.data.internet.icmpv4 import Unknown as Data_Unknown
        from pcapkit.protocols.internet.icmpv4 import ICMPv4

        def custom_parser(schema, *, header, length):  # pylint: disable=unused-argument
            return Data_Unknown(type=header.type, code=header.code, checksum=header.checksum,
                               length=length, data=b'custom-parsed')

        def custom_constructor(type, message=None, **kwargs):  # pylint: disable=redefined-builtin,unused-argument
            from pcapkit.protocols.schema.internet.icmpv4 import Unknown as Schema_Unknown
            return Schema_Unknown(data=b'custom-made')

        # ``.get`` rather than ``[...]``: a defaultdict lookup by subscript
        # would insert the default and make the registration below warn about
        # "already registered" for a code that, from the caller's side, never
        # was.
        original = ICMPv4.__type__.get(Type.Timestamp)
        try:
            ICMPv4.register_type(Type.Timestamp, (custom_parser, custom_constructor))

            packet = bytes.fromhex('0d00' '0000') + bytes(12)
            with warnings.catch_warnings():
                warnings.simplefilter('ignore')
                parsed = ICMPv4(io.BytesIO(packet), len(packet))
            self.assertEqual(parsed.info.data, b'custom-parsed')

            proto = object.__new__(ICMPv4)
            schema = proto.make(type=Type.Timestamp, code=0, checksum=b'\x00\x00', body={})
            self.assertEqual(schema.data.data, b'custom-made')
        finally:
            # Delete rather than reassign when there was nothing to restore:
            # the key was never present before this test ran, and writing
            # back ``None`` would leave it mismatched against what the
            # dispatch code in ``read``/``make`` expects.
            if original is None:
                ICMPv4.__type__.pop(Type.Timestamp, None)
            else:
                ICMPv4.__type__[Type.Timestamp] = original

    def test_make_error_messages_use_the_shared_alias(self) -> None:
        """The shared make path words its errors with ``alias``, which is ``ICMP`` here."""
        from pcapkit.protocols.internet.icmpv4 import ICMPv4
        from pcapkit.utilities.exceptions import ProtocolError

        proto = object.__new__(ICMPv4)
        with warnings.catch_warnings(), self.assertRaises(ProtocolError) as ctx:
            warnings.simplefilter('ignore')
            proto.make(type=8, code=0, checksum=b'\x00\x00', body=b'\x01')
        self.assertEqual(str(ctx.exception),
                         'ICMP: [TypeNo 8] message body 01 does not parse as this type')
        with warnings.catch_warnings(), self.assertRaises(ProtocolError) as ctx:
            warnings.simplefilter('ignore')
            proto.make(type=8, code=0, checksum=b'\x00\x00', body=12345)  # type: ignore[arg-type]
        self.assertEqual(str(ctx.exception), "ICMP: invalid message body type: <class 'int'>")


if __name__ == '__main__':
    unittest.main()
