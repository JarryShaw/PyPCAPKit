# -*- coding: utf-8 -*-
"""The ``icmpv4-type`` and ``icmpv6-type`` families: ICMP and ICMPv6 message types.

A family module of :file:`examples/generators/options.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
# Deferring these is the design, as in options.py -- see its module docstring.
# pylint: disable=import-outside-toplevel

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/options.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any

#: The invoking packet an ICMP error message quotes: an IPv4 header and the
#: first eight octets of its UDP datagram [:rfc:`792`].
ICMPV4_QUOTED = (bytes.fromhex('4500001c00010000401100000a0000010a000002')
                 + bytes.fromhex('3039003500080000'))

#: The invoking packet an ICMPv6 error message quotes: an IPv6 header and its
#: UDP header [:rfc:`4443#section-3`].
ICMPV6_QUOTED = (bytes.fromhex('6000000000081140') + bytes(15) + b'\x01' + bytes(15) + b'\x02'
                 + bytes.fromhex('3039003500080000'))

#: Echo arguments shared by both versions. The defaults are all zero and empty,
#: which cannot tell a swapped ``id`` and ``seq``, or a dropped ``data``, apart.
ICMP_ECHO = {'id': 0x1234, 'seq': 0x5678, 'data': b'ping'}


def _icmpv4_registry() -> 'Any':
    from pcapkit.protocols.internet.icmpv4 import ICMPv4
    return ICMPv4.__type__


def _icmpv4_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.icmp.type import Type as Enum_Type
    return {
        Enum_Type.Echo_Reply: dict(ICMP_ECHO),
        Enum_Type.Echo: dict(ICMP_ECHO),
        Enum_Type.Destination_Unreachable: {'data': ICMPV4_QUOTED},
        Enum_Type.Time_Exceeded: {'data': ICMPV4_QUOTED},
        # Octet 8 of the quoted header is its TTL.
        Enum_Type.Parameter_Problem: {'pointer': 8, 'data': ICMPV4_QUOTED},
    }


def _icmpv4_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.icmpv4 import ICMPv4

    # ``body`` has to be a mapping for ``make`` to dispatch on ``__type__``;
    # a ``bytes`` body is parsed against the schema registry instead.
    return ICMPv4(type=code, code=0, body=dict(kwargs))


def _icmpv4_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.icmpv4 import ICMPv4
    return ICMPv4(octets, len(octets))


def _icmp_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _icmpv4_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.icmpv4 import ICMPv4
    return ICMPv4(type=message.type, code=message.code, checksum=message.checksum,
                  body=message)


def _icmpv6_registry() -> 'Any':
    from pcapkit.protocols.internet.icmpv6 import ICMPv6
    return ICMPv6.__type__


def _icmpv6_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.icmpv6.type import Type as Enum_Type
    return {
        Enum_Type.Destination_Unreachable: {'data': ICMPV6_QUOTED},
        # The IPv6 minimum link MTU [RFC 8200 section 5].
        Enum_Type.Packet_Too_Big: {'mtu': 1280, 'data': ICMPV6_QUOTED},
        Enum_Type.Time_Exceeded: {'data': ICMPV6_QUOTED},
        # Octet 6 of the quoted header is its Next Header.
        Enum_Type.Parameter_Problem: {'pointer': 6, 'data': ICMPV6_QUOTED},
        Enum_Type.Echo_Request: dict(ICMP_ECHO),
        Enum_Type.Echo_Reply: dict(ICMP_ECHO),
    }


def _icmpv6_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.icmpv6 import ICMPv6

    # With no enclosing IPv6 layer to supply the pseudo-header, the checksum is
    # left zero, and the rebuild passes the parsed zero back.
    return ICMPv6(type=code, code=0, body=dict(kwargs))


def _icmpv6_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.icmpv6 import ICMPv6
    return ICMPv6(octets, len(octets))


def _icmpv6_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.icmpv6 import ICMPv6
    return ICMPv6(type=message.type, code=message.code, checksum=message.checksum,
                  body=message)


#: The families this module adds.
FAMILIES = (
    # NOTE: The ICMP families write no capture; their wire form is pinned against
    # RFC 792 and RFC 4443 by test_option_generator_icmp_2560_unit instead.
    generator.Family('icmpv4-type', _icmpv4_registry, _icmpv4_overrides,
                     _icmpv4_build, _icmpv4_parse, _icmp_extract, _icmpv4_rebuild,
                     capture=None, envelope=None),
    generator.Family('icmpv6-type', _icmpv6_registry, _icmpv6_overrides,
                     _icmpv6_build, _icmpv6_parse, _icmp_extract, _icmpv6_rebuild,
                     capture=None, envelope=None),
)
