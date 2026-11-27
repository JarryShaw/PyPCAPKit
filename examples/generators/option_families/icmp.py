# -*- coding: utf-8 -*-
"""The ``icmpv4-type``, ``icmpv6-type`` and ``icmpv6-nd-option`` families.

ICMP and ICMPv6 message types, and the Neighbor Discovery options of ICMPv6.

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

#: The multicast address an MLD message names, the all-MLDv2-routers group, and
#: a source address [:rfc:`9777#section-5`].
MLD_GROUP = 'ff02::16'
MLD_SOURCE = '2001:db8::1'

#: An MLDv1 Report or Done [:rfc:`2710#section-3`], whose defaults are all zero.
MLDV1 = {'max_resp_delay': 0x1234, 'multicast_address': MLD_GROUP}

#: A Source Link-layer Address option, on Ethernet [:rfc:`4861#section-4.6.1`].
ND_SLLA = (1, {'link_layer_address': bytes.fromhex('001122334455')})
#: A neighbor's address and a destination redirected [:rfc:`4861#section-4.5`].
ND_TARGET = 'fe80::1'
ND_DESTINATION = '2001:db8::1'


def _icmpv4_registry() -> 'Any':
    from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
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
    from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4

    # ``body`` has to be a mapping for ``make`` to dispatch on ``__type__``;
    # a ``bytes`` body is parsed against the schema registry instead.
    return ICMPv4.from_fields(type=code, code=0, body=dict(kwargs))


def _icmpv4_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
    return ICMPv4(octets, len(octets))


def _icmp_extract(parsed: 'Any') -> 'Any':
    return parsed.info


def _icmpv4_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.icmpv4.protocol import ICMPv4
    return ICMPv4.from_fields(type=message.type, code=message.code, checksum=message.checksum,
                              body=message)


def _icmpv6_registry() -> 'Any':
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
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
        # An MLDv2 Query, which an MLDv1 one is the first 24 octets of; no field
        # picks the version type 130 is shared by.
        Enum_Type.Multicast_Listener_Query: {
            'version': 2, 'max_resp_code': 0x8123, 'multicast_address': MLD_GROUP,
            'flags': 0x5, 's_flag': True, 'qrv': 2, 'qqic': 0x7D, 'sources': [MLD_SOURCE],
        },
        Enum_Type.Multicast_Listener_Report: dict(MLDV1),
        Enum_Type.Multicast_Listener_Done: dict(MLDV1),
        Enum_Type.Version_2_Multicast_Listener_Report: {'flags': 0x8000, 'records': [{
            'record_type': 4, 'multicast_address': MLD_GROUP, 'sources': [MLD_SOURCE], 'aux_data': b'AUX!',
        }]},
        # Neighbor Discovery [RFC 4861 section 4], whose defaults are all zero.
        Enum_Type.Router_Solicitation: {'options': [ND_SLLA]},
        Enum_Type.Router_Advertisement: {
            'cur_hop_limit': 64, 'm_flag': True, 'prf': 1, 'router_lifetime': 1800,
            'reachable_time': 30000, 'retrans_timer': 1000, 'options': [ND_SLLA],
        },
        Enum_Type.Neighbor_Solicitation: {'target_address': ND_TARGET, 'options': [ND_SLLA]},
        Enum_Type.Neighbor_Advertisement: {'r_flag': True, 's_flag': True, 'target_address': ND_TARGET,
                                           'options': [(2, ND_SLLA[1])]},
        Enum_Type.Redirect_Message: {'target_address': ND_TARGET, 'destination_address': ND_DESTINATION,
                                     'options': [(4, {'data': ICMPV6_QUOTED})]},
    }


def _icmpv6_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6

    # With no enclosing IPv6 layer to supply the pseudo-header, the checksum is
    # left zero, and the rebuild passes the parsed zero back.
    return ICMPv6.from_fields(type=code, code=0, body=dict(kwargs))


def _icmpv6_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
    return ICMPv6(octets, len(octets))


def _icmpv6_rebuild(message: 'Any') -> 'Any':
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
    return ICMPv6.from_fields(type=message.type, code=message.code, checksum=message.checksum,
                              body=message)


def _nd_option_registry() -> 'Any':
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
    return ICMPv6.__option__


def _nd_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.icmpv6.nd_option import NDOption as Enum_NDOption
    return {
        Enum_NDOption.Source_Link_layer_Address: dict(ND_SLLA[1]),
        Enum_NDOption.Target_Link_layer_Address: dict(ND_SLLA[1]),
        Enum_NDOption.Prefix_Information: {'prefix_length': 64, 'l_flag': True, 'a_flag': True,
                                           'valid_lifetime': 2592000, 'preferred_lifetime': 604800,
                                           'prefix': '2001:db8:1::'},
        Enum_NDOption.Redirected_Header: {'data': ICMPV6_QUOTED},
        Enum_NDOption.MTU: {'mtu': 1500},
        Enum_NDOption.Advertisement_Interval_Option: {'interval': 600000},
        Enum_NDOption.Home_Agent_Information_Option: {'preference': 10, 'lifetime': 1800},
        Enum_NDOption.Nonce_option: {'nonce': bytes(range(1, 7))},
        Enum_NDOption.Route_Information_Option: {'prefix_length': 48, 'prf': 1, 'lifetime': 3600,
                                                 'prefix': '2001:db8:2::'},
        Enum_NDOption.Recursive_DNS_Server_Option: {'lifetime': 3600,
                                                    'addresses': ['2001:db8::53', '2001:db8::35']},
        # Bit 55, the last of IANA's Private Experimentation bits [RFC 5175 section 5].
        Enum_NDOption.RA_Flags_Extension_Option: {'bits': bytes.fromhex('000000000001')},
        Enum_NDOption.DNS_Search_List_Option: {'lifetime': 3600, 'domain_names': ['example.com', 'example.net']},
        Enum_NDOption.DHCP_Captive_Portal: {'uri': b'https://portal.example/api'},
        Enum_NDOption.PREF64_option: {'lifetime': 1800, 'prefix_length': 64, 'prefix': '2001:db8:64::'},
    }


def _nd_option_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _nd_option_message([(code, dict(kwargs))])


def _nd_option_message(options: 'Any') -> 'Any':
    """A Router Advertisement carrying ``options``, the message most of them go in."""
    from pcapkit.const.icmpv6.type import Type as Enum_Type
    from pcapkit.protocols.internet.icmpv6.protocol import ICMPv6
    return ICMPv6.from_fields(type=Enum_Type.Router_Advertisement, code=0,
                              body={'cur_hop_limit': 64, 'options': options})


def _nd_option_extract(parsed: 'Any') -> 'Any':
    return parsed.info.options


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
    generator.Family('icmpv6-nd-option', _nd_option_registry, _nd_option_overrides,
                     _nd_option_build, _icmpv6_parse, _nd_option_extract, _nd_option_message,
                     capture=None, envelope=None),
)
