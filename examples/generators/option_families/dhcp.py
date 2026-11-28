# -*- coding: utf-8 -*-
"""The ``dhcp-option`` family: BOOTP and DHCP options (#2959).

Each case is one option in a DHCPDISCOVER, after its DHCP Message Type option,
built by its ``_make_opt_*`` from keyword arguments; the Option Overload case
overloads the ``file`` field with an End option. No capture is written: the
``udp`` envelope's port does not dispatch to DHCP.

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

#: The arguments each decoder's options are built with, by the name
#: ``DHCP.__option__`` maps their codes to.
_ARGUMENTS = {
    'address': {'address': '192.0.2.1'},
    'time_offset': {'value': -18000},
    'addresses': {'addresses': ('192.0.2.1', '192.0.2.2')},
    'text': {'text': 'example'},
    'uint16': {'value': 1500},
    'boolean': {'value': True},
    'policy_filter': {'filters': ({'address': '10.0.0.0', 'mask': '255.0.0.0'},)},
    'uint8': {'value': 64},
    'uint32': {'value': 86400},
    'mtu_plateau': {'sizes': (68, 296, 1500)},
    'static_route': {'routes': ({'destination': '10.0.0.0', 'router': '192.0.2.1'},)},
    'node_type': {'node_type': 0x8},
    'overload': {'file': True},
    'message_type': {'type': 3},
    'parameter_list': {'codes': (1, 3, 6, 15)},
    'client_id': {'type': 1, 'identifier': '00:0b:82:01:fc:42'},
    'home_agent': {'addresses': ('192.0.2.1',)},
    'user_class': {'classes': (b'office', b'lab')},
    'client_fqdn': {'flags': {'e': True, 's': True}, 'name': 'host.example.com.'},
    'relay_agent': {'suboptions': ({'code': 1, 'data': b'eth0'}, {'code': 2, 'data': b'relay'})},
    'client_system': {'types': (7,)},
    'client_ndi': {'type': 1, 'major': 3, 'minor': 10},
    'machine_id': {'type': 0, 'identifier': bytes(range(16))},
    'domain_search': {'names': ('example.com', 'sub.example.com')},
    'classless_route': {'routes': ({'destination': '10.0.0.0/8', 'router': '192.0.2.1'},
                                   {'destination': '0.0.0.0/0', 'router': '192.0.2.254'})},
    'vendor_class': {'vendors': ({'enterprise': 4491, 'classes': (b'docsis3.0',)},)},
    'vendor_specific': {'vendors': ({'enterprise': 4491, 'options': ({'code': 1, 'data': b'\x01'},)},)},
}  # type: dict[str, dict[str, Any]]


def _dhcp_option_registry() -> 'Any':
    from pcapkit.protocols.application.dhcp.protocol import DHCP
    return DHCP.__option__


def _dhcp_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.protocols.application.dhcp.protocol import DHCP
    return {code: dict(_ARGUMENTS[meth]) for code, meth in DHCP.__option__.items() if isinstance(meth, str)}


def _dhcp_option_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.const.dhcp.option import Option as Enum_Option

    if code == Enum_Option.DHCP_Msg_Type:
        return _dhcp_message(({'code': code, 'data': dict(kwargs)}, {'code': Enum_Option.End}))
    return _dhcp_message(({'code': Enum_Option.DHCP_Msg_Type, 'data': {'type': 1}},
                          {'code': code, 'data': dict(kwargs)}, {'code': Enum_Option.End}))


def _dhcp_message(options: 'Any') -> 'Any':
    """A DHCPDISCOVER carrying ``options``, its ``file`` overloaded where they say so."""
    from pcapkit.const.dhcp.option import Option as Enum_Option
    from pcapkit.protocols.application.dhcpv4.protocol import DHCPv4

    overloaded = any(option['code'] == Enum_Option.Overload for option in options)
    file = {'options': ({'code': Enum_Option.End},), 'padding': b''} if overloaded else b''
    return DHCPv4.from_fields(xid=0x3D1D, chaddr='00:0b:82:01:fc:42', file=file, options=options)


def _dhcp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.dhcp.protocol import DHCP
    return DHCP(octets, len(octets))


def _dhcp_option_extract(parsed: 'Any') -> 'Any':
    return parsed.info.options


#: The families this module adds.
FAMILIES = (
    # No capture -- see the comment at the top of this module.
    generator.Family('dhcp-option', _dhcp_option_registry, _dhcp_option_overrides,
                     _dhcp_option_build, _dhcp_parse, _dhcp_option_extract,
                     _dhcp_message, capture=None, envelope=None),
)
