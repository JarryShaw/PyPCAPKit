# -*- coding: utf-8 -*-
"""The ``ppp-control`` family: the control packets PPP reads at header level (#2817).

Each case is one protocol number of ``PPP.__control__``, built as a PPP frame
carrying one control packet of that protocol, then rebuilt from the control
packet its parse read. No capture is written.

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


def _ppp_control_registry() -> 'Any':
    from pcapkit.protocols.link.ppp.protocol import PPP
    return PPP.__control__


def _ppp_control_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ppp.protocol import Protocol as Enum_Protocol

    # A Configure-Request with Maximum-Receive-Unit 1500 (RFC 1661 Section 6.1),
    # an IP-Address of 10.0.0.1 (RFC 1332 Section 3.3), an Interface-Identifier
    # (RFC 5072 Section 4.1), an Authenticate-Request (RFC 1334 Section 2.2.1)
    # and a Challenge (RFC 1994 Section 4.1).
    return {
        Enum_Protocol.Link_Control_Protocol: {'code': 1, 'identifier': 1, 'data': bytes.fromhex('010405dc')},
        Enum_Protocol.Internet_Protocol_Control_Protocol: {'code': 1, 'identifier': 2,
                                                           'data': bytes.fromhex('03060a000001')},
        Enum_Protocol.IPv6_Control_Protocol: {'code': 1, 'identifier': 3,
                                              'data': bytes.fromhex('010a0011223344556677')},
        Enum_Protocol.Password_Authentication_Protocol: {'code': 1, 'identifier': 4,
                                                         'data': bytes.fromhex('01750170')},
        Enum_Protocol.Challenge_Handshake_Authentication_Protocol: {'code': 1, 'identifier': 5,
                                                                    'data': bytes.fromhex('0401020304')},
    }


def _ppp_control_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.link.ppp.protocol import PPP
    return PPP.build(protocol=code, control_packet=dict(kwargs))


def _ppp_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.link.ppp.protocol import PPP
    return PPP(octets, len(octets))


def _ppp_control_extract(parsed: 'Any') -> 'Any':
    return parsed.info.protocol, parsed.info.control_packet


def _ppp_control_rebuild(collection: 'Any') -> 'Any':
    from pcapkit.protocols.link.ppp.protocol import PPP

    protocol, packet = collection
    return PPP.build(protocol=protocol, control_packet=packet)


#: The families this module adds.
FAMILIES = (
    # No capture -- see the module docstring.
    generator.Family('ppp-control', _ppp_control_registry, _ppp_control_overrides,
                     _ppp_control_build, _ppp_parse, _ppp_control_extract,
                     _ppp_control_rebuild, capture=None, envelope=None),
)
