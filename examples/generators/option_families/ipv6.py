# -*- coding: utf-8 -*-
"""The ``hopopt-option``, ``ipv6-opts-option`` and ``ipv6-route-type`` families: the
IPv6 extension headers HOPOPT, IPv6-Opts and IPv6-Route.

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


def _hopopt_registry() -> 'Any':
    from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
    return HOPOPT.__option__


def _ipv6_opts_registry() -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
    return IPv6_Opts.__option__


def _ipv6_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv6.option import Option as Enum_Option

    # HOPOPT and IPv6-Opts key on the same enumeration and behave identically
    # on every code, so one table serves both; ``_hopopt_overrides`` adds the
    # one value that matters only in a Hop-by-Hop Options header.
    return {
        # The nonce is sized to its bit length rounded up to whole octets, at
        # least one, so the default ``nonce=0`` is a one-octet zero. A
        # three-octet value exercises a multi-octet width; every width from 1
        # to 16 octets builds and round-trips.
        Enum_Option.ILNP_Nonce: {'nonce': 0xFFFFFF},
        Enum_Option.Line_Identification_Option: {'id': b'line-1'},
    }


def _hopopt_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv6.option import Option as Enum_Option

    # A Jumbo Payload option in the Hop-by-Hop Options header after an IPv6
    # header makes the packet a jumbogram, and one whose Jumbo Payload Length is
    # not above 65,535 is an error (RFC 2675 section 3) the default engine
    # rejects (#1687). So the option carries a legal length, and options.py's
    # ``_frame`` builds the jumbogram around it. In IPv6-Opts the option is just
    # an option.
    return {**_ipv6_option_overrides(), Enum_Option.Jumbo_Payload: {'len': generator.JUMBO_LEN}}


def _hopopt_base() -> 'dict[str, Any]':
    from pcapkit.const.reg.transtype import TransType
    return {'next': TransType.UDP, 'payload': b''}


def _hopopt_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
    return HOPOPT(options=[(code, kwargs)], **_hopopt_base())


def _hopopt_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
    return HOPOPT(octets, len(octets), extension=True)


def _ipv6_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _hopopt_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.hopopt.protocol import HOPOPT
    return HOPOPT(options=options, **_hopopt_base())


def _ipv6_opts_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
    return IPv6_Opts(options=[(code, kwargs)], **_hopopt_base())


def _ipv6_opts_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
    return IPv6_Opts(octets, len(octets), extension=True)


def _ipv6_opts_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv6_opts.protocol import IPv6_Opts
    return IPv6_Opts(options=options, **_hopopt_base())


def _ipv6_route_registry() -> 'Any':
    from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
    return IPv6_Route.__routing__


def _ipv6_route_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv6.routing import Routing as Enum_Routing
    return {
        Enum_Routing.Source_Route: {'ip': ['2001:db8::1', '2001:db8::2']},
        Enum_Routing.Type_2_Routing_Header: {'ip': '2001:db8::2'},
        Enum_Routing.RPL_Source_Route_Header: {'ip': ['2001:db8::1', '2001:db8::2']},
    }


def _ipv6_route_base() -> 'dict[str, Any]':
    from pcapkit.const.reg.transtype import TransType
    return {'next': TransType.UDP, 'seg_left': 0, 'payload': b''}


def _ipv6_route_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
    return IPv6_Route(type=code, data=dict(kwargs), **_ipv6_route_base())


def _ipv6_route_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
    return IPv6_Route(octets, len(octets), extension=True)


def _ipv6_route_extract(parsed: 'Any') -> 'Any':
    # A routing header carries one routing type, not a collection of them, so
    # the "collection" handed on is the message itself.
    return parsed.info


def _ipv6_route_rebuild(info: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv6_route.protocol import IPv6_Route
    return IPv6_Route(type=info.type, data=info, next=info.next,
                      seg_left=info.seg_left, payload=b'')


#: The families this module adds.
FAMILIES = (
    generator.Family('hopopt-option', _hopopt_registry, _hopopt_overrides,
                     _hopopt_build, _hopopt_parse, _ipv6_extract, _hopopt_rebuild,
                     capture='options-ipv6.pcap', envelope='ipv6', proto=0),
    generator.Family('ipv6-opts-option', _ipv6_opts_registry, _ipv6_option_overrides,
                     _ipv6_opts_build, _ipv6_opts_parse, _ipv6_extract, _ipv6_opts_rebuild,
                     capture='options-ipv6.pcap', envelope='ipv6', proto=60),
    generator.Family('ipv6-route-type', _ipv6_route_registry, _ipv6_route_overrides,
                     _ipv6_route_build, _ipv6_route_parse, _ipv6_route_extract,
                     _ipv6_route_rebuild,
                     capture='options-ipv6.pcap', envelope='ipv6', proto=43),
)

#: Codes of :data:`FAMILIES` left out of the case list, with the reason; see
#: :data:`examples.generators.options.SKIP`.
#:
#: Every padding option has a case except PadN in HOPOPT and IPv6-Opts. Their
#: ``_make_*_options`` keep the padding of parsed options in place, but drop
#: any in a list of fresh options and insert their own to reach 8-octet
#: alignment. A case is built from such a list, so the Pad1 and PadN cases
#: would both emit the same option-less header; Pad1 is kept, PadN skipped.
SKIP = {
    ('hopopt-option', 'PadN'): 'padding, indistinguishable from Pad1 here',
    ('ipv6-opts-option', 'PadN'): 'padding, indistinguishable from Pad1 here',
}
