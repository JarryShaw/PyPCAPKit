# -*- coding: utf-8 -*-
"""The ``dns-rdata`` and ``dns-option`` families: DNS RDATA and EDNS(0) options.

Each ``dns-rdata`` case is one answer record of its type, built from keyword
arguments by the type's ``_make_rdata_*``; each ``dns-option`` case is one
option in an OPT pseudo-record, built by its ``_make_opt_*``. No capture is
written: the ``udp`` envelope's port does not dispatch to DNS.

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


def _dns_rdata_registry() -> 'Any':
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS.__rdata__


def _dns_rdata_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.dns.rr_type import RRType as Enum_RRType
    return {
        Enum_RRType.A: {'address': '192.0.2.1'},
        Enum_RRType.NS: {'nsdname': 'ns1.example.com'},
        Enum_RRType.CNAME: {'cname': 'www.example.com'},
        Enum_RRType.SOA: {'mname': 'ns1.example.com', 'rname': 'hostmaster.example.com',
                          'serial': 2026112101, 'refresh': 7200, 'retry': 3600,
                          'expire': 1209600, 'minimum': 300},
        Enum_RRType.PTR: {'ptrdname': 'host.example.com'},
        Enum_RRType.MX: {'preference': 10, 'exchange': 'mail.example.com'},
        Enum_RRType.TXT: {'strings': (b'v=spf1 -all', b'')},
        Enum_RRType.AAAA: {'address': '2001:db8::1'},
        Enum_RRType.SRV: {'priority': 1, 'weight': 5, 'port': 5060, 'target': 'sip.example.com'},
        Enum_RRType.CAA: {'flags': 128, 'tag': b'issue', 'value': b'ca.example.net'},
    }


def _dns_rdata_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS.build(id=1, qr=True, answer=({'name': 'example.com', 'type': code, 'ttl': 300,
                                             'rdata': dict(kwargs)},), compress=True)


def _dns_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS(octets, len(octets), framed=False)


def _dns_rdata_extract(parsed: 'Any') -> 'Any':
    return parsed.info.answer


def _dns_rdata_rebuild(answer: 'Any') -> 'Any':
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS.build(id=1, qr=True, answer=answer)


def _dns_option_registry() -> 'Any':
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS.__option__


def _dns_option_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.dns.option import Option as Enum_Option
    return {
        Enum_Option.edns_client_subnet: {'family': 1, 'source_prefix': 24, 'scope_prefix': 0,
                                         'address': bytes((198, 51, 100))},
        Enum_Option.COOKIE: {'client': bytes(range(8)), 'server': bytes(range(8, 24))},
        Enum_Option.edns_tcp_keepalive: {'timeout': 600},
        Enum_Option.Extended_DNS_Error: {'info_code': 18, 'extra_text': b'prohibited'},
    }


def _dns_option_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    return _dns_opt_message(({'code': code, 'data': dict(kwargs)},))


def _dns_opt_message(options: 'Any') -> 'Any':
    """A query carrying one OPT pseudo-record with ``options``."""
    from pcapkit.const.dns.rr_type import RRType as Enum_RRType
    from pcapkit.protocols.application.dns.protocol import DNS
    return DNS.build(id=1, question=({'name': 'example.com'},),
                     additional=({'type': Enum_RRType.OPT, 'udp_payload_size': 1232, 'do': True,
                                  'options': options},))


def _dns_option_extract(parsed: 'Any') -> 'Any':
    return parsed.info.additional[0].options


#: The families this module adds.
FAMILIES = (
    # No capture -- see the comment at the top of this module.
    generator.Family('dns-rdata', _dns_rdata_registry, _dns_rdata_overrides,
                     _dns_rdata_build, _dns_parse, _dns_rdata_extract,
                     _dns_rdata_rebuild, capture=None, envelope=None),
    generator.Family('dns-option', _dns_option_registry, _dns_option_overrides,
                     _dns_option_build, _dns_parse, _dns_option_extract,
                     _dns_opt_message, capture=None, envelope=None),
)
