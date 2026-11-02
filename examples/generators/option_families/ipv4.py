# -*- coding: utf-8 -*-
"""The ``ipv4-option`` family: IPv4 options.

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

#: Header fields shared by every constructed IPv4 packet.
IPV4_BASE = {'protocol': 6, 'src': '192.0.2.1', 'dst': '198.51.100.1', 'payload': b''}


def _ipv4_registry() -> 'Any':
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.protocols.internet.ipv4 import IPv4
    return generator._named_registry(IPv4, OptionNumber, '_make_opt_', '__option__')


def _ipv4_overrides() -> 'dict[Any, dict[str, Any]]':
    from pcapkit.const.ipv4.option_number import OptionNumber
    from pcapkit.const.ipv4.protection_authority import ProtectionAuthority
    return {
        # Two authorities rather than one because two bits set in the bitmap say
        # more than one does, not because one is unrepresentable. Without
        # #537's fix, a single ``GENSER`` (value 0) makes ``_make_opt_sec`` size
        # a zero-octet bitmap and then index into it for a bare ``IndexError``.
        # So this is a coverage choice and routes around nothing.
        OptionNumber.SEC: {'authorities': [ProtectionAuthority.GENSER,
                                           ProtectionAuthority.NSA]},
        # ``counts=10``, the default, needs 43 option octets, which overflows
        # the 4-bit ``ihl``. Nine is the largest an IPv4 header can carry.
        OptionNumber.LSR: {'counts': 9},
        OptionNumber.RR: {'counts': 9},
        OptionNumber.SSR: {'counts': 9},
        # The default builds an option with no timestamp in it, which is
        # degenerate; one is recorded.
        OptionNumber.TS: {'counts': 1, 'timestamp': [1]},
        OptionNumber.E_SEC: {'info': b'\x00'},
    }


def _ipv4_build(code: 'Any', kwargs: 'dict[str, Any]') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(options=[(code, kwargs)], **IPV4_BASE)


def _ipv4_parse(octets: 'bytes') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(octets, len(octets))


def _ipv4_extract(parsed: 'Any') -> 'Any':
    from pcapkit.corekit.multidict import OrderedMultiDict

    # ``_make_ipv4_options`` drops EOOL and NOP from a fresh option list as
    # padding, so the header a case builds from either has no options at all and ``info`` carries no
    # ``options`` attribute. An empty collection is the honest reading of that,
    # and it keeps the two padding codes from being reported as parse failures.
    return getattr(parsed.info, 'options', OrderedMultiDict())


def _ipv4_rebuild(options: 'Any') -> 'Any':
    from pcapkit.protocols.internet.ipv4 import IPv4
    return IPv4(options=options, **IPV4_BASE)


#: The families this module adds.
FAMILIES = (
    generator.Family('ipv4-option', _ipv4_registry, _ipv4_overrides,
                     _ipv4_build, _ipv4_parse, _ipv4_extract, _ipv4_rebuild,
                     capture='options-ipv4.pcap', envelope='ethernet-ipv4'),
)
