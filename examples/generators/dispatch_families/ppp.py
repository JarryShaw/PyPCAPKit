# -*- coding: utf-8 -*-
"""The ``ppp`` family: ``PPP.__proto__``, keyed by PPP protocol number (#2817).

A family module of :file:`examples/generators/dispatch.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615).

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _registry() -> 'Any':
    from pcapkit.protocols.link.ppp.protocol import PPP
    return PPP.__proto__


def _build(code: 'Any') -> 'Any':
    from pcapkit.const.ppp.protocol import Protocol

    _ip4, _ip6, _tcp = generator._ip4, generator._ip6, generator._tcp
    if code == Protocol.Internet_Protocol_version_4:
        payload = _ip4(6, _tcp(9999))
    elif code == Protocol.Internet_Protocol_version_6:
        payload = _ip6(6, _tcp(9999))
    else:  # pragma: no cover
        raise LookupError(f'ppp: no payload builder for {code!r}')
    frame = generator._ppp(payload, protocol=int(code))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=9), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('ppp', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'ppp/Internet_Protocol_version_4': ('pcapkit.protocols.internet.ipv4.protocol', 'IPv4'),
    'ppp/Internet_Protocol_version_6': ('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
}
