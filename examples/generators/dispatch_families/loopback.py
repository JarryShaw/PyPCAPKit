# -*- coding: utf-8 -*-
"""The ``loopback`` family: ``Loopback.__proto__``, keyed by address family (#1574).

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
    from pcapkit.protocols.link.loopback.protocol import Loopback
    return Loopback.__proto__


def _build(family: 'int') -> 'Any':
    _ip4, _ip6, _tcp = generator._ip4, generator._ip6, generator._tcp
    payload = _ip4(6, _tcp(9999)) if family == 2 else _ip6(6, _tcp(9999))
    frame = generator._loopback(family, payload)
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=0), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('loopback', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'loopback/2': ('pcapkit.protocols.internet.ipv4.protocol', 'IPv4'),
    'loopback/24': ('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
    'loopback/28': ('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
    'loopback/30': ('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
}
