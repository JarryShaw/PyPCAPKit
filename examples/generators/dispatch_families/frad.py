# -*- coding: utf-8 -*-
"""The ``frad`` family: ``FRAD.__proto__``, keyed by NLPID (#2560).

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
    from pcapkit.protocols.link.frad.protocol import FRAD
    return FRAD.__proto__


def _payload(nlpid: 'int') -> 'bytes':
    """The registered target's own wire bytes for ``nlpid``."""
    if nlpid == 0xCC:
        return generator._ip4(6, generator._tcp(9999))
    if nlpid == 0x8E:
        return generator._ip6(6, generator._tcp(9999))
    raise LookupError(f'frad: no payload builder for NLPID {nlpid!r}')  # pragma: no cover


def _build(nlpid: 'int') -> 'Any':
    """A direct-NLPID FRAD frame, reached as LinuxSLL dispatches it in a capture."""
    from pcapkit.const.linux.arphrd import ARPHRD
    from pcapkit.protocols.link.frad.protocol import FRAD
    from pcapkit.protocols.link.linux_sll1.protocol import LinuxSLL1

    frad = bytes(FRAD(nlpid=int(nlpid), payload=_payload(nlpid)))
    record = bytes(LinuxSLL1(arphrd_type=ARPHRD.FRAD, protocol_type=0, payload=frad))
    return generator._extract_first(generator._pcap_bytes((record,), linktype=113), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('frad', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes. Keyed in
#: decimal: 0x8E, 0xCC.
PINNED_TARGETS = {
    'frad/142': ('pcapkit.protocols.internet.ipv6.protocol', 'IPv6'),
    'frad/204': ('pcapkit.protocols.internet.ipv4.protocol', 'IPv4'),
}
