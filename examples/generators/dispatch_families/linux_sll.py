# -*- coding: utf-8 -*-
"""The ``linux_sll`` family: ``LinuxSLL.__proto__``, keyed by ARPHRD type (#2510, #2592).

Probes the table through ``LINUX_SLL`` records, as the ``linux_sll2`` family
does through ``LINUX_SLL2`` ones. A family module of
:file:`examples/generators/dispatch.py`, which loads it by path and binds
``generator`` to itself before this body runs (#2615).

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _registry() -> 'Any':
    from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL
    return LinuxSLL.__proto__


def _build(arphrd_type: 'Any') -> 'Any':
    """A ``LINUX_SLL`` record on ``arphrd_type``, built through the family base."""
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.protocols.link.linux_sll.protocol import LinuxSLL

    protocol_type, payload = generator._linux_sll_payload(arphrd_type)
    record = bytes(LinuxSLL(version=1, arphrd_type=arphrd_type, protocol_type=protocol_type,
                            payload=payload))
    capture = generator._pcap_bytes((record,), linktype=int(LinkType.LINUX_SLL))
    return generator._extract_first(capture, '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('linux_sll', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'linux_sll/FRAD': ('pcapkit.protocols.link.frad.protocol', 'FRAD'),
    'linux_sll/IPGRE': ('pcapkit.protocols.link.gre.protocol', 'GRE'),
    'linux_sll/IEEE80211_RADIOTAP': ('pcapkit.protocols.link.radiotap.protocol', 'Radiotap'),
    'linux_sll/IP6GRE': ('pcapkit.protocols.link.gre.protocol', 'GRE'),
    'linux_sll/NETLINK': ('pcapkit.protocols.link.netlink.protocol', 'Netlink'),
}
