# -*- coding: utf-8 -*-
"""The ``radiotap`` family: ``Radiotap.__proto__``, keyed by the link type behind it (#2575).

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
    from pcapkit.protocols.link.radiotap import Radiotap
    return Radiotap.__proto__


def _build(code: 'Any') -> 'Any':
    """An 802.11 Ack behind radiotap, on a ``LINUX_SLL`` capture.

    :meth:`Radiotap.read <pcapkit.protocols.link.radiotap.Radiotap.read>`
    consults ``LinkType.IEEE802_11`` alone, so that is the only code with a
    case.

    """
    from pcapkit.const.linux.arphrd import ARPHRD
    from pcapkit.const.reg.linktype import LinkType
    from pcapkit.protocols.link.ieee802_11 import IEEE802_11
    from pcapkit.protocols.link.linux_sll1 import LinuxSLL1
    from pcapkit.protocols.link.radiotap import Radiotap

    if code != LinkType.IEEE802_11:
        raise ValueError(f'no radiotap case for link type {code!r}')
    ack = bytes(IEEE802_11(type='Control', subtype='ACK', addr1='02:00:00:00:00:01'))
    frame = bytes(LinuxSLL1(arphrd_type=ARPHRD.IEEE80211_RADIOTAP, payload=bytes(Radiotap(payload=ack))))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=int(LinkType.LINUX_SLL)),
                                    '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('radiotap', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'radiotap/IEEE802_11': ('pcapkit.protocols.link.ieee802_11', 'IEEE802_11'),
}
