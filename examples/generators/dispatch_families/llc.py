# -*- coding: utf-8 -*-
"""The ``llc`` family: ``LLC.__proto__``, keyed by DSAP (#2936, #3115).

A family module of :file:`examples/generators/dispatch.py`, which loads it by
path and binds ``generator`` to itself before this body runs (#2615). Each
case is a UI PDU in an 802.3 frame, whose Length/Type field is its length.

"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Any

#: :file:`examples/generators/dispatch.py`, which its loader binds here
#: before this body runs.
generator = globals()['generator']  # type: Any


def _registry() -> 'Any':
    from pcapkit.protocols.link.llc.protocol import LLC
    return LLC.__proto__


def _build(code: 'Any') -> 'Any':
    from pcapkit.const.llc.lsap import LSAP
    from pcapkit.protocols.link.llc.protocol import LLC
    from pcapkit.protocols.link.snap.protocol import SNAP

    if code == LSAP.SNAP:
        payload = bytes(SNAP.from_fields(oui=0, pid=0x0800, payload=generator._ip4(6, generator._tcp(9999))))
    elif code == LSAP.Bridge_Spanning_Tree_Protocol:
        from pcapkit.protocols.application.stp.protocol import STP
        payload = bytes(STP.from_fields(version=0))
    else:  # pragma: no cover
        raise LookupError(f'llc: no payload builder for {code!r}')
    pdu = bytes(LLC.from_fields(dsap=code, ssap=code, payload=payload))
    frame = generator._ethernet(len(pdu), pdu)
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('llc', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'llc/Bridge_Spanning_Tree_Protocol': ('pcapkit.protocols.application.stp.protocol', 'STP'),
    'llc/SNAP': ('pcapkit.protocols.link.snap.protocol', 'SNAP'),
}
