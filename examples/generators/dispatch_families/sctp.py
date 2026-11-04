# -*- coding: utf-8 -*-
"""The ``sctp`` family: ``SCTP.__proto__``, keyed by payload protocol identifier (#496).

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
    from pcapkit.protocols.transport.sctp.protocol import SCTP
    return SCTP.__proto__


def _build(ppid: 'Any') -> 'Any':
    from pcapkit.const.sctp.chunk import Chunk
    from pcapkit.protocols.transport.sctp.protocol import SCTP

    sctp = bytes(SCTP(srcport=50000, dstport=80, vtag=0x11223344, chksum=b'\x00' * 4,
                      chunks=[(Chunk.Payload_Data, {'ppid': ppid, 'data': b'ngap-pdu'})]))
    frame = generator._ethernet(0x0800, generator._ip4(132, sctp))
    return generator._extract_first(generator._pcap_bytes((frame,), linktype=1), '.pcap')


#: The families this module adds.
FAMILIES = (
    generator.Family('sctp', _registry, _build),
)

#: The class each case of :data:`FAMILIES` is pinned to, as
#: :data:`examples.generators.dispatch.PINNED_TARGETS` describes.
PINNED_TARGETS = {
    'sctp/PayloadProtocolIdentifier_3GPP_NG_Application_Protocol':
        ('pcapkit.protocols.application.ngap.protocol', 'NGAP'),
    'sctp/PayloadProtocolIdentifier_3GPP_NGAP_over_DTLS_over_SCTP':
        ('pcapkit.protocols.application.ngap.protocol', 'NGAP'),
}
