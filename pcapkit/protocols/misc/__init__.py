# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Auxiliary Protocols
=========================

.. module:: pcapkit.protocols.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
These include the :class:`~pcapkit.protocols.misc.raw.protocol.Raw` class for not-supported
protocols, the :class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload` class for
indication of empty payload, the PCAP and PCAP-NG file format classes, and the
checksum pseudo-headers in :mod:`pcapkit.protocols.misc.checksum`.

Each class is imported the first time it is reached rather than with this
package, through :func:`~pcapkit.utilities.importlib.lazy_exports` (:issue:`2730`).

"""
from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    # PCAP Headers
    from pcapkit.protocols.misc.pcap import Frame, Header

    # PCAPNG Format
    from pcapkit.protocols.misc.pcapng import PCAPNG

    # Miscellaneous Classes for Protocols
    from pcapkit.protocols.misc.raw import Raw
    from pcapkit.protocols.misc.no_payload import NoPayload

    # Checksum Pseudo-Headers
    from pcapkit.protocols.misc.checksum import IP_Pseudo

__all__ = [
    # PCAP Headers
    'Header', 'Frame',

    # PCAPNG Format
    'PCAPNG',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',

    # Checksum Pseudo-Headers
    'IP_Pseudo',
]

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'Header': ('pcap', 'Header'),
    'Frame': ('pcap', 'Frame'),
    'PCAPNG': ('pcapng', 'PCAPNG'),
    'NoPayload': ('no_payload', 'NoPayload'),
    'Raw': ('raw', 'Raw'),
    'IP_Pseudo': ('checksum', 'IP_Pseudo'),
})
