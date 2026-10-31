# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""Auxiliary Protocols
=========================

.. module:: pcapkit.protocols.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
These include the :class:`~pcapkit.protocols.misc.raw.Raw` class for not-supported
protocols, the :class:`~pcapkit.protocols.misc.null.NoPayload` class for
indication of empty payload, the PCAP and PCAP-NG file format classes, and the
checksum pseudo-headers in :mod:`pcapkit.protocols.misc.checksum`.

"""

# PCAP Headers
from pcapkit.protocols.misc.pcap import *

# PCAPNG Format
from pcapkit.protocols.misc.pcapng import *

# Miscellaneous Classes for Protocols
from pcapkit.protocols.misc.raw import Raw
from pcapkit.protocols.misc.null import NoPayload

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
