# -*- coding: utf-8 -*-
# pylint: disable=unused-wildcard-import
"""Auxiliary Protocols
=========================

.. module:: pcapkit.protocols.misc

:mod:`pcapkit.protocols.misc` contains the auxiliary protocol implementations.
Such includes the :class:`~pcapkit.protocols.misc.raw.Raw` class for not-supported
protocols, the :class:`~pcapkit.protocols.misc.null.NoPayload` class for
indication of empty payload, and PCAP header classes.

"""

# PCAP Headers
from pcapkit.protocols.misc.pcap import *

# PCAPNG Format
from pcapkit.protocols.misc.pcapng import *

# Miscellaneous Classes for Protocols
from pcapkit.protocols.misc.raw import Raw
from pcapkit.protocols.misc.null import NoPayload

__all__ = [
    # PCAP Headers
    'Header', 'Frame',

    # PCAPNG Format
    'PCAPNG',

    # No Payload
    'NoPayload',

    # Raw Packet
    'Raw',
]
