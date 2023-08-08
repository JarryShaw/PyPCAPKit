# -*- coding: utf-8 -*-
"""data models for root protocol"""

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

__all__ = [
    'Packet',
]


@info_final
class Packet(Data):
    """Header and payload data."""

    #: packet header
    header: 'bytes'
    #: packet payload
    payload: 'bytes'
