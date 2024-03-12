# -*- coding: utf-8 -*-
"""data models for root protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

__all__ = [
    'Packet',
]


class Protocol(Data):
    """Root protocol."""

    if TYPE_CHECKING:
        #: Packet payload.
        packet: 'bytes'


@info_final
class Packet(Data):
    """Header and payload data."""

    #: packet header
    header: 'bytes'
    #: packet payload
    payload: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, header: 'bytes', payload: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
