# -*- coding: utf-8 -*-
"""data modules for root protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

__all__ = [
    'Packet',
]


class Packet(Info):
    """Header and payload data."""

    #: packet header
    header: 'bytes'
    #: packet payload
    payload: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, header: 'bytes', payload: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
