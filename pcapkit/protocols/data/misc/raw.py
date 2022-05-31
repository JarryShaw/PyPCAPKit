# -*- coding: utf-8 -*-
"""data modules for raw protocol data"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from typing import Optional

__all__ = ['Raw']


class Raw(Info):
    """Raw packet is an unknown protocol."""

    #: packet data
    packet: 'bytes'
    #: error instance when parsing packet data
    error: 'Optional[Exception]'

    if TYPE_CHECKING:
        def __init__(self, packet: 'bytes', error: 'Optional[Exception]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
