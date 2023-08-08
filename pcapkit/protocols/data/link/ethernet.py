# -*- coding: utf-8 -*-
"""data models for ethernet protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from pcapkit.const.reg.ethertype import EtherType

__all__ = ['Ethernet']


@info_final
class Ethernet(Data):
    """Data model for ethernet packet."""

    #: Destination MAC address.
    dst: 'str'
    #: Source MAC address.
    src: 'str'
    #: Protocol (internet layer).
    type: 'EtherType'
