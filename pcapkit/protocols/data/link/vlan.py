# -*- coding: utf-8 -*-
"""data models for 802.1Q customer VLAN tag type"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.const.vlan.priority_level import PriorityLevel

__all__ = ['VLAN', 'TCI']


@info_final
class TCI(Data):
    """Data model for tag control information."""

    #: Priority code point.
    pcp: 'PriorityLevel'
    #: Drop eligible indicator.
    dei: 'bool'
    #: VLAN identifier.
    vid: 'int'


@info_final
class VLAN(Data):
    """Data model for 802.1Q customer VLAN tag type."""

    #: Tag control information.
    tci: 'TCI'
    #: Protocol (Internet Layer).
    type: 'EtherType'
