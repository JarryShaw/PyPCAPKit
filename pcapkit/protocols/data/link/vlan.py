# -*- coding: utf-8 -*-
"""data models for 802.1Q customer VLAN tag type"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

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

    if TYPE_CHECKING:
        def __init__(self, pcp: 'PriorityLevel', dei: 'bool', vid: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


@info_final
class VLAN(Protocol):
    """Data model for 802.1Q customer VLAN tag type."""

    #: Tag control information.
    tci: 'TCI'
    #: Protocol (Internet Layer).
    type: 'EtherType'

    if TYPE_CHECKING:
        def __init__(self, tci: 'TCI', type: 'EtherType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
