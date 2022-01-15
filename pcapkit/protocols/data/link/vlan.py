# -*- coding: utf-8 -*-
"""data models for 802.1Q customer VLAN tag type"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from pcapkit.const.reg.ethertype import EtherType
    from pcapkit.const.vlan.priority_level import PriorityLevel

__all__ = ['VLAN', 'TCI']


class TCI(Info):
    """Data model for tag control information."""

    #: Priority code point.
    pcp: 'PriorityLevel'
    #: Drop eligible indicator.
    dei: 'bool'
    #: VLAN identifier.
    vid: 'int'

    if TYPE_CHECKING:
        def __init__(self, pcp: 'PriorityLevel', dei: 'bool', vid: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements


class VLAN(Info):
    """Data model for 802.1Q customer VLAN tag type."""

    #: Tag control information.
    tci: 'TCI'
    #: Protocol (Internet Layer).
    type: 'EtherType'

    if TYPE_CHECKING:
        def __init__(self, tci: 'TCI', type: 'EtherType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
