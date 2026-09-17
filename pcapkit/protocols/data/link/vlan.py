# -*- coding: utf-8 -*-
"""data models for 802.1Q/802.1ad VLAN tag types

The customer tag (802.1Q) and the service tag (802.1ad) carry an identical
layout, so :class:`~pcapkit.protocols.link.c_tag.C_Tag` and
:class:`~pcapkit.protocols.link.s_tag.S_Tag` share the data model below.

"""

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
    """Data model for an 802.1Q/802.1ad VLAN tag."""

    #: Tag control information.
    tci: 'TCI'
    #: Protocol (Internet Layer).
    type: 'EtherType'

    if TYPE_CHECKING:
        def __init__(self, tci: 'TCI', type: 'EtherType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
