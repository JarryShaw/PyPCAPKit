# -*- coding: utf-8 -*-
"""data models for ethernet protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Data, Protocol

if TYPE_CHECKING:
    from pcapkit.const.reg.ethertype import EtherType

__all__ = ['Ethernet']


@info_final
class Ethernet(Protocol):
    """Data model for ethernet packet."""

    #: Destination MAC address.
    dst: 'str'
    #: Source MAC address.
    src: 'str'
    #: Length/Type, an EtherType or the length of the payload.
    type: 'EtherType'

    if TYPE_CHECKING:
        #: Octets captured past the length a Length/Type field gives, the pad
        #: among them, present only when there are any.
        trailer: 'bytes'

        def __init__(self, dst: 'str', src: 'str', type: 'EtherType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements
