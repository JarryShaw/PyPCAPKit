# -*- coding: utf-8 -*-
"""data models for ethernet protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

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
    #: Protocol (internet layer).
    type: 'EtherType'

    if TYPE_CHECKING:
        def __init__(self, dst: 'str', src: 'str', type: 'EtherType') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements
