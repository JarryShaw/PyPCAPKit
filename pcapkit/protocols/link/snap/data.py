# -*- coding: utf-8 -*-
"""data models for IEEE 802 Subnetwork Access Protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType

__all__ = ['SNAP']


@info_final
class SNAP(Protocol):
    """Data model for SNAP headers."""

    #: Organizationally Unique Identifier.
    oui: 'int'
    #: Protocol identifier, an EtherType where :attr:`oui` is ``00-00-00``.
    pid: 'Enum_EtherType | int'

    if TYPE_CHECKING:
        def __init__(self, oui: 'int', pid: 'Enum_EtherType | int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
