# -*- coding: utf-8 -*-
"""data models for IPv6 Fragment Header"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from pcapkit.const.reg.transtype import TransType

__all__ = ['IPv6_Frag']


@info_final
class IPv6_Frag(Protocol):
    """Data model for IPv6 fragment header."""

    #: Next header.
    next: 'TransType'
    #: Fragment offset.
    offset: 'int'
    #: More flag.
    mf: 'bool'
    #: Identification.
    id: 'int'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', offset: 'int', mf: 'bool', id: 'int') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,redefined-builtin,multiple-statements
