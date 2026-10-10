# -*- coding: utf-8 -*-
"""data models for BSD loopback encapsulation"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from typing_extensions import Literal

__all__ = ['Loopback']


@info_final
class Loopback(Protocol):
    """Data model for BSD loopback encapsulation."""

    #: Address family (internet layer).
    family: 'int'
    #: Byte order the address family was written in.
    byteorder: 'Literal["big", "little"]'

    if TYPE_CHECKING:
        def __init__(self, family: 'int', byteorder: 'Literal["big", "little"]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
