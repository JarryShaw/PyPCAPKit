# -*- coding: utf-8 -*-
"""data model for AH protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

if TYPE_CHECKING:
    from pcapkit.const.reg.transtype import TransType

__all__ = ['AH']


@info_final
class AH(Data):
    """Data model for AH protocol."""

    #: Next header.
    next: 'TransType'
    #: Payload length.
    length: 'int'
    #: Security parameters index.
    spi: 'int'
    #: Sequence number field.
    seq: 'int'
    #: Integrity check value.
    icv: 'bytes'
