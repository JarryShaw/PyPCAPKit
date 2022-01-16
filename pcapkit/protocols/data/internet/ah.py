# -*- coding: utf-8 -*-
"""data model for AH protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from pcapkit.const.reg.transtype import TransType

__all__ = ['AH']


class AH(Info):
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

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', spi: 'int', seq: 'int', icv: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin
