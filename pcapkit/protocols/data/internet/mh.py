# -*- coding: utf-8 -*-
"""data model for MH protocol"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info

if TYPE_CHECKING:
    from pcapkit.const.mh.packet import Packet
    from pcapkit.const.reg.transtype import TransType

__all__ = ['MH']


class MH(Info):
    """Data model for MH protocol."""

    #: Next header.
    next: 'TransType'
    #: Header length.
    length: 'int'
    #: Mobility header type.
    type: 'Packet'
    #: Checksum.
    chksum: 'bytes'
    #: Message data.
    data: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, next: 'TransType', length: 'int', type: 'Packet', chksum: 'bytes', data: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long
