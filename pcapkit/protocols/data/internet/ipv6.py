# -*- coding: utf-8 -*-
"""data model for Internet Protocol version 6"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any

    from typing_extensions import Literal

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.protocols.data.protocol import Packet

__all__ = [
    'IPv6',
]


@info_final
class IPv6(Protocol):
    """Data model for Internet Protocol version 6.

    Important:
        Due to the preserved keyword conflict, please use :meth:`from_dict`
        to create an instance of this data model.

    """

    #: Version.
    version: 'Literal[6]'
    #: Traffic class.
    #class: 'int'
    #: Flow label.
    label: 'int'
    #: Payload length.
    payload: 'int'
    #: Next header.
    next: 'TransType'
    #: Hop limit.
    limit: 'int'
    #: Source address.
    src: 'IPv6Address'
    #: Destination address.
    dst: 'IPv6Address'

    if TYPE_CHECKING:
        #: Fragmented packet header & payload (from IPv6-Frag header).
        fragment: 'Packet'
        #: Highest header protocol type (extension header excluded).
        protocol: 'TransType'
        #: Header length (including extension headers).
        hdr_len: 'int'
        #: Raw payload length (excluding extension headers).
        raw_len: 'int'

    def __new__(cls, *args: 'Any', **kwargs: 'Any') -> 'IPv6':
        self = super().__new__(cls, *args, **kwargs)

        # NOTE: We cannot define ``class`` due to preserved keyword conflict.
        # Thus, we directly inject the information into the annotations.
        self.__annotations__['class'] = int  # pylint: disable=no-member

        return self
