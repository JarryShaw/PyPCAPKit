# -*- coding: utf-8 -*-
"""data model for the IP pseudo-header"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    from typing_extensions import Literal

    from pcapkit.const.reg.transtype import TransType

__all__ = ['IP_Pseudo']


@info_final
class IP_Pseudo(Protocol):
    """Data model for the IP pseudo-header.

    .. versionadded:: 1.6.0

    """

    #: IP version of the enclosing layer.
    version: 'Literal[4, 6]'
    #: Source address.
    src: 'IPv4Address | IPv6Address'
    #: Destination address.
    dst: 'IPv4Address | IPv6Address'
    #: Upper-layer protocol number.
    protocol: 'TransType'
    #: Upper-layer packet length, header included.
    len: 'int'
    #: Reserved octets, as parsed.
    zero: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, version: 'Literal[4, 6]', src: 'IPv4Address | IPv6Address', dst: 'IPv4Address | IPv6Address', protocol: 'TransType', len: 'int', zero: 'bytes') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,redefined-builtin,line-too-long
