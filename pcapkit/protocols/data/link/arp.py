# -*- coding: utf-8 -*-
"""data models for address resolution protocol family"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data
from pcapkit.protocols.data.protocol import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address

    from pcapkit.const.arp.hardware import Hardware
    from pcapkit.const.arp.operation import Operation
    from pcapkit.const.reg.ethertype import EtherType

__all__ = ['Address', 'Type', 'ARP']


@info_final
class Address(Data):
    """Data model for ARP addresses."""

    #: Hardware address.
    hardware: 'str'
    #: Protocol address.
    protocol: 'str | IPv4Address | IPv6Address'

    if TYPE_CHECKING:
        def __init__(self, hardware: 'str', protocol: 'str | IPv4Address | IPv6Address') -> 'None': ...  # pylint: disable=line-too-long,super-init-not-called,unused-argument,multiple-statements


@info_final
class Type(Data):
    """Data model for ARP type."""

    #: Hardware type.
    hardware: 'Hardware'
    #: Protocol type.
    protocol: 'EtherType | str'

    if TYPE_CHECKING:
        def __init__(self, hardware: 'Hardware', protocol: 'EtherType | str') -> 'None': ...  # pylint: disable=line-too-long,super-init-not-called,unused-argument,multiple-statements


@info_final
class ARP(Protocol):
    """Data model for ARP packet."""

    #: Hardware type.
    htype: 'Hardware'
    #: Protocol type.
    ptype: 'EtherType'
    #: Hardware address length.
    hlen: 'int'
    #: Protocol address length.
    plen: 'int'
    #: Operation code.
    oper: 'Operation'
    #: Sender hardware address.
    sha: 'str'
    #: Sender protocol address.
    spa: 'str | IPv4Address | IPv6Address'
    #: Target hardware address.
    tha: 'str'
    #: Target protocol address.
    tpa: 'str | IPv4Address | IPv6Address'
    #: Header length.
    len: 'int'

    if TYPE_CHECKING:
        def __init__(self, htype: 'Hardware', ptype: 'EtherType', hlen: 'int', plen: 'int',  # pylint: disable=line-too-long,super-init-not-called,unused-argument,multiple-statements
                     oper: 'Operation', sha: 'str', spa: 'str | IPv4Address | IPv6Address',  # pylint: disable=unused-argument
                     tha: 'str', tpa: 'str | IPv4Address | IPv6Address', len: 'int') -> 'None': ...  # pylint: disable=unused-argument,redefined-builtin
