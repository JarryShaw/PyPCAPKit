# -*- coding: utf-8 -*-
"""data models for address resolution protocol family"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data.data import Data

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


@info_final
class Type(Data):
    """Data model for ARP type."""

    #: Hardware type.
    hardware: 'Hardware'
    #: Protocol type.
    protocol: 'EtherType | str'


@info_final
class ARP(Data):
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
