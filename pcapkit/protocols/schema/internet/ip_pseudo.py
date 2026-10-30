# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for the IP pseudo-header"""

import ipaddress
from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv4AddressField, IPv6AddressField
from pcapkit.corekit.fields.misc import ConditionalField, SwitchField
from pcapkit.corekit.fields.numbers import EnumField, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import PaddingField
from pcapkit.protocols.schema.schema import Schema, schema_final

__all__ = ['IP_Pseudo']

if TYPE_CHECKING:
    from ipaddress import IPv4Address, IPv6Address
    from typing import Any

    from pcapkit.corekit.fields.field import FieldBase as Field

#: Length of the IPv4 pseudo-header, :rfc:`793#section-3.1`.
#:
#: .. versionadded:: 1.6.0
IPV4_PSEUDO_LEN = 12

#: Length of the IPv6 pseudo-header, :rfc:`8200#section-8.1`.
#:
#: .. versionadded:: 1.6.0
IPV6_PSEUDO_LEN = 40


def is_ipv6(packet: 'dict[str, Any]') -> 'bool':
    """Tell whether ``packet`` holds an IPv6 pseudo-header.

    Args:
        packet: Packet data.

    Returns:
        Whether the pseudo-header has the IPv6 layout: by the version of the
        source address once it is known, by the octets to unpack before that.

    .. versionadded:: 1.6.0

    """
    src = packet.get('src')
    if isinstance(src, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return src.version == 6
    return packet['__length__'] >= IPV6_PSEUDO_LEN


def ip_pseudo_address_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`IP_Pseudo.src` and :attr:`IP_Pseudo.dst`.

    Args:
        packet: Packet data.

    Returns:
        An :class:`~pcapkit.corekit.fields.ipaddress.IPv6AddressField` for the
        IPv6 layout, an :class:`~pcapkit.corekit.fields.ipaddress.IPv4AddressField`
        otherwise.

    .. versionadded:: 1.6.0

    """
    if is_ipv6(packet):
        return IPv6AddressField()
    return IPv4AddressField()


def ip_pseudo_zero_selector(packet: 'dict[str, Any]') -> 'Field':
    """Selector function for :attr:`IP_Pseudo.zero`.

    Args:
        packet: Packet data.

    Returns:
        A :class:`~pcapkit.corekit.fields.strings.PaddingField` of three octets
        for the IPv6 layout, of one octet otherwise.

    .. versionadded:: 1.6.0

    """
    return PaddingField(length=3 if is_ipv6(packet) else 1)


@schema_final
class IP_Pseudo(Schema):
    """Header schema for the IP pseudo-header.

    The layout follows the source address: :rfc:`793#section-3.1` for IPv4,
    whose length is :attr:`ipv4_len`, and :rfc:`8200#section-8.1` for IPv6,
    whose length is :attr:`ipv6_len`.

    .. versionadded:: 1.6.0

    """

    #: Source address.
    src: 'IPv4Address | IPv6Address' = SwitchField(selector=ip_pseudo_address_selector)
    #: Destination address.
    dst: 'IPv4Address | IPv6Address' = SwitchField(selector=ip_pseudo_address_selector)
    #: Upper-layer packet length (IPv6 only).
    ipv6_len: 'int' = ConditionalField(UInt32Field(), is_ipv6)
    #: Zero octets.
    zero: 'bytes' = SwitchField(selector=ip_pseudo_zero_selector)
    #: Upper-layer protocol number.
    protocol: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Upper-layer packet length (IPv4 only).
    ipv4_len: 'int' = ConditionalField(UInt16Field(), lambda pkt: not is_ipv6(pkt))

    if TYPE_CHECKING:
        def __init__(self, src: 'IPv4Address | IPv6Address', dst: 'IPv4Address | IPv6Address',
                     protocol: 'Enum_TransType | int', zero: 'bytes' = b'',
                     ipv4_len: 'int' = ..., ipv6_len: 'int' = ...) -> 'None': ...
