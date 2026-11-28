# -*- coding: utf-8 -*-
"""data model for DHCP

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Union

    from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
    from pcapkit.const.dhcp.opcode import Opcode as Enum_Opcode
    from pcapkit.protocols.application.dhcp.data import Flags as Data_Flags
    from pcapkit.protocols.application.dhcp.data import Option as Data_Option
    from pcapkit.protocols.application.dhcp.data import OverloadedField as Data_OverloadedField

__all__ = ['DHCPv4']


@info_final
class DHCPv4(Protocol):
    """Data model for a DHCP message (:rfc:`2131#section-2`)."""

    #: Message op code.
    op: 'Enum_Opcode'
    #: Hardware address type.
    htype: 'Enum_Hardware'
    #: Hardware address length.
    hlen: 'int'
    #: Hops.
    hops: 'int'
    #: Transaction ID.
    xid: 'int'
    #: Seconds elapsed since the client began.
    secs: 'int'
    #: Flags.
    flags: 'Data_Flags'
    #: Client IP address.
    ciaddr: 'IPv4Address'
    #: Your (client) IP address.
    yiaddr: 'IPv4Address'
    #: Next server IP address.
    siaddr: 'IPv4Address'
    #: Relay agent IP address.
    giaddr: 'IPv4Address'
    #: Client hardware address, its first :attr:`hlen` octets; a MAC address
    #: for an Ethernet or IEEE 802 type of six octets.
    chaddr: 'Union[str, bytes]'
    #: The octets of ``chaddr`` after the address.
    chaddr_padding: 'bytes'
    #: Server host name, its trailing NULs removed, or the options it holds
    #: where the Option Overload option says so.
    sname: 'Union[bytes, Data_OverloadedField]'
    #: Boot file name, its trailing NULs removed, or the options it holds
    #: where the Option Overload option says so.
    file: 'Union[bytes, Data_OverloadedField]'
    #: The magic cookie opening the options field.
    magic_cookie: 'bytes'
    #: Options.
    options: 'tuple[Data_Option, ...]'
    #: Octets after the End option, or from the option the field ends inside.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, op: 'Enum_Opcode', htype: 'Enum_Hardware', hlen: 'int', hops: 'int', xid: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     secs: 'int', flags: 'Data_Flags', ciaddr: 'IPv4Address', yiaddr: 'IPv4Address',
                     siaddr: 'IPv4Address', giaddr: 'IPv4Address', chaddr: 'Union[str, bytes]',
                     chaddr_padding: 'bytes', sname: 'Union[bytes, Data_OverloadedField]',
                     file: 'Union[bytes, Data_OverloadedField]', magic_cookie: 'bytes',
                     options: 'tuple[Data_Option, ...]', padding: 'bytes') -> 'None': ...
