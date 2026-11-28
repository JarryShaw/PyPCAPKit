# -*- coding: utf-8 -*-
"""data model for BOOTP

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import info_final
from pcapkit.protocols.data import Protocol

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Optional, Union

    from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
    from pcapkit.const.dhcp.opcode import Opcode as Enum_Opcode
    from pcapkit.protocols.application.dhcp.data import Flags as Data_Flags
    from pcapkit.protocols.application.dhcp.data import Option as Data_Option

__all__ = ['BOOTP']


@info_final
class BOOTP(Protocol):
    """Data model for a BOOTP message (:rfc:`951#section-3`, :rfc:`1542`)."""

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
    #: Server IP address.
    siaddr: 'IPv4Address'
    #: Gateway IP address.
    giaddr: 'IPv4Address'
    #: Client hardware address, its first :attr:`hlen` octets; a MAC address
    #: for an Ethernet or IEEE 802 type of six octets.
    chaddr: 'Union[str, bytes]'
    #: The octets of ``chaddr`` after the address.
    chaddr_padding: 'bytes'
    #: Server host name, its trailing NULs removed.
    sname: 'bytes'
    #: Boot file name, its trailing NULs removed.
    file: 'bytes'
    #: The magic cookie opening :attr:`vend`, or :obj:`None` where it holds no
    #: vendor extensions.
    magic_cookie: 'Optional[bytes]'
    #: Vendor area, its vendor extensions (:rfc:`1497`, :rfc:`2132`) where
    #: :attr:`magic_cookie` opens it, else its raw octets.
    vend: 'Union[tuple[Data_Option, ...], bytes]'
    #: Octets after the End option, or from the vendor extension the area ends
    #: inside.
    padding: 'bytes'

    if TYPE_CHECKING:
        def __init__(self, op: 'Enum_Opcode', htype: 'Enum_Hardware', hlen: 'int', hops: 'int', xid: 'int',  # pylint: disable=unused-argument,super-init-not-called,multiple-statements
                     secs: 'int', flags: 'Data_Flags', ciaddr: 'IPv4Address', yiaddr: 'IPv4Address',
                     siaddr: 'IPv4Address', giaddr: 'IPv4Address', chaddr: 'Union[str, bytes]',
                     chaddr_padding: 'bytes', sname: 'bytes', file: 'bytes', magic_cookie: 'Optional[bytes]',
                     vend: 'Union[tuple[Data_Option, ...], bytes]', padding: 'bytes') -> 'None': ...
