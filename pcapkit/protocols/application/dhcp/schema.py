# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for the BOOTP and DHCP family

A BOOTP message (:rfc:`951#section-3`) and a DHCP message (:rfc:`2131#section-2`)
share one layout, so :class:`~pcapkit.protocols.application.bootp.protocol.BOOTP`
and :class:`~pcapkit.protocols.application.dhcpv4.protocol.DHCPv4` share the
schema below. The area after ``file`` is BOOTP's ``vend`` and DHCP's
``options``.

.. versionadded:: 1.10.0

"""

from typing import TYPE_CHECKING

from pcapkit.corekit.fields.ipaddress import IPv4AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import UInt8Field, UInt16Field, UInt32Field
from pcapkit.corekit.fields.strings import BitField, BytesField
from pcapkit.protocols.application.dhcp.const import CHADDR_LENGTH, FILE_LENGTH, SNAME_LENGTH
from pcapkit.protocols.schema import Schema, schema_final

__all__ = ['DHCP']

if TYPE_CHECKING:
    from ipaddress import IPv4Address
    from typing import Any

    from typing_extensions import TypedDict

    from pcapkit.protocols.protocol import ProtocolBase

    class Flags(TypedDict):
        """BOOTP and DHCP header flags."""

        #: Broadcast flag.
        broadcast: int
        #: Remaining bits, which must be zero.
        reserved: int


def dhcp_area_length(packet: 'dict[str, Any]') -> 'int':
    """Length of :attr:`DHCP.options`.

    Args:
        packet: Packet data.

    Returns:
        The rest of the data; packing, where ``__length__`` is unset, the
        area as given.

    """
    return packet['__length__']


@schema_final
class DHCP(Schema):
    """Header schema for a BOOTP or DHCP message."""

    #: Message op code.
    op: 'int' = UInt8Field()
    #: Hardware address type.
    htype: 'int' = UInt8Field()
    #: Hardware address length.
    hlen: 'int' = UInt8Field()
    #: Hops.
    hops: 'int' = UInt8Field()
    #: Transaction ID.
    xid: 'int' = UInt32Field()
    #: Seconds elapsed since the client began.
    secs: 'int' = UInt16Field()
    #: Flags (:rfc:`1542#section-3.1.1`).
    flags: 'Flags' = BitField(length=2, namespace={
        'broadcast': (0, 1),
        'reserved': (1, 15),
    })
    #: Client IP address.
    ciaddr: 'IPv4Address' = IPv4AddressField()
    #: Your (client) IP address.
    yiaddr: 'IPv4Address' = IPv4AddressField()
    #: Next server IP address.
    siaddr: 'IPv4Address' = IPv4AddressField()
    #: Relay agent IP address.
    giaddr: 'IPv4Address' = IPv4AddressField()
    #: Client hardware address.
    chaddr: 'bytes' = BytesField(length=CHADDR_LENGTH)
    #: Server host name.
    sname: 'bytes' = BytesField(length=SNAME_LENGTH)
    #: Boot file name.
    file: 'bytes' = BytesField(length=FILE_LENGTH)
    #: BOOTP's vendor area or DHCP's options, undecoded.
    options: 'bytes' = BytesField(length=dhcp_area_length)
    #: Octets after the message, which it does not define.
    payload: 'bytes' = PayloadField()

    if TYPE_CHECKING:
        def __init__(self, op: 'int', htype: 'int', hlen: 'int', hops: 'int', xid: 'int', secs: 'int',
                     flags: 'Flags', ciaddr: 'IPv4Address | str | bytes | int',
                     yiaddr: 'IPv4Address | str | bytes | int', siaddr: 'IPv4Address | str | bytes | int',
                     giaddr: 'IPv4Address | str | bytes | int', chaddr: 'bytes', sname: 'bytes', file: 'bytes',
                     options: 'bytes', payload: 'bytes | ProtocolBase | Schema') -> 'None': ...
