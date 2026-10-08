# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 6"""

from typing import TYPE_CHECKING

from pcapkit.const.ipv6.option import Option as Enum_Option
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField
from pcapkit.protocols.schema.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['IPv6']

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Optional

    from pcapkit.protocols.protocol import ProtocolBase

if SPHINX_TYPE_CHECKING:  # pragma: no cover
    from typing_extensions import TypedDict

    #: Version, traffic class and flow label.
    IPv6Hextet = TypedDict('IPv6Hextet', {
        #: Version.
        'version': int,
        #: Traffic class.
        'class': int,
        #: Flow label.
        'label': int,
    })


@schema_final
class IPv6(Schema):
    """Header schema for IPv6 packet."""

    #: Version, traffic class and flow label.
    #:
    #: The :class:`~pcapkit.corekit.fields.strings.BitField` namespace maps each
    #: subfield to a ``(start_bit, length_in_bits)`` pair, *not* to
    #: ``(start_bit, end_bit)``. Per :rfc:`8200#section-3` the first 32 bits of
    #: the IPv6 header are Version (bits 0-3), Traffic Class (bits 4-11) and
    #: Flow Label (bits 12-31), so the flow label starts at bit 12 -- reading it
    #: as ``(8, 20)`` would overlap the low nibble of the traffic class and drop
    #: the low nibble of the label.
    hextet: 'IPv6Hextet' = BitField(length=4, namespace={
        'version': (0, 4),
        'class': (4, 8),
        'label': (12, 20),
    })
    #: Payload length.
    length: int = UInt16Field()
    #: Next header.
    next: 'Enum_TransType' = EnumField(length=1, namespace=Enum_TransType)
    #: Hop limit.
    limit: int = UInt8Field()
    #: Source address.
    src: 'IPv6Address' = IPv6AddressField()
    #: Destination address.
    dst: 'IPv6Address' = IPv6AddressField()
    #: Payload.
    payload: 'bytes' = PayloadField(length=lambda pkt: pkt['length'])
    #: Octets captured past the Payload Length (or a jumbogram's Jumbo Payload
    #: Length, see :meth:`post_process`), such as Ethernet minimum-frame
    #: padding, c.f. :attr:`IPv4.trailer <pcapkit.protocols.schema.internet.ipv4.IPv4.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    if TYPE_CHECKING:
        def __init__(self, hextet: 'IPv6Hextet', length: 'int', next: 'Enum_TransType',
                     limit: 'int', src: 'IPv6Address | bytes | str | int',
                     dst: 'IPv6Address | bytes | str | int',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> None: ...

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        A jumbogram [:rfc:`2675`] declares a Payload Length of zero and
        carries its real length in a Jumbo Payload option instead, so the
        :attr:`payload` field reads nothing and every octet lands in
        :attr:`trailer`. When :func:`jumbo_payload_length` finds that option,
        the two are split again at the Jumbo Payload Length, and only the
        octets beyond it stay in :attr:`trailer`. The octets themselves are
        untouched, so the packed header is unchanged.

        Args:
            packet: Unpacked data.

        Returns:
            Revised schema.

        """
        if self.length != 0 or self.__buffer__.get('payload'):
            return self

        rest = self.__buffer__.get('trailer', b'')
        jumbo = jumbo_payload_length(self.next, rest)
        if jumbo is None:
            return self

        self.payload = self.__buffer__['payload'] = rest[:jumbo]
        self.trailer = self.__buffer__['trailer'] = rest[jumbo:]
        return self


def jumbo_payload_length(next: 'int', data: 'bytes') -> 'Optional[int]':  # pylint: disable=redefined-builtin
    """Find the Jumbo Payload Length of an IPv6 packet [:rfc:`2675`].

    The Jumbo Payload option is only honoured in a Hop-by-Hop Options header
    that immediately follows the IPv6 header, as :rfc:`2675#section-2` and
    :rfc:`8200#section-4.1` place it there; one anywhere else is left to the
    extension header that carries it.

    Args:
        next: Next Header of the IPv6 header.
        data: Octets following the IPv6 header.

    Returns:
        The Jumbo Payload Length, or :data:`None` if ``data`` does not start
        with a Hop-by-Hop Options header carrying a well-formed (four-octet)
        Jumbo Payload option.

    """
    if next != Enum_TransType.HOPOPT or len(data) < 2:
        return None

    end = min((data[1] + 1) * 8, len(data))
    ptr = 2
    while ptr < end:
        code = data[ptr]
        if code == Enum_Option.Pad1:
            ptr += 1
            continue
        if ptr + 1 >= end:
            break
        size = data[ptr + 1]
        if code == Enum_Option.Jumbo_Payload and size == 4 and ptr + 6 <= end:
            return int.from_bytes(data[ptr + 2:ptr + 6], 'big', signed=False)
        ptr += 2 + size
    return None
