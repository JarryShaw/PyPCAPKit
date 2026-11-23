# -*- coding: utf-8 -*-
# mypy: disable-error-code=assignment
"""header schema for internet protocol version 6

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.internet.ipv6.jumbo_payload_length``, now
   :func:`pcapkit.corekit.schema.jumbogram.jumbo_payload_length` (:issue:`2674`).

.. versionremoved:: 1.7.0

   ``pcapkit.protocols.internet.ipv6.schema.IP_MAX_LENGTH``, now
   :data:`pcapkit.corekit.const.ipheader.IP_MAX_LENGTH` (:issue:`2883`).

"""

from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.corekit.const.ipheader import IP_MAX_LENGTH
from pcapkit.corekit.fields.ipaddress import IPv6AddressField
from pcapkit.corekit.fields.misc import PayloadField
from pcapkit.corekit.fields.numbers import EnumField, UInt8Field, UInt16Field
from pcapkit.corekit.fields.strings import BitField
from pcapkit.corekit.schema.jumbogram import jumbo_payload_length
from pcapkit.protocols.schema import Schema, schema_final
from pcapkit.utilities.logging import SPHINX_TYPE_CHECKING

__all__ = ['IPv6']

if TYPE_CHECKING:
    from ipaddress import IPv6Address
    from typing import Any, Callable, Optional

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
    """Header schema for IPv6 packet.

    .. versionchanged:: 1.5.0

       New field :attr:`trailer`, which keeps the octets captured past the
       Payload Length rather than dropping them (:issue:`1209`).

    """

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
    #: padding, see :attr:`IPv4.trailer <pcapkit.protocols.internet.ipv4.schema.IPv4.trailer>`.
    trailer: 'bytes' = PayloadField(default=b'')

    def post_process(self, packet: 'dict[str, Any]') -> 'Schema':
        """Revise ``schema`` data after unpacking process.

        A jumbogram [:rfc:`2675`] declares a Payload Length of zero and
        carries its real length in a Jumbo Payload option instead, so the
        :attr:`payload` field reads nothing and every octet lands in
        :attr:`trailer`. When
        :func:`~pcapkit.corekit.schema.jumbogram.jumbo_payload_length` finds that option,
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

    if TYPE_CHECKING:
        def __init__(self, hextet: 'IPv6Hextet', length: 'int', next: 'Enum_TransType',
                     limit: 'int', src: 'IPv6Address | bytes | str | int',
                     dst: 'IPv6Address | bytes | str | int',
                     payload: 'bytes | ProtocolBase | Schema',
                     trailer: 'bytes' = b'') -> None: ...


def jumbogram_error(length: 'int', next: 'int', data: 'bytes',  # pylint: disable=redefined-builtin
                    fragment: 'Optional[Callable[[], bool]]' = None) -> 'Optional[str]':
    """Name the error :rfc:`2675#section-3` has a receiver detect in an IPv6 packet, if any.

    The four errors that section lists for a node that understands the Jumbo
    Payload option, each a packet the default engine rejects (:issue:`1687`):

    * a Payload Length of zero, a Next Header of Hop-by-Hop Options, and no
      Jumbo Payload option;
    * a non-zero Payload Length and a Jumbo Payload option;
    * a Jumbo Payload option whose Jumbo Payload Length is below 65,536;
    * a Jumbo Payload option and a Fragment header.

    The option counts only where
    :func:`~pcapkit.corekit.schema.jumbogram.jumbo_payload_length` finds it.

    Args:
        length: Payload Length of the IPv6 header.
        next: Next Header of the IPv6 header.
        data: Octets following the IPv6 header, as captured.
        fragment: Tells whether the extension header chain, as the default
            engine walks it, has a Fragment header; called only for a packet
            carrying the option, so a caller walks the chain only for those.

    Returns:
        The error, or :data:`None` if the packet makes none of them.

    """
    jumbo = jumbo_payload_length(next, data)
    if jumbo is None:
        if not length and next == Enum_TransType.HOPOPT:
            return 'Payload Length 0 and a Hop-by-Hop Options header with no Jumbo Payload option'
        return None
    if length:
        return f'Jumbo Payload option with a non-zero Payload Length {length}'
    if jumbo <= IP_MAX_LENGTH:
        return f'Jumbo Payload Length {jumbo}, not greater than {IP_MAX_LENGTH:,}'
    if fragment is not None and fragment():
        return 'Jumbo Payload option with a Fragment header'
    return None
