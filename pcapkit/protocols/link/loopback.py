# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""BSD Loopback Encapsulation
================================

.. module:: pcapkit.protocols.link.loopback

:mod:`pcapkit.protocols.link.loopback` contains
:class:`~pcapkit.protocols.link.loopback.Loopback`
only, which implements extractor for the BSD loopback
encapsulation [*]_ of ``LINKTYPE_NULL`` and ``LINKTYPE_LOOP``,
whose structure is described as below:

.. table::

   ====== ===== =================== ===================================
   Octets Bits  Name                Description
   ====== ===== =================== ===================================
   0          0 ``loopback.family`` Address Family (Internet Layer)
   ====== ===== =================== ===================================

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_NULL.html

"""
import collections
import sys
from typing import TYPE_CHECKING

from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.module import ModuleDescriptor
from pcapkit.protocols.data.link.loopback import Loopback as Data_Loopback
from pcapkit.protocols.link.link import Link
from pcapkit.protocols.schema.link.loopback import Loopback as Schema_Loopback
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, DefaultDict, Optional, Type

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['Loopback', 'family_byteorder']


def family_byteorder(family: 'bytes', linktype: 'Optional[int]' = None) -> 'Literal["big", "little"]':
    """Byte order a loopback header's address family was written in.

    Args:
        family: The 4 octets of the address family.
        linktype: Link type the frame was captured under; :data:`None` reads as
            ``LINKTYPE_NULL``.

    Returns:
        ``'big'`` for ``LINKTYPE_LOOP`` (108), whose family is in network byte
        order. Otherwise, for ``LINKTYPE_NULL`` (0), ``'big'`` if the octets
        read as a smaller number big-endian than little-endian, else
        ``'little'``.

    Note:
        A ``LINKTYPE_NULL`` family is in the byte order of the host that
        captured the packet, which the capture file does not record. Every
        address family is below ``0x10000``, so its zero octets lie at the high
        end, and the smaller of the two readings is the one in the writer's byte
        order. A family that reads the same both ways, such as 0, packs to the
        same octets either way. A ``LINKTYPE_LOOP`` family is never inferred,
        so one written little-endian reads as a family no table holds.

    """
    if linktype == Enum_LinkType.LOOP:
        return 'big'
    if int.from_bytes(family, 'big') < int.from_bytes(family, 'little'):
        return 'big'
    return 'little'


class Loopback(Link[Data_Loopback, Schema_Loopback],
               schema=Schema_Loopback, data=Data_Loopback):
    """This class implements BSD Loopback Encapsulation.

    The header is one 4-octet address family, in the byte order of the host
    that captured the packet for ``LINKTYPE_NULL`` and in network byte order
    for ``LINKTYPE_LOOP``. Which link type a frame was captured under is the
    ``alias`` it was dispatched with; for ``LINKTYPE_NULL``, which a frame
    parsed on its own is read as, the byte order is read from the octets
    themselves (see :func:`family_byteorder`). Either way it is kept in
    :attr:`info`, and :meth:`from_data <pcapkit.protocols.link.link.Link.from_data>`
    reads the family back in that byte order rather than inferring it again.

    The address families are those of the BSD socket API, whose ``AF_INET6``
    differs between the BSDs, so each of its values is read as IPv6. This class
    supports parsing of the following protocols, which are registered in the
    :attr:`self.__proto__ <pcapkit.protocols.link.loopback.Loopback.__proto__>`
    attribute:

    .. list-table::
       :header-rows: 1

       * - Index
         - Protocol
       * - 2
         - :class:`pcapkit.protocols.internet.ipv4.IPv4`
       * - 24
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`
       * - 28
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`
       * - 30
         - :class:`pcapkit.protocols.internet.ipv6.IPv6`

    Any other family is kept as :class:`~pcapkit.protocols.misc.raw.Raw`.

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[int, ModuleDescriptor[ProtocolBase] | ~typing.Type[ProtocolBase]]: Protocol index
    #: mapping for decoding next layer,
    #: c.f. :meth:`self._decode_next_layer <pcapkit.protocols.protocol.Protocol._decode_next_layer>`
    #: & :meth:`self._import_next_layer <pcapkit.protocols.protocol.Protocol._import_next_layer>`.
    #: Keyed by address family rather than by EtherType, so this class keeps a
    #: registry of its own instead of sharing :attr:`Link.__proto__
    #: <pcapkit.protocols.link.link.Link.__proto__>`.
    __proto__ = collections.defaultdict(
        lambda: ModuleDescriptor('pcapkit.protocols.misc.raw', 'Raw'),
        {
            2:  ModuleDescriptor('pcapkit.protocols.internet.ipv4', 'IPv4'),
            24: ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),
            28: ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),
            30: ModuleDescriptor('pcapkit.protocols.internet.ipv6', 'IPv6'),
        },
    )  # type: DefaultDict[int, ModuleDescriptor[ProtocolBase] | Type[ProtocolBase]]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["BSD Loopback Encapsulation"]':
        """Name of current protocol."""
        return 'BSD Loopback Encapsulation'

    @property
    def length(self) -> 'Literal[4]':
        """Header length of current protocol."""
        return 4

    @property
    def protocol(self) -> 'int':  # type: ignore[override]
        """Address family of next layer protocol."""
        return self._info.family

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, *, alias: 'Optional[int]' = None,
             byteorder: 'Optional[Literal["big", "little"]]' = None,
             **kwargs: 'Any') -> 'Data_Loopback':  # pylint: disable=unused-argument
        """Read BSD Loopback Encapsulation.

        Structure of the BSD loopback header:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Address Family                         |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            alias: Link type the frame was dispatched under, as
                :class:`~pcapkit.protocols.misc.pcap.frame.Frame` and
                :class:`~pcapkit.protocols.misc.pcapng.PCAPNG` pass it;
                ``LINKTYPE_LOOP`` reads the family in network byte order, and
                anything else as ``LINKTYPE_NULL``.
            byteorder: Byte order to read the family in, ahead of ``alias``.
                :meth:`make` is handed the one :attr:`info` holds by
                :meth:`from_data <pcapkit.protocols.link.link.Link.from_data>`,
                and it reaches here too, so a rebuild reads the family as it was
                parsed rather than inferring it again.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If ``byteorder`` is neither ``'big'`` nor
                ``'little'``.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        if byteorder is None:
            _byte = family_byteorder(schema.family, alias)
        elif byteorder in ('big', 'little'):
            _byte = byteorder
        else:
            raise ProtocolError(f'Loopback: invalid byte order: {byteorder!r}')
        _family = int.from_bytes(schema.family, _byte)

        loopback = Data_Loopback(
            family=_family,
            byteorder=_byte,
        )
        return self._decode_next_layer(loopback, _family, length - self.length)

    def make(self,
             family: 'int' = 2,
             byteorder: 'Literal["big", "little"]' = sys.byteorder,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_Loopback':
        """Make (construct) packet data.

        Args:
            family: Address family, e.g. 2 for IPv4.
            byteorder: Byte order to write the address family in, by default
                this host's, as a capture of its own loopback interface does.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``byteorder`` is neither ``'big'`` nor
                ``'little'``, or ``family`` does not fit in 4 octets.

        """
        if byteorder not in ('big', 'little'):
            raise ProtocolError(f'Loopback: invalid byte order: {byteorder!r}')
        if not 0 <= family <= 0xFFFF_FFFF:
            raise ProtocolError(f'Loopback: invalid address family: {family!r}')

        return Schema_Loopback(
            family=family.to_bytes(4, byteorder),
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types. ``LINKTYPE_LOOP`` (108) is dispatched here as well.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.NULL  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Loopback') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'family': data.family,
            'byteorder': data.byteorder,
            'payload': cls._make_payload(data),
        }
