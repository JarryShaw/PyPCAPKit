# -*- coding: utf-8 -*-
"""Ethernet Protocol
=======================

.. module:: pcapkit.protocols.link.ethernet.protocol

:mod:`pcapkit.protocols.link.ethernet.protocol` contains
:class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet`
only, which implements the extractor for Ethernet
Protocol [*]_, whose structure is described as
below:

.. table::

   ====== ===== ================= =========================
   Octets Bits  Name              Description
   ====== ===== ================= =========================
   0          0 ``ethernet.dst``  Destination MAC Address
   ------ ----- ----------------- -------------------------
   6         48 ``ethernet.src``  Source MAC Address
   ------ ----- ----------------- -------------------------
   12        96 ``ethernet.type`` Length/Type
   ====== ===== ================= =========================

.. [*] https://en.wikipedia.org/wiki/Ethernet

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.corekit.decorators import beholder
from pcapkit.protocols.link.ethernet.const import LENGTH_MAX
from pcapkit.protocols.link.ethernet.data import Ethernet as Data_Ethernet
from pcapkit.protocols.link.ethernet.schema import Ethernet as Schema_Ethernet
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema import Schema

__all__ = ['Ethernet']


class Ethernet(Link[Data_Ethernet, Schema_Ethernet],
               schema=Schema_Ethernet, data=Data_Ethernet):
    """This class implements Ethernet Protocol.

    The Length/Type field is an EtherType from ``0x0600`` up, and the payload
    is dispatched through :attr:`Link.__proto__
    <pcapkit.protocols.link.link.Link.__proto__>`. Up to ``0x05DC`` it is the
    length of the MAC client data, an IEEE 802.2
    :class:`~pcapkit.protocols.link.llc.protocol.LLC` PDU, and the octets past
    it, the pad among them, are kept as
    :attr:`~pcapkit.protocols.link.ethernet.schema.Ethernet.trailer`
    (:ieee:`802.3-2022` §3.2.6). A value between the two is neither, and its payload is
    kept as :class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

    .. versionchanged:: 1.9.0

       A Length/Type field up to ``0x05DC`` is a length, and the payload it
       bounds is dissected as LLC, where it was kept raw; ``make()`` takes the
       ``trailer`` (:issue:`2936`).

    .. versionchanged:: 1.6.0

       ``type`` of :meth:`make` takes a member or an :class:`int` code,
       resolved with the enumeration's ``get``; a name, a :obj:`bool`, or a
       code the field cannot carry raises
       :exc:`~pcapkit.utilities.exceptions.ProtocolError`, rather than
       resolving against an enumeration inferred from the caller's frame or
       writing a different value (:issue:`2594`).

    .. versionremoved:: 1.6.0

       The ``type_default``, ``type_namespace`` and ``type_reversed``
       arguments of :meth:`make`; resolve a name with
       :meth:`~pcapkit.protocols.protocol.Protocol.resolve_index` first
       (:issue:`2594`).

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Ethernet Protocol"]':
        """Name of current protocol."""
        return 'Ethernet Protocol'

    @property
    def length(self) -> 'Literal[14]':
        """Header length of current protocol."""
        return 14

    @property
    def protocol(self) -> 'Enum_EtherType':
        """Name of next layer protocol, the Length/Type field."""
        return self._info.type

    # source mac address
    @property
    def src(self) -> 'str':
        """Source mac address."""
        return self._info.src

    # destination mac address
    @property
    def dst(self) -> 'str':
        """Destination mac address."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_Ethernet':  # pylint: disable=unused-argument
        """Read Ethernet Protocol.

        Structure of Ethernet header [:rfc:`7042`]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                         Dst MAC Addr                          |
           +                               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                               |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
           |                         Src MAC Addr                          |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Ether Type           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        _dstm = self._read_mac_addr(schema.dst)
        _srcm = self._read_mac_addr(schema.src)
        _type = schema.type

        ethernet = Data_Ethernet(
            dst=_dstm,
            src=_srcm,
            type=_type,
        )

        # NOTE: Octets captured past a Length belong to this layer, as PPPoE keeps its own.
        if schema.trailer:
            ethernet.__update__([
                ('trailer', schema.trailer),
            ])

        # NOTE: A header the capture cut leaves a negative length, which keeps the next layer
        # raw however the cut left the Length/Type field (#1170).
        remaining = length - self.length
        if _type <= LENGTH_MAX and remaining >= 0:
            return self._decode_next_layer(ethernet, _type, _type)
        return self._decode_next_layer(ethernet, _type, remaining)

    def make(self, *,
             dst: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             src: 'str | bytes | bytearray' = '00:00:00:00:00:00',
             type: 'Enum_EtherType | int' = Enum_EtherType.Internet_Protocol_version_4,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             trailer: 'bytes' = b'',
             **kwargs: 'Any') -> 'Schema_Ethernet':
        """Make (construct) packet data.

        Args:
            dst: Destination MAC address.
            src: Source MAC address.
            type: Length/Type: an EtherType, or, up to ``0x05DC``, the length
                of the payload, which it has to be but in a rebuild of a cut
                frame.
            payload: Payload data.
            trailer: Octets after the payload a length gives, such as the pad;
                written as is.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``dst`` or ``src`` is rejected by
                :meth:`~pcapkit.protocols.protocol.Protocol._make_mac_addr`;
                if ``type`` is a name, a :obj:`bool`, or a member or code its
                field cannot carry; if a length is not that of ``payload``; or
                if ``trailer`` is given with no length to end the payload.

        """
        _type = self._make_index(type, Enum_EtherType, bits=16, name='EtherType')

        # NOTE: A trailer reads back as payload unless a length ends the payload before it, and
        # another length moves octets between the two, unless a rebuild of a cut frame carries it.
        if _type <= LENGTH_MAX:
            size = len(payload if isinstance(payload, (bytes, bytearray)) else bytes(payload))
            if _type != size and self.__short_read__ is None:
                raise ProtocolError(f'{self.alias}: length {int(_type)} is not the {size} octet(s) of the payload')
        elif trailer:
            raise ProtocolError(f'{self.alias}: trailer given, but EtherType {_type!r} gives no length')

        return Schema_Ethernet(
            dst=self._make_mac_addr(dst),
            src=self._make_mac_addr(src),
            type=_type,
            payload=payload,
            trailer=trailer,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[14]':
        """Return an estimated length for the object."""
        return 14

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.ETHERNET  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_Ethernet') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'dst': data.dst,
            'src': data.src,
            'type': data.type,
            'payload': cls._make_payload(data),
            'trailer': data.get('trailer', b''),
        }

    @beholder  # type: ignore[arg-type]
    def _import_next_layer(self, proto: 'int', length: 'Optional[int]' = None, *,  # type: ignore[misc]
                           packet: 'Optional[dict[str, Any]]' = None) -> 'ProtocolBase':
        """Import next layer extractor.

        Arguments:
            proto: next layer protocol index, the Length/Type field
            length: valid (*non-padding*) length
            packet: packet info (passed from :meth:`self.unpack
                <pcapkit.protocols.protocol.Protocol.unpack>`)

        Returns:
            Instance of next layer: :class:`~pcapkit.protocols.link.llc.protocol.LLC`
            where ``proto`` is a length, and otherwise the class
            :attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`
            registers for it.

        """
        if proto <= LENGTH_MAX:
            return self._import_llc(proto, length, packet=packet)
        return super()._import_next_layer(proto, length, packet=packet)  # type: ignore[misc,call-arg]
