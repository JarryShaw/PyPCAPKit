# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Linux "Cooked" Capture Encapsulation v2
=============================================

.. module:: pcapkit.protocols.link.linux_sll2

:mod:`pcapkit.protocols.link.linux_sll2` contains
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2` only: the Linux "cooked"
capture encapsulation v2 [*]_ of ``LINKTYPE_LINUX_SLL2``. Its structure:

.. table::

   ====== ===== ================================ ================================
   Octets Bits  Name                             Description
   ====== ===== ================================ ================================
   0          0 ``linux_sll2.protocol_type``     Protocol (Internet Layer)
   ------ ----- -------------------------------- --------------------------------
   2         16 ``linux_sll2.reserved``          Reserved
   ------ ----- -------------------------------- --------------------------------
   4         32 ``linux_sll2.interface_index``   Interface Index
   ------ ----- -------------------------------- --------------------------------
   8         64 ``linux_sll2.arphrd_type``       ARP Hardware Type
   ------ ----- -------------------------------- --------------------------------
   10        80 ``linux_sll2.packet_type``       Packet Type
   ------ ----- -------------------------------- --------------------------------
   11        88 ``linux_sll2.link_addr_length``  Link-Layer Address Length
   ------ ----- -------------------------------- --------------------------------
   12        96 ``linux_sll2.link_addr``         Link-Layer Address (padded)
   ====== ===== ================================ ================================

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html

"""
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.protocols.data.link.linux_sll2 import LinuxSLL2 as Data_LinuxSLL2
from pcapkit.protocols.link.linux_sll import (LinuxSLL, _resolve_next_layer_proto,
                                              _validate_link_addr)
from pcapkit.protocols.schema.link.linux_sll2 import LinuxSLL2 as Schema_LinuxSLL2

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['LinuxSLL2']


class LinuxSLL2(LinuxSLL[Data_LinuxSLL2, Schema_LinuxSLL2],
                schema=Schema_LinuxSLL2, data=Data_LinuxSLL2):
    """Linux "cooked" capture encapsulation v2 (``LINUX_SLL2``).

    Next-layer dispatch is that of :class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Linux cooked capture encapsulation v2"]':
        """Name of current protocol."""
        return 'Linux cooked capture encapsulation v2'

    @property
    def alias(self) -> 'Literal["LINUX_SLL2"]':
        """Acronym of corresponding protocol."""
        return 'LINUX_SLL2'

    #: NOTE: see :attr:`LinuxSLL1.info_name
    #: <pcapkit.protocols.link.linux_sll1.LinuxSLL1.info_name>`.
    @property
    def info_name(self) -> 'Literal["linux_sll2"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'linux_sll2'

    @property
    def length(self) -> 'Literal[20]':
        """Header length of current protocol."""
        return 20

    @property
    def protocol(self) -> 'int':  # type: ignore[override]
        """Protocol (internet layer) of next layer protocol."""
        return self._info.protocol_type

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["LinuxSLL2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, this version's own name.

        """
        return ('LinuxSLL2',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_LinuxSLL2':  # pylint: disable=unused-argument
        """Read Linux "cooked" capture encapsulation v2.

        Structure of the ``LINUX_SLL2`` header:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Protocol Type        |            Reserved           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                        Interface Index                       |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          ARPHRD Type          |Packet Type|Link-Addr Length|
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 Link-Layer Address (padded)                  |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        linux_sll2 = Data_LinuxSLL2(
            protocol_type=schema.protocol_type,
            reserved=schema.reserved,
            interface_index=schema.interface_index,
            arphrd_type=schema.arphrd_type,
            packet_type=schema.packet_type,
            link_addr_length=schema.link_addr_length,
            link_addr=schema.link_addr,
        )

        _proto = _resolve_next_layer_proto(self.__proto__, schema.arphrd_type,
                                           schema.protocol_type)
        return self._decode_next_layer(linux_sll2, _proto, length - self.length)

    def make(self,
             protocol_type: 'Enum_EtherType | int' = Enum_EtherType.Internet_Protocol_version_4,
             reserved: 'int' = 0,
             interface_index: 'int' = 0,
             arphrd_type: 'Enum_Hardware | int' = Enum_Hardware.Ethernet,
             packet_type: 'int' = 0,
             link_addr: 'bytes | bytearray' = b'',
             link_addr_length: 'Optional[int]' = None,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_LinuxSLL2':
        """Make (construct) packet data.

        Args:
            protocol_type: Protocol (internet layer); an EtherType unless
                ``arphrd_type`` is a key of :attr:`LinuxSLL.__proto__
                <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`.
            reserved: Reserved, must be zero.
            interface_index: Index, in the capturing host's own numbering, of
                the interface the packet was seen on.
            arphrd_type: ARP hardware type of the interface the packet was
                seen on.
            packet_type: Packet type (direction).
            link_addr: Link-layer address, at most 8 octets; padded with
                ``NUL`` octets to 8 if shorter.
            link_addr_length: Length of the address actually in use, by
                default ``len(link_addr)``; may exceed 8, up to ``0xFF``.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``link_addr`` does not fit in 8 octets, or
                ``link_addr_length`` is given outside ``0`` to ``0xFF``.

        """
        _addr, link_addr_length = _validate_link_addr(
            self.alias, link_addr, link_addr_length, max_length=0xFF)

        _arphrd = self._make_index(arphrd_type, pack=False)
        _proto = self._make_index(protocol_type, pack=False)

        return Schema_LinuxSLL2(
            protocol_type=_proto,
            reserved=reserved,
            interface_index=interface_index,
            arphrd_type=_arphrd,
            packet_type=packet_type,
            link_addr_length=link_addr_length,
            link_addr=_addr,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[20]':
        """Return an estimated length for the object."""
        return 20

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.LINUX_SLL2  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_LinuxSLL2') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'protocol_type': data.protocol_type,
            'reserved': data.reserved,
            'interface_index': data.interface_index,
            'arphrd_type': data.arphrd_type,
            'packet_type': data.packet_type,
            'link_addr': data.link_addr,
            'link_addr_length': data.link_addr_length,
            'payload': cls._make_payload(data),
        }
