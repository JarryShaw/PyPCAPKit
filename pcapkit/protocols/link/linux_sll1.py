# -*- coding: utf-8 -*-
# mypy: disable-error-code=dict-item
"""Linux "Cooked" Capture Encapsulation
==========================================

.. module:: pcapkit.protocols.link.linux_sll1

:mod:`pcapkit.protocols.link.linux_sll1` contains
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1` only: the Linux "cooked"
capture encapsulation [*]_ of ``LINKTYPE_LINUX_SLL``, the header of every
``tcpdump -i any`` capture on Linux. Its structure:

.. table::

   ====== ===== ============================== ================================
   Octets Bits  Name                           Description
   ====== ===== ============================== ================================
   0          0 ``linux_sll.packet_type``      Packet Type
   ------ ----- ------------------------------ --------------------------------
   2         16 ``linux_sll.arphrd_type``      ARP Hardware Type
   ------ ----- ------------------------------ --------------------------------
   4         32 ``linux_sll.link_addr_length`` Link-Layer Address Length
   ------ ----- ------------------------------ --------------------------------
   6         48 ``linux_sll.link_addr``        Link-Layer Address (padded)
   ------ ----- ------------------------------ --------------------------------
   14       112 ``linux_sll.protocol_type``    Protocol (Internet Layer)
   ====== ===== ============================== ================================

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html

"""
from typing import TYPE_CHECKING

from pcapkit.const.arp.hardware import Hardware as Enum_Hardware
from pcapkit.const.reg.ethertype import EtherType as Enum_EtherType
from pcapkit.const.reg.linktype import LinkType as Enum_LinkType
from pcapkit.protocols.data.link.linux_sll1 import LinuxSLL1 as Data_LinuxSLL1
from pcapkit.protocols.link.linux_sll import (LinuxSLL, _resolve_next_layer_proto,
                                              _validate_link_addr)
from pcapkit.protocols.schema.link.linux_sll1 import LinuxSLL1 as Schema_LinuxSLL1

if TYPE_CHECKING:
    from typing import Any, Optional

    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['LinuxSLL1']


class LinuxSLL1(LinuxSLL[Data_LinuxSLL1, Schema_LinuxSLL1],
                schema=Schema_LinuxSLL1, data=Data_LinuxSLL1):
    """Linux "cooked" capture encapsulation v1 (``LINUX_SLL``).

    ``protocol_type`` is dispatched as an EtherType, unless ``arphrd_type`` is
    a key of :attr:`LinuxSLL.__proto__
    <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`, which dispatches
    it instead; with no dissector registered either way, the payload is
    :class:`~pcapkit.protocols.misc.raw.Raw`.

    """

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Linux cooked capture encapsulation"]':
        """Name of current protocol."""
        return 'Linux cooked capture encapsulation'

    @property
    def alias(self) -> 'Literal["LINUX_SLL1"]':
        """Acronym of corresponding protocol."""
        return 'LINUX_SLL1'

    #: NOTE: ``linux_sll``, not the default ``linuxsll``; see
    #: :class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`.
    @property
    def info_name(self) -> 'Literal["linux_sll"]':
        """Key name of the :attr:`~pcapkit.protocols.protocol.Protocol.info` dict."""
        return 'linux_sll'

    @property
    def length(self) -> 'Literal[16]':
        """Header length of current protocol."""
        return 16

    @property
    def protocol(self) -> 'int':  # type: ignore[override]
        """Protocol (internet layer) of next layer protocol."""
        return self._info.protocol_type

    ##########################################################################
    # Methods.
    ##########################################################################

    @classmethod
    def id(cls) -> 'tuple[Literal["LinuxSLL1"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol, this version's own name.

        """
        return ('LinuxSLL1',)

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_LinuxSLL1':  # pylint: disable=unused-argument
        """Read Linux "cooked" capture encapsulation.

        Structure of the ``LINUX_SLL`` header:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Packet Type          |         ARPHRD Type           |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |      Link-Layer Addr Length   |     Link-Layer Address...     |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |                 ...Link-Layer Address (padded)                |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |          Protocol Type        |
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

        linux_sll = Data_LinuxSLL1(
            packet_type=schema.packet_type,
            arphrd_type=schema.arphrd_type,
            link_addr_length=schema.link_addr_length,
            link_addr=schema.link_addr,
            protocol_type=schema.protocol_type,
        )

        _proto = _resolve_next_layer_proto(self.__proto__, schema.arphrd_type,
                                           schema.protocol_type)
        return self._decode_next_layer(linux_sll, _proto, length - self.length)

    def make(self,
             packet_type: 'int' = 0,
             arphrd_type: 'Enum_Hardware | int' = Enum_Hardware.Ethernet,
             link_addr: 'bytes | bytearray' = b'',
             link_addr_length: 'Optional[int]' = None,
             protocol_type: 'Enum_EtherType | int' = Enum_EtherType.Internet_Protocol_version_4,
             payload: 'bytes | ProtocolBase | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_LinuxSLL1':
        """Make (construct) packet data.

        Args:
            packet_type: Packet type (direction).
            arphrd_type: ARP hardware type of the interface the packet was
                seen on.
            link_addr: Link-layer address, at most 8 octets; padded with
                ``NUL`` octets to 8 if shorter.
            link_addr_length: Length of the address actually in use, by
                default ``len(link_addr)``; may exceed 8, up to ``0xFFFF``.
            protocol_type: Protocol (internet layer); an EtherType unless
                ``arphrd_type`` is a key of :attr:`LinuxSLL.__proto__
                <pcapkit.protocols.link.linux_sll.LinuxSLL.__proto__>`.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        Raises:
            ProtocolError: If ``link_addr`` does not fit in 8 octets, or
                ``link_addr_length`` is given outside ``0`` to ``0xFFFF``.

        """
        _addr, link_addr_length = _validate_link_addr(
            self.alias, link_addr, link_addr_length, max_length=0xFFFF)

        _arphrd = self._make_index(arphrd_type, pack=False)
        _proto = self._make_index(protocol_type, pack=False)

        return Schema_LinuxSLL1(
            packet_type=packet_type,
            arphrd_type=_arphrd,
            link_addr_length=link_addr_length,
            link_addr=_addr,
            protocol_type=_proto,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[16]':
        """Return an estimated length for the object."""
        return 16

    @classmethod
    def __index__(cls) -> 'Enum_LinkType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `tcpdump`_ link-layer
            header types.

        .. _tcpdump: https://www.tcpdump.org/linktypes.html

        """
        return Enum_LinkType.LINUX_SLL  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_LinuxSLL1') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'packet_type': data.packet_type,
            'arphrd_type': data.arphrd_type,
            'link_addr': data.link_addr,
            'link_addr_length': data.link_addr_length,
            'protocol_type': data.protocol_type,
            'payload': cls._make_payload(data),
        }
