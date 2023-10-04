# -*- coding: utf-8 -*-
"""IPX - Internetwork Packet Exchange
========================================

.. module:: pcapkit.protocols.internet.ipx

:mod:`pcapkit.protocols.internet.ipx` contains
:class:`~pcapkit.protocols.internet.ipx.IPX` only,
which implements extractor for Internetwork Packet
Exchange (IPX) [*]_, whose structure is described
as below:

======= ========= ====================== =====================================
Octets      Bits        Name                    Description
======= ========= ====================== =====================================
  0           0   ``ipx.cksum``             Checksum
  2          16   ``ipx.len``               Packet Length (header includes)
  4          32   ``ipx.count``             Transport Control (hop count)
  5          40   ``ipx.type``              Packet Type
  6          48   ``ipx.dst``               Destination Address
  18        144   ``ipx.src``               Source Address
======= ========= ====================== =====================================

.. [*] https://en.wikipedia.org/wiki/Internetwork_Packet_Exchange

"""
import textwrap
from typing import TYPE_CHECKING

from pcapkit.const.ipx.packet import Packet as Enum_Packet
from pcapkit.const.ipx.socket import Socket as Enum_Socket
from pcapkit.const.reg.transtype import TransType as Enum_TransType
from pcapkit.protocols.data.internet.ipx import IPX as Data_IPX
from pcapkit.protocols.data.internet.ipx import Address as Data_Address
from pcapkit.protocols.internet.internet import Internet
from pcapkit.protocols.schema.internet.ipx import IPX as Schema_IPX

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Optional, Type

    from aenum import IntEnum as AenumEnum
    from typing_extensions import Literal

    from pcapkit.protocols.protocol import ProtocolBase as Protocol
    from pcapkit.protocols.schema.schema import Schema

__all__ = ['IPX']


class IPX(Internet[Data_IPX, Schema_IPX],
          schema=Schema_IPX, data=Data_IPX):
    """This class implements Internetwork Packet Exchange."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["Internetwork Packet Exchange"]':
        """Name of corresponding protocol."""
        return 'Internetwork Packet Exchange'

    @property
    def length(self) -> 'Literal[30]':
        """Header length of corresponding protocol."""
        return 30

    @property
    def protocol(self) -> 'Enum_TransType':
        """Name of next layer protocol."""
        return self._info.type

    @property
    def src(self) -> 'str':
        """Source IPX address."""
        return self._info.src.addr

    @property
    def dst(self) -> 'str':
        """Destination IPX address."""
        return self._info.dst.addr

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_IPX':
        """Read Internetwork Packet Exchange.

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)
        schema = self.__header__

        ipx = Data_IPX(
            chksum=schema.chksum,
            len=schema.len,
            count=schema.count,
            type=schema.type,
            dst=self._read_ipx_address(schema.dst),
            src=self._read_ipx_address(schema.src),
        )

        return self._decode_next_layer(ipx, ipx.type, ipx.len - 30)

    def make(self,
             chksum: 'bytes' = b'\x00\x00',
             count: 'int' = 0,
             type: 'Enum_Packet | StdlibEnum | AenumEnum | str | int' = Enum_Packet.Unknown,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             dst: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
             src: 'bytes' = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00',
             payload: 'bytes | Protocol | Schema' = b'',
             **kwargs: 'Any') -> 'Schema_IPX':
        """Make (construct) packet data.

        Args:
            chksum: Checksum.
            count: Transport Control (hop count).
            type: Packet Type.
            type_default: Default value for undefined packet type.
            type_namespace: Namespace for packet type.
            type_reversed: Reverse namespace for packet type.
            dst: Destination Address.
            src: Source Address.
            payload: Payload data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        type_val = self._make_index(type, type_default, namespace=type_namespace,
                                    reversed=type_reversed, pack=False)

        return Schema_IPX(
            chksum=chksum,
            len=30 + len(payload),
            count=count,
            type=type_val,  # type: ignore[arg-type]
            dst=dst,
            src=src,
            payload=payload,
        )

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[30]':
        """Return an estimated length for the object."""
        return 30

    @classmethod
    def __index__(cls) -> 'Enum_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return Enum_TransType.IPX_in_IP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    @classmethod
    def _make_data(cls, data: 'Data_IPX') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'chksum': data.chksum,
            'count': data.count,
            'type': data.type,
            'dst': data.dst,
            'src': data.src,
            'payload': cls._make_payload(data),
        }

    def _read_ipx_address(self, addr: 'bytes') -> 'Data_Address':
        """Read IPX address field.

        Args:
            addr: IPX address data.

        Returns:
            Parsed IPX address field.

        """
        # Address Number
        _ntwk = ':'.join(textwrap.wrap(addr[:4].hex(), 2))

        # Node Number (MAC)
        _node = ':'.join(textwrap.wrap(addr[4:10].hex(), 2))
        _maca = '-'.join(textwrap.wrap(addr[4:10].hex(), 2))

        # Socket Number
        _sock = addr[10:12]

        # Whole Address
        _list = [_ntwk, _node, ':'.join(textwrap.wrap(_sock.hex(), 2))]
        _addr = ':'.join(_list)

        ipx_addr = Data_Address(
            network=_ntwk,
            node=_maca,
            socket=Enum_Socket.get(int.from_bytes(_sock, 'big', signed=False)),
            addr=_addr,
        )
        return ipx_addr
