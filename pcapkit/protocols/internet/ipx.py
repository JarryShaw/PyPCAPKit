# -*- coding: utf-8 -*-
"""IPX - Internetwork Packet Exchange
========================================

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

from pcapkit.const.ipx.packet import Packet as RegType_Packet
from pcapkit.const.ipx.socket import Socket as RegType_Socket
from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.protocols.data.internet.ipx import IPX as DataType_IPX
from pcapkit.protocols.data.internet.ipx import Address as DataType_Address
from pcapkit.protocols.internet.internet import Internet

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['IPX']


class IPX(Internet[DataType_IPX]):
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
    def protocol(self) -> 'RegType_TransType':
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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_IPX':
        """Read Internetwork Packet Exchange.

         Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_IPX: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _csum = self._read_fileng(2)
        _tlen = self._read_unpack(2)
        _ctrl = self._read_unpack(1)
        _type = self._read_unpack(1)
        _dsta = self._read_ipx_address()
        _srca = self._read_ipx_address()

        ipx = DataType_IPX(
            chksum=_csum,
            len=_tlen,
            count=_ctrl,
            type=RegType_Packet.get(_type),
            dst=_dsta,
            src=_srca,
        )

        return self._decode_next_layer(ipx, ipx.type, ipx.len - 30)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[30]':
        """Return an estimated length for the object."""
        return 30

    @classmethod
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.IPX_in_IP  # type: ignore[return-value]

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ipx_address(self) -> 'DataType_Address':
        """Read IPX address field.

        Returns:
            Parsed IPX address field.

        """
        # Address Number
        _byte = self._read_fileng(4)
        _ntwk = ':'.join(textwrap.wrap(_byte.hex(), 2))

        # Node Number (MAC)
        _byte = self._read_fileng(6)
        _node = ':'.join(textwrap.wrap(_byte.hex(), 2))
        _maca = '-'.join(textwrap.wrap(_byte.hex(), 2))

        # Socket Number
        _sock = self._read_fileng(2)

        # Whole Address
        _list = [_ntwk, _node, _sock.hex()]
        _addr = ':'.join(_list)

        addr = DataType_Address(
            network=_ntwk,
            node=_maca,
            socket=RegType_Socket.get(int(_sock.hex(), base=16)),
            addr=_addr,
        )

        return addr
