# -*- coding: utf-8 -*-
"""internetwork packet exchange

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

from pcapkit.const.ipx.packet import Packet as TYPE
from pcapkit.const.ipx.socket import Socket as SOCK
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.internet.internet import Internet

__all__ = ['IPX']


class IPX(Internet):
    """This class implements Internetwork Packet Exchange."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding protocol.

        :rtype: Literal['Internetwork Packet Exchange']
        """
        return 'Internetwork Packet Exchange'

    @property
    def length(self):
        """Header length of corresponding protocol.

        :rtype: Literal[30]
        """
        return 30

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.transtype.TransType
        """
        return self._info.type  # pylint: disable=E1101

    @property
    def src(self):
        """Source IPX address.

        :rtype: str
        """
        return self._info.src.addr  # pylint: disable=E1101

    @property
    def dst(self):
        """Destination IPX address.

        :rtype: str
        """
        return self._info.dst.addr  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):
        """Read Internetwork Packet Exchange.

         Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
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

        ipx = dict(
            chksum=_csum,
            len=_tlen,
            count=_ctrl,
            type=TYPE.get(_type),
            dst=_dsta,
            src=_srca,
        )

        proto = ipx['type']
        length = ipx['len'] - 30
        ipx['packet'] = self._read_packet(header=30, payload=length)

        return self._decode_next_layer(ipx, proto, length)

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        """Return an estimated length for the object.

        :rtype: Literal[30]
        """
        return 30

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(111)

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_ipx_address(self):
        """Read IPX address field.

        Returns:
            DataType_IPX_Address: Parsed IPX address field.

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

        addr = dict(
            network=_ntwk,
            node=_maca,
            socket=SOCK.get(int(_sock.hex(), base=16)) or _sock,
            addr=_addr,
        )

        return addr
