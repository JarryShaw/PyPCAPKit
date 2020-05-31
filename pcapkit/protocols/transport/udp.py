# -*- coding: utf-8 -*-
"""user datagram protocol

:mod:`pcapkit.protocols.transport.udp` contains
:class:`~pcapkit.protocols.transport.udp.UDP` only,
which implements extractor for User Datagram Protocol
(UDP) [*]_, whose structure is described as below:

======= ========= ===================== ===============================
Octets      Bits        Name                    Description
======= ========= ===================== ===============================
  0           0   ``udp.srcport``             Source Port
  2          16   ``udp.dstport``             Destination Port
  4          32   ``udp.len``                 Length (header includes)
  6          48   ``udp.checksum``            Checksum
======= ========= ===================== ===============================

.. [*] https://en.wikipedia.org/wiki/User_Datagram_Protocol

"""
from pcapkit.const.reg.transtype import TransType
from pcapkit.protocols.transport.transport import Transport

__all__ = ['UDP']


class UDP(Transport):
    """This class implements User Datagram Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['User Datagram Protocol']
        """
        return 'User Datagram Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: Literal[8]
        """
        return 8

    @property
    def src(self):
        """Source port.

        :rtype: int
        """
        return self._info.src  # pylint: disable=E1101

    @property
    def dst(self):
        """Destination port.

        :rtype: int
        """
        return self._info.dst  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read User Datagram Protocol (UDP).

        Structure of UDP header [:rfc:`768`]::

             0      7 8     15 16    23 24    31
            +--------+--------+--------+--------+
            |     Source      |   Destination   |
            |      Port       |      Port       |
            +--------+--------+--------+--------+
            |                 |                 |
            |     Length      |    Checksum     |
            +--------+--------+--------+--------+
            |
            |          data octets ...
            +---------------- ...

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_UDP: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _srcp = self._read_unpack(2)
        _dstp = self._read_unpack(2)
        _tlen = self._read_unpack(2)
        _csum = self._read_fileng(2)

        udp = dict(
            srcport=_srcp,
            dstport=_dstp,
            len=_tlen,
            checksum=_csum,
        )

        length = udp['len'] - 8
        udp['packet'] = self._read_packet(header=8, payload=length)

        return self._decode_next_layer(udp, None, length)

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

        :rtype: Literal[8]
        """
        return 8

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            pcapkit.const.reg.transtype.TransType: Numeral registry index of the
            protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return TransType(17)
