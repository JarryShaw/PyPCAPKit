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
from typing import TYPE_CHECKING

from pcapkit.const.reg.transtype import TransType as RegType_TransType
from pcapkit.protocols.data.transport.udp import UDP as DataType_UDP
from pcapkit.protocols.transport.transport import Transport

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

__all__ = ['UDP']


class UDP(Transport):
    """This class implements User Datagram Protocol."""

    #: Parsed packet data.
    _info: 'DataType_UDP'

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["User Datagram Protocol"]':
        """Name of current protocol."""
        return 'User Datagram Protocol'

    @property
    def length(self) -> 'Literal[8]':
        """Header length of current protocol."""
        return 8

    @property
    def src(self) -> 'int':
        """Source port."""
        return self._info.src

    @property
    def dst(self) -> 'int':
        """Destination port."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_UDP':  # pylint: disable=unused-argument
        """Read User Datagram Protocol (UDP).

        Structure of UDP header [:rfc:`768`]:

        .. code-block:: text

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

        udp = DataType_UDP(
            srcport=_srcp,
            dstport=_dstp,
            len=_tlen,
            checksum=_csum,
        )

        return self._decode_next_layer(udp, None, udp.len - 8)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[8]':
        """Return an estimated length for the object."""
        return 8

    @classmethod
    def __index__(cls) -> 'RegType_TransType':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Returns:
            Numeral registry index of the protocol in `IANA`_.

        .. _IANA: https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml

        """
        return RegType_TransType.UDP  # type: ignore[return-value]
