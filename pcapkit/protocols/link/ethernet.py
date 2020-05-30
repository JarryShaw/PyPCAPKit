# -*- coding: utf-8 -*-
"""ethernet protocol

:mod:`pcapkit.protocols.link.ethernet` contains
:class:`~pcapkit.protocols.link.ethernet.Ethernet`
only, which implements extractor for Ethernet
Protocol [*]_, whose structure is described as
below:

+========+=======+==============+===========================+
| Octets | Bits  | Name         | Description               |
+========+=======+==============+===========================+
| 0      |     0 | ``eth.dst``  | Destination MAC Address   |
+--------+-------+--------------+---------------------------+
| 1      |     8 | ``eth.src``  | Source MAC Address        |
+--------+-------+--------------+---------------------------+
| 2      |    16 | ``eth.type`` | Protocol (Internet Layer) |
+--------+-------+--------------+---------------------------+

.. [*] https://en.wikipedia.org/wiki/Ethernet

"""
import textwrap

from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Ethernet']


class Ethernet(Link):
    """This class implements Ethernet Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['Ethernet Protocol']
        """
        return 'Ethernet Protocol'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: Literal[14]
        """
        return 14

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.ethertype.EtherType
        """
        return self._info.type  # pylint: disable=E1101

    # source mac address
    @property
    def src(self):
        """Source mac address.

        :rtype: str
        """
        return self._info.src  # pylint: disable=E1101

    # destination mac address
    @property
    def dst(self):
        """Destination mac address.

        :rtype: str
        """
        return self._info.dst  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Ethernet Protocol [:rfc:`7042`].

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_Ethernet: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _dstm = self._read_mac_addr()
        _srcm = self._read_mac_addr()
        _type = self._read_protos(2)

        ethernet = dict(
            dst=_dstm,
            src=_srcm,
            type=_type,
        )

        length -= 14
        ethernet['packet'] = self._read_packet(header=14, payload=length)

        return self._decode_next_layer(ethernet, _type, length)

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

        :rtype: Literal[14]
        """
        return 14

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_mac_addr(self):
        """Read MAC address.

        Returns:
            str: Colon (``:``) seperated *hex* encoded MAC address.

        """
        _byte = self._read_fileng(6)
        _addr = ':'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr
