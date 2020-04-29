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

from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.link.link import Link

__all__ = ['Ethernet']


class Ethernet(Link):
    """This class implements Ethernet Protocol."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return 'Ethernet Protocol'

    @property
    def length(self):
        """Header length of current protocol."""
        return 14

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.type  # pylint: disable=E1101

    # source mac address
    @property
    def src(self):
        """Source mac address."""
        return self._info.src  # pylint: disable=E1101

    # destination mac address
    @property
    def dst(self):
        """Destination mac address."""
        return self._info.dst  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ethernet(self, length):
        """Read Ethernet Protocol [:rfc:`7042`].

        Args:
            length (int): packet length

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, length=None, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            length (int): Packet length.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        """
        self._file = file
        self._info = Info(self.read_ethernet(length))

    def __length_hint__(self):
        """Return an estimated length (14) for the object."""
        return 14

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
