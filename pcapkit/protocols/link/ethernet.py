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
import sys
import textwrap
from typing import TYPE_CHECKING

from pcapkit.protocols.data.link.ethernet import Ethernet as DataType_Ethernet
from pcapkit.protocols.link.link import Link

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.ethertype import EtherType as RegType_EtherType

__all__ = ['Ethernet']

# check Python version
py38 = ((version_info := sys.version_info).major >= 3 and version_info.minor >= 8)


class Ethernet(Link):
    """This class implements Ethernet Protocol."""

    #: Parsed packet data.
    _info: 'DataType_Ethernet'

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
    def protocol(self) -> 'RegType_EtherType':
        """Name of next layer protocol."""
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

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_Ethernet':  # pylint: disable=unused-argument
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

        ethernet = DataType_Ethernet(
            dst=_dstm,
            src=_srcm,
            type=_type,
        )
        return self._decode_next_layer(ethernet, _type, length - self.length)  # type: ignore[return-value]

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

    def __length_hint__(self) -> 'Literal[14]':
        """Return an estimated length for the object."""
        return 14

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_mac_addr(self) -> 'str':
        """Read MAC address.

        Returns:
            Colon (``:``) seperated *hex* encoded MAC address.

        """
        _byte = self._read_fileng(6)
        if py38:
            _addr = _byte.hex(':')
        else:
            _addr = ':'.join(textwrap.wrap(_byte.hex(), 2))
        return _addr
