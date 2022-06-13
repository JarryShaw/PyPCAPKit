# -*- coding: utf-8 -*-
"""VLAN - 802.1Q Customer VLAN Tag Type
==========================================

:mod:`pcapkit.protocols.link.vlan` contains
:class:`~pcapkit.protocols.link.vlan.VLAN`
only, which implements extractor for 802.1Q
Customer VLAN Tag Type [*]_, whose structure is
described as below:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  1           0   ``vlan.tci``              Tag Control Information
  1           0   ``vlan.tci.pcp``          Priority Code Point
  1           3   ``vlan.tci.dei``          Drop Eligible Indicator
  1           4   ``vlan.tci.vid``          VLAN Identifier
  3          24   ``vlan.type``             Protocol (Internet Layer)
======= ========= ====================== =============================

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q

"""
from typing import TYPE_CHECKING

from pcapkit.const.vlan.priority_level import PriorityLevel as RegType_PriorityLevel
from pcapkit.protocols.data.link.vlan import TCI as DataType_TCI
from pcapkit.protocols.data.link.vlan import VLAN as DataType_VLAN
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

if TYPE_CHECKING:
    from typing import Any, NoReturn, Optional

    from typing_extensions import Literal

    from pcapkit.const.reg.ethertype import EtherType as RegType_EtherType

__all__ = ['VLAN']


class VLAN(Link[DataType_VLAN]):
    """This class implements 802.1Q Customer VLAN Tag Type."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self) -> 'Literal["802.1Q Customer VLAN Tag Type"]':
        """Name of current protocol."""
        return '802.1Q Customer VLAN Tag Type'

    @property
    def alias(self) -> 'Literal["802.1Q"]':
        """Acronym of corresponding protocol."""
        return '802.1Q'

    @property
    def info_name(self) -> 'Literal["c_tag"]':
        """Key name of the :attr:`info` dict."""
        return 'c_tag'

    @property
    def length(self) -> 'Literal[4]':
        """Header length of current protocol."""
        return 4

    @property
    def protocol(self) -> 'RegType_EtherType':
        """Name of next layer protocol."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'DataType_VLAN':  # pylint: disable=unused-argument
        """Read 802.1Q Customer VLAN Tag Type.

        Structure of 802.1Q Customer VLAN Tag Type [`IEEE 802.1Q <https://standards.ieee.org/ieee/802.1Q/6844/>`__]:

        .. code-block:: text

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
           |              TCI              |                               |
           |-------------------------------|                               |
           |  P  |D|                       |             Type              |
           |  C  |E|          VID          |                               |
           |  P  |I|                       |                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        Args:
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        """
        if length is None:
            length = len(self)

        _tcif = self._read_binary(2)
        _type = self._read_protos(2)

        vlan = DataType_VLAN(
            tci=DataType_TCI(
                pcp=RegType_PriorityLevel.get(int(_tcif[:3], base=2)),
                dei=bool(_tcif[3]),
                vid=int(_tcif[4:], base=2),
            ),
            type=_type,
        )
        return self._decode_next_layer(vlan, _type, length - self.length)

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[4]':
        """Return an estimated length for the object."""
        return 4

    @classmethod
    def __index__(cls) -> 'NoReturn':  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
