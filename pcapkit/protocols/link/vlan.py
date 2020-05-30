# -*- coding: utf-8 -*-
"""802.1Q customer VLAN tag type

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
from pcapkit.const.vlan.priority_level import PriorityLevel as _PCP
from pcapkit.protocols.link.link import Link
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['VLAN']


class VLAN(Link):
    """This class implements 802.1Q Customer VLAN Tag Type."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol.

        :rtype: Literal['802.1Q Customer VLAN Tag Type']
        """
        return '802.1Q Customer VLAN Tag Type'

    @property
    def alias(self):
        """Acronym of corresponding protocol.

        :rtype: Literal['802.1Q']
        """
        return '802.1Q'

    @property
    def length(self):
        """Header length of current protocol.

        :rtype: Literal[4]
        """
        return 4

    @property
    def protocol(self):
        """Name of next layer protocol.

        :rtype: pcapkit.const.reg.ethertype.EtherType
        """
        return self._info.type  # pylint: disable=E1101

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read 802.1Q Customer VLAN Tag Type.

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_VLAN: Parsed packet data.

        """
        if length is None:
            length = len(self)

        _tcif = self._read_binary(2)
        _type = self._read_protos(2)

        vlan = dict(
            tci=dict(
                pcp=_PCP.get(int(_tcif[:3], base=2)),
                dei=bool(_tcif[3]),
                vid=int(_tcif[4:], base=2),
            ),
            type=_type,
        )

        length -= 4
        vlan['packet'] = self._read_packet(header=4, payload=length)

        return self._decode_next_layer(vlan, _type, length)

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

        :rtype: Literal[4]
        """
        return 4

    @classmethod
    def __index__(cls):  # pylint: disable=invalid-index-returned
        """Numeral registry index of the protocol.

        Raises:
            UnsupportedCall: This protocol has no registry entry.

        """
        raise UnsupportedCall(f'{cls.__name__!r} object cannot be interpreted as an integer')
