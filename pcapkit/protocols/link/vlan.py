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
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.link.link import Link

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

    def read_vlan(self, length):
        """Read 802.1Q Customer VLAN Tag Type.

        Args:
            length (int): packet length

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

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):  # pylint: disable=super-init-not-called
        """Initialisation.

        Args:
            file (io.BytesIO): Source packet stream.
            length (int): Packet length.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        """
        self._file = _file
        self._info = Info(self.read_vlan(length))

    def __length_hint__(self):
        """Return an estimated length (4) for the object."""
        return 4
