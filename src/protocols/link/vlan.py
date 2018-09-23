# -*- coding: utf-8 -*-
"""802.1Q customer VLAN tag type

`pcapkit.protocols.link.vlan` contains `VLAN`
only, which implements extractor for 802.1QCustomer
VLAN Tag Type, whose structure is described as below.

Octets      Bits        Name                    Description
  1           0     vlan.tci                Tag Control Information
  1           0     vlan.tci.pcp            Priority Code Point
  1           3     vlan.tci.dei            Drop Eligible Indicator
  1           4     vlan.tci.vid            VLAN Identifier
  3          24     vlan.type               Protocol (Internet Layer)

"""
from pcapkit._common.vlan_pcp import PrioLvl as _PCP
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.link.link import Link

__all__ = ['VLAN']


class VLAN(Link):
    """This class implements 802.1Q Customer VLAN Tag Type.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Link`
        * length -- int, header length of corresponding protocol
        * protocol -- str, next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_vlan -- read 802.1Q Customer VLAN Tag Type

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _read_packet -- read raw packet data
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of current protocol."""
        return '802.1Q Customer VLAN Tag Type'

    @property
    def alias(self):
        """Acronym of corresponding protocol."""
        return '802.1Q'

    @property
    def length(self):
        """Header length of current protocol."""
        return 4

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.type

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_vlan(self, length):
        """Read 802.1Q Customer VLAN Tag Type.

        Structure of 802.1Q Customer VLAN Tag Type [RFC 7042]:
            Octets      Bits        Name                    Description
              1           0     vlan.tci                Tag Control Information
              1           0     vlan.tci.pcp            Priority Code Point
              1           3     vlan.tci.dei            Drop Eligible Indicator
              1           4     vlan.tci.vid            VLAN Identifier
              3          24     vlan.type               Protocol (Internet Layer)

        """
        if length is None:
            length = len(self)

        _tcif = self._read_binary(2)
        _type = self._read_protos(2)

        vlan = dict(
            tci=dict(
                pcp=_PCP.get(int(_tcif[:3], base=2)),
                dei=True if _tcif[3] else False,
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

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_vlan(length))

    def __length_hint__(self):
        return 4
