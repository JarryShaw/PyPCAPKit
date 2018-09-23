# -*- coding: utf-8 -*-
"""routing header for IPv6

``pcapkit.protocols.internet.ipv6_route`` contains
``IPv6_Route`` only, which implements extractor for Routing
Header for IPv6 (IPv6-Route), whose structure is described
as below.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
.                                                               .
.                       type-specific data                      .
.                                                               .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
import ipaddress

from pcapkit._common.ipv6_routing_type import RT_TYPE as _ROUTING_TYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['IPv6_Route']

# IPv6 Routing Processors
_ROUTE_PROC = {
    0: 'src',                          # [RFC 5095] DEPRECATED
    2: '2',                            # [RFC 6275]
    3: 'rpl',                          # [RFC 6554]
}


class IPv6_Route(Internet):
    """This class implements Routing Header for IPv6.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_ipv6_route -- read Routing Header for IPv6 (IPv6-Route)

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
        return 'Routing Header for IPv6'

    @property
    def alias(self):
        """Acronym of corresponding protocol."""
        return 'IPv6-Route'

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self):
        """Payload of current instance."""
        if self._extf:
            raise UnsupportedCall("'{}' object has no attribute 'payload'".format(self.__class__.__name__))
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.next

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_ipv6_route(self, length, extension):
        """Read Routing Header for IPv6.

        Structure of IPv6-Route header [RFC 8200][RFC 5095]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            .                                                               .
            .                       type-specific data                      .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     route.next              Next Header
              1           8     route.length            Header Extensive Length
              2          16     route.type              Routing Type
              3          24     route.seg_left          Segments Left
              4          32     route.data              Type-Specific Data

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_unpack(1)
        _left = self._read_unpack(1)

        ipv6_route = dict(
            next=_next,
            length=(_hlen + 1) * 8,
            type=_ROUTING_TYPE.get(_type, 'Unassigned'),
            seg_left=_left,
        )

        _dlen = _hlen * 8 - 4
        if _dlen:
            _func = _ROUTE_PROC.get(_type, 'none')
            _data = eval('self._read_data_type_{}'.format(_func))(_dlen)
            ipv6_route.update(_data)

        length -= ipv6_route['length']
        ipv6_route['packet'] = self._read_packet(header=ipv6_route['length'], payload=length)

        if extension:
            self._protos = None
            return ipv6_route
        return self._decode_next_layer(ipv6_route, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._extf = extension
        self._info = Info(self.read_ipv6_route(length, extension))

    def __length_hint__(self):
        return 4

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_data_type_none(self, length):
        """Read IPv6-Route unknown type data.

        Structure of IPv6-Route unknown type data [RFC 8200][RFC 5095]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  |  Routing Type | Segments Left |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            .                                                               .
            .                       type-specific data                      .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     route.next              Next Header
              1           8     route.length            Header Extensive Length
              2          16     route.type              Routing Type
              3          24     route.seg_left          Segments Left
              4          32     route.data              Type-Specific Data

        """
        _data = self._read_fileng(length)

        data = dict(
            data=_data,
        )

        return data

    def _read_data_type_src(self, length):
        """Read IPv6-Route Source Route data.

        Structure of IPv6-Route Source Route data [RFC 5095]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  | Routing Type=0| Segments Left |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Reserved                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                                                               +
            |                                                               |
            +                           Address[1]                          +
            |                                                               |
            +                                                               +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                                                               +
            |                                                               |
            +                           Address[2]                          +
            |                                                               |
            +                                                               +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            .                               .                               .
            .                               .                               .
            .                               .                               .
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                                                               +
            |                                                               |
            +                           Address[n]                          +
            |                                                               |
            +                                                               +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     route.next              Next Header
              1           8     route.length            Header Extensive Length
              2          16     route.type              Routing Type
              3          24     route.seg_left          Segments Left
              4          32     -                       Reserved
              8          64     route.ip                Address
                                ............

        """
        _resv = self._read_fileng(4)
        _addr = list()
        for _ in range((length - 4) // 16):
            _addr.append(ipaddress.ip_address(self._read_fileng(16)))

        data = dict(
            ip=tuple(_addr),
        )

        return data

    def _read_data_type_2(self, length):
        """Read IPv6-Route Type 2 data.

        Structure of IPv6-Route Type 2 data [RFC 6275]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  | Hdr Ext Len=2 | Routing Type=2|Segments Left=1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                            Reserved                           |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            +                                                               +
            |                                                               |
            +                         Home Address                          +
            |                                                               |
            +                                                               +
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     route.next              Next Header
              1           8     route.length            Header Extensive Length
              2          16     route.type              Routing Type
              3          24     route.seg_left          Segments Left
              4          32     -                       Reserved
              8          64     route.ip                Home Address

        """
        if length != 20:
            raise ProtocolError('{}: [Typeno 2] invalid format'.format(self.alias))

        _resv = self._read_fileng(4)
        _home = self._read_fileng(16)

        data = dict(
            ip=ipaddress.ip_address(_home),
        )

        return data

    def _read_data_type_rpl(self, length):
        """Read IPv6-Route RPL Source data.

        Structure of IPv6-Route RPL Source data [RFC 6554]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  | Routing Type  | Segments Left |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | CmprI | CmprE |  Pad  |               Reserved                |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            .                                                               .
            .                        Addresses[1..n]                        .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     route.next              Next Header
              1           8     route.length            Header Extensive Length
              2          16     route.type              Routing Type
              3          24     route.seg_left          Segments Left
              4          32     route.cmpri             CmprI
              4          36     route.cpmre             CmprE
              5          40     route.pad               Pad Size
              5          44     -                       Reserved
              8          64     route.ip                Addresses

        """
        _cmpr = self._read_binary(1)
        _padr = self._read_binary(1)
        _resv = self._read_fileng(2)

        _inti = int(_cmpr[:4], base=2)
        _inte = int(_cmpr[4:], base=2)
        _plen = int(_padr[:4], base=2)

        _ilen = 16 - _inti
        _elen = 16 - _inte

        _addr = list()
        for _ in (((length - 4) - _elen - _plen) // _ilen):
            _addr.append(ipaddress.ip_address(self._read_fileng(_ilen)))
        _addr.append(ipaddress.ip_address(self._read_fileng(_elen)))

        _pads = self._read_fileng(_plen)

        data = dict(
            cmpri=_inti,
            cmpre=_inte,
            pad=_plen,
            ip=tuple(_addr),
        )

        return data
