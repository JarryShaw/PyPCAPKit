# -*- coding: utf-8 -*-
"""routing header for IPv6

``jspcap.protocols.internet.ipv6_route`` contains
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
# TODO: Implements extractor of all routing types.


# Routing Header for IPv6
# Analyser for IPv6-Route header


from jspcap.utilities import Info
from jspcap.protocols.protocol import Protocol


__all__ = ['IPv6_Route']


# IPv6 Routing Types
_ROUTING_TYPE = {
    0 : 'Source Route',                 # [RFC 5095] DEPRECATED
    1 : 'Nimrod',                       # DEPRECATED 2009-05-06
    2 : 'Type 2 Routing Header',        # [RFC 6275]
    3 : 'RPL Source Route Header',      # [RFC 6554]
  253 : 'RFC3692-style Experiment 1',   # [RFC 4727]
  254 : 'RFC3692-style Experiment 2',   # [RFC 4727]
  255 : 'Reserved',
}


class IPv6_Route(Protocol):
    """This class implements Routing Header for IPv6.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
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
        """Acronym of corresponding procotol."""
        return 'IPv6-Route'

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.length

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

            Octets      Bits        Name                    Discription
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
        _data = self._read_fileng(_hlen - 3)

        ipv6_route = dict(
            next = _next,
            length = _hlen + 1,
            type = _ROUTING_TYPE.get(_type, 'Unassigned'),
            sed_left = _left,
            data = _data,
        )

        if length is not None:
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
        self._info = Info(self.read_ipv6_route(length, extension))

    def __length_hint__(self):
        return 4
