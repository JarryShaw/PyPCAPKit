# -*- coding: utf-8 -*-
"""mobility header

`pcapkit.protocols.internet.mh` contains `MH` only,
which implements extractor for Mobility Header (MH),
whose structure is described as below.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Payload Proto |  Header Len   |   MH Type     |   Reserved    |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|           Checksum            |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
|                                                               |
.                                                               .
.                       Message Data                            .
.                                                               .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
from pcapkit._common.mh_mobility_type import PktType as _MOBILITY_TYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

# TODO: Implements extractor for message data of all MH types.
__all__ = ['MH']


class MH(Internet):
    """This class implements Mobility Header.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_mh -- read Mobility Header (MH)

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
        return 'Mobility Header'

    @property
    def length(self):
        """Header length of current protocol."""
        return self._info.length

    @property
    def payload(self):
        """Payload of current instance."""
        if self.extension:
            raise UnsupportedCall("'{}' object has no attribute 'payload'".format(self.__class__.__name__))
        return self._next

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.next

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_mh(self, length, extension):
        """Read Mobility Header.

        Structure of MH header [RFC 6275]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Payload Proto |  Header Len   |   MH Type     |   Reserved    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |           Checksum            |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               |
            |                                                               |
            .                                                               .
            .                       Message Data                            .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     mh.next                 Next Header
              1           8     mh.length               Header Length
              2          16     mh.type                 Mobility Header Type
              3          24     -                       Reserved
              4          32     mh.chksum               Checksum
              6          48     mh.data                 Message Data

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_unpack(1)
        _temp = self._read_fileng(1)
        _csum = self._read_fileng(2)
        # _data = self._read_fileng((_hlen+1)*8)

        mh = dict(
            next=_next,
            length=(_hlen + 1) * 8,
            type=_MOBILITY_TYPE.get(_type, 'Unassigned'),
            chksum=_csum,
        )

        length -= mh['length']
        mh['packet'] = self._read_packet(header=mh['length'], payload=length)

        if extension:
            self._protos = None
            return mh
        return self._decode_next_layer(mh, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._info = Info(self.read_mh(length, extension))

    def __length_hint__(self):
        return 6
