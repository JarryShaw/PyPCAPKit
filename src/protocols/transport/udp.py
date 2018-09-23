# -*- coding: utf-8 -*-
"""user datagram protocol

`pcapkit.protocols.transport.udp` contains `UDP` only,
which implements extractor for User Datagram Protocol
(UDP), whose structure is described as below.

 0      7 8     15 16    23 24    31
+--------+--------+--------+--------+
|     Source      |   Destination   |
|      Port       |      Port       |
+--------+--------+--------+--------+
|                 |                 |
|     Length      |    Checksum     |
+--------+--------+--------+--------+
|
|          data octets ...
+---------------- ...

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.transport.transport import Transport

__all__ = ['UDP']


class UDP(Transport):
    """This class implements User Datagram Protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Transport`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance
        * src -- int, source port
        * dst -- int, destination port

    Methods:
        * read_udp -- read User Datagram Protocol (UDP)

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
        return 'User Datagram Protocol'

    @property
    def length(self):
        """Header length of current protocol."""
        return 8

    @property
    def src(self):
        """Source port."""
        return self._info.src

    @property
    def dst(self):
        """Destination port."""
        return self._info.dst

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_udp(self, length):
        """Read User Datagram Protocol (UDP).

        Structure of UDP header [RFC 768]:
             0      7 8     15 16    23 24    31
            +--------+--------+--------+--------+
            |     Source      |   Destination   |
            |      Port       |      Port       |
            +--------+--------+--------+--------+
            |                 |                 |
            |     Length      |    Checksum     |
            +--------+--------+--------+--------+
            |
            |          data octets ...
            +---------------- ...

            Octets      Bits        Name                    Description
              0           0     udp.srcport             Source Port
              2          16     udp.dstport             Destination Port
              4          32     udp.len                 Length (header includes)
              6          48     udp.checksum            Checksum

        """
        if length is None:
            length = len(self)

        _srcp = self._read_unpack(2)
        _dstp = self._read_unpack(2)
        _tlen = self._read_unpack(2)
        _csum = self._read_fileng(2)

        udp = dict(
            srcport=_srcp,
            dstport=_dstp,
            len=_tlen,
            checksum=_csum,
        )

        length = udp['len'] - 8
        udp['packet'] = self._read_packet(header=8, payload=length)

        return self._decode_next_layer(udp, None, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_udp(length))

    def __length_hint__(self):
        return 8
