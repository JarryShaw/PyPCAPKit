#!/usr/bin/python3
# -*- coding: utf-8 -*-


# User Datagram Protocol
# Analyser for UDP header


from jspcap.utilities import Info
from jspcap.protocols.transport.transport import Transport


__all__ = ['UDP']


class UDP(Transport):
    """This class implements Transmission Control Protocol.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
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
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        return 'User Datagram Protocol'

    @property
    def length(self):
        return 8

    @property
    def src(self):
        return self._info.src

    @property
    def dst(self):
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

            Octets          Bits          Name                      Discription
              0              0          udp.srcport             Source Port
              2              16         udp.dstport             Destination Port
              4              32         udp.len                 Length (header includes)
              6              48         udp.checksum            Checksum

        """
        _srcp = self._read_unpack(2)
        _dstp = self._read_unpack(2)
        _tlen = self._read_unpack(2)
        _csum = self._read_fileng(2)

        udp = dict(
            srcport = _srcp,
            dstport = _dstp,
            len = _tlen,
            checksum = _csum,
        )

        length = udp['len'] - 8
        return self._decode_next_layer(udp, None, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None):
        self._file = _file
        self._info = Info(self.read_udp(length))

    def __len__(self):
        return 8

    def __length_hint__(self):
        return 8
