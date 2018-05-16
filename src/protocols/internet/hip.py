# -*- coding: utf-8 -*-
"""host identity protocol

`jspcap.protocols.internet.hip` contains `HIP`
only, which implements extractor for Host Identity
Protocol (HIP), whose structure is described as below.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
| Next Header   | Header Length |0| Packet Type |Version| RES.|1|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|          Checksum             |           Controls            |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                Sender's Host Identity Tag (HIT)               |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|               Receiver's Host Identity Tag (HIT)              |
|                                                               |
|                                                               |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
/                        HIP Parameters                         /
/                                                               /
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
# TODO: Implements extractor of all HIP parameters.


# Host Identity Protocol
# Analyser for HIP header


from jspcap.exceptions import ProtocolError
from jspcap.utilities import Info
from jspcap.protocols.protocol import Protocol


__all__ = ['HIP']


# HIP Packet Types
_HIP_TYPES = {
    0 : 'Reserved',     # [RFC 7401]
    1 : 'I1',           # [RFC 7401] the HIP Initiator Packet
    2 : 'R1',           # [RFC 7401] the HIP Responder Packet
    3 : 'I2',           # [RFC 7401] the Second HIP Initiator Packet
    4 : 'R2',           # [RFC 7401] the Second HIP Responder Packet
   16 : 'UPDATE',       # [RFC 7401] the HIP Update Packet
   17 : 'NOTIFY',       # [RFC 7401] the HIP Notify Packet
   18 : 'CLOSE',        # [RFC 7401] the HIP Association Closing Packet
   19 : 'CLOSE_ACK',    # [RFC 7401] the HIP Closing Acknowledgment Packet
   20 : 'HDRR',         # [RFC 6537] HIP Distributed Hash Table Resource Record
   32 : 'HIP_DATA',     # [RFC 6078]
}


class HIP(Protocol):
    """This class implements Host Identity Protocol.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_hip -- read Host Identity Protocol (HIP)

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
        return 'Host Identity Protocol'

    @property
    def alias(self):
        """Acronym of corresponding procotol."""
        return f'HIPv{self._info.version}'

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

    def read_hip(self, length, extension):
        """Read Host Identity Protocol.

        Structure of HIP header [RFC 7401]:
             0                   1                   2                   3
             0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            | Next Header   | Header Length |0| Packet Type |Version| RES.|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |          Checksum             |           Controls            |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                Sender's Host Identity Tag (HIT)               |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |               Receiver's Host Identity Tag (HIT)              |
            |                                                               |
            |                                                               |
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                                                               |
            /                        HIP Parameters                         /
            /                                                               /
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Discription
              0           0     hip.next                Next Header
              1           8     hip.length              Header Length
              2          16     -                       Reserved (0)
              2          17     hip.type                Packet Type
              3          24     hip.version             Version
              3          28     -                       Reserved
              3          31     -                       Reserved (1)
              4          32     hip.chksum              Checksum
              6          48     hip.control             Controls
              8          64     hip.shit                Sender's Host Identity Tag
              24        192     hip.rhit                Receiver's Host Identity Tag
              40        320     hip.parameters          HIP Parameters

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _type = self._read_binary(1)
        if _type[0] != '0':
            raise ProtocolError('HIP: invalid format')
        _vers = self._read_binary(1)
        if _vers[7] != '1':
            raise ProtocolError('HIP: invalid format')
        _csum = self._read_fileng(2)
        _ctrl = self._read_binary(2)
        _shit = self._read_unpack(16)
        _rhit = self._read_unpack(16)
        _para = self._read_fileng(_hlen - 38)

        hip = dict(
            next = _next,
            length = _hlen + 1,
            type = _HIP_TYPES.get(int(_type[1:], base=2), 'Unassigned'),
            version = int(_vers[:4], base=2),
            chksum = _csum,
            control = dict(
                anonymous = True if int(_ctrl[15], base=2) else False,
            ),
            shit = _shit,
            rhit = _rhit,
            parameters = _para,
        )

        length -= hip['length']
        hip['packet'] = self._read_packet(header=hip['length'], payload=length)

        if extension:
            self._protos = None
            return hip
        return self._decode_next_layer(hip, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._info = Info(self.read_hip(length, extension))

    def __length_hint__(self):
        return 40
