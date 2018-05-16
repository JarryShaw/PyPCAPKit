# -*- coding: utf-8 -*-
"""mobility header

`jspcap.protocols.internet.mh` contains `MH` only,
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
# TODO: Implements extractor for message data of all MH types.


# Mobility Header
# Analyser for Mobility Header


from jspcap.utilities import Info
from jspcap.protocols.protocol import Protocol


__all__ = ['MH']


# Mobility Header Types - for the MH Type field in the Mobility Header
_MOBILITY_TYPE = {
    0 : 'Binding Refresh Request',              # [RFC 6275]
    1 : 'Home Test Init',                       # [RFC 6275]
    2 : 'Care-of Test Init',                    # [RFC 6275]
    3 : 'Home Test',                            # [RFC 6275]
    4 : 'Care-of Test',                         # [RFC 6275]
    5 : 'Binding Update',                       # [RFC 6275]
    6 : 'Binding Acknowledgement',              # [RFC 6275]
    7 : 'Binding Error',                        # [RFC 6275]
    8 : 'Fast Binding Update',                  # [RFC 5568]
    9 : 'Fast Binding Acknowledgment',          # [RFC 5568]
   10 : 'Fast Neighbor Advertisement',          # [RFC 5568] DEPRECATED
   11 : 'Experimental Mobility Header',         # [RFC 5096]
   12 : 'Home Agent Switch Message',            # [RFC 5142]
   13 : 'Heartbeat Message',                    # [RFC 5847]
   14 : 'Handover Initiate Message',            # [RFC 5568]
   15 : 'Handover Acknowledge Message',         # [RFC 5568]
   16 : 'Binding Revocation Message',           # [RFC 5846]
   17 : 'Localized Routing Initiation',         # [RFC 6705]
   18 : 'Localized Routing Acknowledgment',     # [RFC 6705]
   19 : 'Update Notification',                  # [RFC 7077]
   20 : 'Update Notification Acknowledgement',  # [RFC 7077]
   21 : 'Flow Binding Message',                 # [RFC 7109]
   22 : 'Subscription Query',                   # [RFC 7161]
   23 : 'Subscription Response',                # [RFC 7161]
}


class MH(Protocol):
    """This class implements Mobility Header.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
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

            Octets      Bits        Name                    Discription
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
        _data = self._read_fileng(_hlen - 5)

        mh = dict(
            next = _next,
            length = _hlen + 1,
            type = _MOBILITY_TYPE.get(_type, 'Unassigned'),
            chksum = _csum,
            data = _data,
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
