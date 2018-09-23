# -*- coding: utf-8 -*-
"""fragment header for IPv6

`pcapkit.protocols.internet.ipv6_frag` contains `IPv6_Frag`
only, which implements extractor for Fragment Header for
IPv6 (IPv6-Frag), whose structure is described as below.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Identification                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.internet.internet import Internet
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['IPv6_Frag']


class IPv6_Frag(Internet):
    """This class implements Fragment Header for IPv6.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_ipv6_frag -- read Fragment Header for IPv6 (IPv6-Frag)

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
        return 'Fragment Header for IPv6'

    @property
    def alias(self):
        """Acronym of corresponding protocol."""
        return 'IPv6-Frag'

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

    def read_ipv6_frag(self, length, extension):
        """Read Fragment Header for IPv6.

        Structure of IPv6-Frag header [RFC 8200]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |   Reserved    |      Fragment Offset    |Res|M|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |                         Identification                        |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Description
              0           0     frag.next               Next Header
              1           8     -                       Reserved
              2          16     frag.offset             Fragment Offset
              3          29     -                       Reserved
              3          31     frag.mf                 More Flag
              4          32     frag.id                 Identification

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _temp = self._read_fileng(1)
        _offm = self._read_binary(2)
        _ipid = self._read_unpack(4)

        ipv6_frag = dict(
            next=_next,
            length=8,
            offset=int(_offm[:13], base=2),
            mf=True if int(_offm[15], base=2) else False,
            id=_ipid,
        )

        length -= ipv6_frag['length']
        ipv6_frag['packet'] = self._read_packet(header=8, payload=length)

        if extension:
            self._protos = None
            return ipv6_frag
        return self._decode_next_layer(ipv6_frag, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._extf = extension
        self._info = Info(self.read_ipv6_frag(length, extension))

    def __length_hint__(self):
        return 8
