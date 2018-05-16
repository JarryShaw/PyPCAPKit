# -*- coding: utf-8 -*-
"""IPv6 hop-by-hop options

`jspcap.protocols.internet.hopopt` contains `HOPOPT`
only, which implements extractor for IPv6 Hop-by-Hop
Options header (HOPOPT), whose structure is described
as below.

+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|  Next Header  |  Hdr Ext Len  |                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
|                                                               |
.                                                               .
.                            Options                            .
.                                                               .
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
# TODO: Implements extractor of all hop-by-hop options.


# IPv6 Hop-by-Hop Option
# Analyser for HOPOPT header


from jspcap.utilities import Info
from jspcap.protocols.protocol import Protocol


__all__ = ['HOPOPT']


class HOPOPT(Protocol):
    """This class implements IPv6 Hop-by-Hop Options.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_hopopt -- read IPv6 Hop-by-Hop Options (HOPOPT)

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
        return 'IPv6 Hop-by-Hop Options'

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

    def read_hopopt(self, length, extension):
        """Read IPv6 Hop-by-Hop Options.

        Structure of HOPOPT header [RFC 8200]:
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |  Next Header  |  Hdr Ext Len  |                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
            |                                                               |
            .                                                               .
            .                            Options                            .
            .                                                               .
            |                                                               |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

            Octets      Bits        Name                    Discription
              0           0     hopopt.next             Next Header
              1           8     hopopt.length           Header Extensive Length
              2          16     hopopt.options          Options

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _opts = self._read_fileng(_hlen - 1)

        hopopt = dict(
            next = _next,
            length = _hlen + 1,
            options = _opts,
        )

        length -= hopopt['length']
        hopopt['packet'] = self._read_packet(header=hopopt['length'], payload=length)

        if extension:
            self._protos = None
            return hopopt
        return self._decode_next_layer(hopopt, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._info = Info(self.read_hopopt(length, extension))

    def __length_hint__(self):
        return 2
