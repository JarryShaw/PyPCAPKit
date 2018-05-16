# -*- coding: utf-8 -*-
"""destination options for IPv6

`jspcap.protocols.internet.ipv6_opts` contains
`IPv6_Opts` only, which implements extractor for
Destination Options for IPv6 (IPv6-Opts), whose structure
is described as below.

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
# TODO: Implements extractor of all destination options.


# Destination Options for IPv6
# Analyser for IPv6-Opts header


from jspcap.utilities import Info
from jspcap.protocols.protocol import Protocol


__all__ = ['IPv6_Opts']


class IPv6_Opts(Protocol):
    """This class implements Destination Options for IPv6.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_ipv6_opts -- read Destination Options for IPv6 (IPv6-Opts)

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
    def alias(self):
        """Acronym of corresponding procotol."""
        return 'IPv6-Opts'

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

    def read_ipv6_opts(self, length, extension):
        """Read Destination Options for IPv6.

        Structure of IPv6-Opts header [RFC 8200]:
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
              0           0     opt.next                Next Header
              1           8     opt.length              Header Extensive Length
              2          16     opt.options             Options

        """
        if length is None:
            length = len(self)

        _next = self._read_protos(1)
        _hlen = self._read_unpack(1)
        _opts = self._read_fileng(_hlen - 1)

        ipv6_opts = dict(
            next = _next,
            length = _hlen + 1,
            options = _opts,
        )

        if length is not None:
            length -= ipv6_opts['length']
        ipv6_opts['packet'] = self._read_packet(header=ipv6_opts['length'], payload=length)

        if extension:
            self._protos = None
            return ipv6_opts
        return self._decode_next_layer(ipv6_opts, _next, length)

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, *, extension=False, **kwargs):
        self._file = _file
        self._info = Info(self.read_ipv6_opts(length, extension))

    def __length_hint__(self):
        return 2
