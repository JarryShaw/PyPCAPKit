# -*- coding: utf-8 -*-
"""raw packet data

`pcapkit.protocols.raw` contains `Raw` only, which
implements extractor for unknown protocol, and constructs
a `Protocol` like object.

"""
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Raw']


class Raw(Protocol):
    """This class implements universal unknown protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * decode_bytes -- try to decode bytes into str
        * decode_url -- decode URLs into Unicode
        * read_raw -- read raw packet data

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

    # name of current protocol
    @property
    def name(self):
        """Name of current protocol."""
        return 'Unknown'

    # header length of current protocol
    @property
    def length(self):
        """DEPRECATED"""
        raise UnsupportedCall("{!r} object has no attribute 'length'".format(self.__class__.__name__))

    # name of next layer protocol
    @property
    def protocol(self):
        """DEPRECATED"""
        raise UnsupportedCall("{!r} object has no attribute 'protocol'".format(self.__class__.__name__))

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_raw(self, length, *, error=None):
        """Read raw packet data."""
        if length is None:
            length = len(self)

        raw = dict(
            packet=self._read_packet(length),
            error=error or None,
        )

        return raw

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, length=None, *, error=None, **kwargs):
        self._file = file
        self._info = Info(self.read_raw(length, error=error))

        self._next = NoPayload()
        self._protos = ProtoChain(self.__class__, self.alias)

    def __length_hint__(self):
        pass
