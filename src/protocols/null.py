# -*- coding: utf-8 -*-
"""no-payload packet

`pcapkit.protocols.null` contains `NoPayload` only, which
implements a `Protocol` like object whose payload is
recursively `NoPayload` itself.

"""
import io

from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['NoPayload']


class NoPayload(Protocol):
    """This class implements no-payload protocol.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol

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

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    # name of current protocol
    @property
    def name(self):
        """Name of current protocol."""
        return 'Null'

    # header length of current protocol
    @property
    def length(self):
        """DEPRECATED"""
        raise UnsupportedCall("'{}' object has no attribute 'length'".format(self.__class__.__name__))

    # name of next layer protocol
    @property
    def protocol(self):
        """DEPRECATED"""
        raise UnsupportedCall("'{}' object has no attribute 'protocol'".format(self.__class__.__name__))

    ##########################################################################
    # Data models.
    ##########################################################################

    def __new__(cls, *args, **kwargs):
        self = super().__new__(cls)
        return self

    def __init__(self, *args, **kwargs):
        self._next = self
        self._info = Info()
        self._file = io.BytesIO()
        self._protos = ProtoChain()

    def __length_hint__(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Deprecated."""
        raise UnsupportedCall("'{}' object has no attribute '_decode_next_layer'".format(self.__class__.__name__))

    def _import_next_layer(self, proto, length):
        """Deprecated."""
        raise UnsupportedCall("'{}' object has no attribute '_import_next_layer'".format(self.__class__.__name__))
