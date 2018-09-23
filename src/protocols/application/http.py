# -*- coding: utf-8 -*-
"""hypertext transfer protocol

`pcapkit.protocols.application.http` contains `HTTP`
only, which is a base class for Hypertext Transfer
Protocol (HTTP) protocol family, eg. HTTP/1.*, HTTP/2.

"""
import chardet
from pcapkit.corekit.infoclass import Info
from pcapkit.corekit.protochain import ProtoChain
from pcapkit.protocols.application.application import Application
from pcapkit.protocols.null import NoPayload
from pcapkit.utilities.exceptions import ProtocolError, UnsupportedCall

__all__ = ['HTTP']


class HTTP(Application):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [RFC 7230]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [RFC 7540]

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Application`
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_http -- read Hypertext Transfer Protocol (HTTP)

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

    @property
    def name(self):
        """Name of current protocol."""
        return 'Hypertext Transfer Protocol'

    @property
    def length(self):
        """Deprecated."""
        raise UnsupportedCall("'{}' object has no attribute 'length'".format(self.__class__.__name__))

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_http(length))

        self._next = NoPayload()
        self._protos = ProtoChain(self.__class__, self.alias)

    @classmethod
    def __index__(cls):
        return ('HTTPv1', 'HTTPv2')
