# -*- coding: utf-8 -*-
"""root application layer protocol

`pcapkit.protocols.application.application` contains only
`Application`, which is a base class for application
layer protocols, eg. HTTP/1.*, HTTP/2 and etc.

"""
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.exceptions import UnsupportedCall

__all__ = ['Application']


class Application(Protocol):
    """Abstract base class for transport layer protocol family.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Application`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

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
    __layer__ = 'Application'

    ##########################################################################
    # Properties.
    ##########################################################################

    # protocol layer
    @property
    def layer(self):
        """Protocol layer."""
        return self.__layer__

    ##########################################################################
    # Utilities.
    ##########################################################################

    # def _make_protochain(self):
    #     """Make ProtoChain instance for corresponding protocol."""
    #     self._protos = ProtoChain(self.__class__.__name__, None, self.alias)

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Deprecated."""
        raise UnsupportedCall("'{}' object has no attribute '_decode_next_layer'".format(self.__class__.__name__))

    def _import_next_layer(self, proto, length):
        """Deprecated."""
        raise UnsupportedCall("'{}' object has no attribute '_import_next_layer'".format(self.__class__.__name__))
