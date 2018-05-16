# -*- coding: utf-8 -*-
"""hypertext transfer protocol

`jspcap.protocols.application.http` contains `HTTP`
only, which is a base class for Hypertext Transfer
Protocol (HTTP) protocol family, eg. HTTP/1.*, HTTP/2.

"""
import chardet


# Hypertext Transfer Protocol
# Analyser for HTTP request & response


from jspcap.exceptions import UnsupportedCall, ProtocolError
from jspcap.utilities import Info
from jspcap.protocols.application.application import Application


__all__ = ['HTTP']


class HTTP(Application):
    """This class implements all protocols in HTTP family.

    - Hypertext Transfer Protocol (HTTP/1.1) [RFC 7230]
    - Hypertext Transfer Protocol version 2 (HTTP/2) [RFC 7540]

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
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
        * _make_protochain -- make ProtoChain instance for corresponding protocol
        * _http_decode -- test and decode HTTP parameters

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
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, length=None, **kwargs):
        self._file = _file
        self._info = Info(self.read_http(length))
        self._make_protochain()

    @classmethod
    def __index__(cls):
        return ('HTTPv1', 'HTTPv2')

    ##########################################################################
    # Utilities.
    ##########################################################################

    @staticmethod
    def _http_decode(byte):
        charset = chardet.detect(byte)['encoding']
        if charset:
            try:
                return byte.decode(charset)
            except Exception:
                pass
        return byte
