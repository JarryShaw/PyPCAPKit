# -*- coding: utf-8 -*-
"""raw packet data

`jspcap.protocols.raw` contains `Raw` only, which
implements extractor for unknown protocol, and constructs
a `Protocol` like object.

"""
# Raw Packet Data
# Analyser for unknown protocol data


from jspcap.exceptions import UnsupportedCall
from jspcap.utilities import Info, ProtoChain
from jspcap.protocols.protocol import Protocol


__all__ = ['Raw']


class Raw(Protocol):
    """This class implements universal unknown procotol.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
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
        * _make_protochain -- make ProtoChain instance for corresponding protocol

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
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'length'")

    # name of next layer protocol
    @property
    def protocol(self):
        """DEPRECATED"""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute 'protocol'")

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_raw(self, length, *, error=None):
        """Read raw packet data."""
        if length is None:
            length = len(self)

        raw = dict(
            packet = self._read_packet(length),
            error = error,
        )

        return raw

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, file, length=None, *, error=None, **kwargs):
        self._file = file
        self._info = Info(self.read_raw(length, error=error))
        self._make_protochain()

    def __length_hint__(self):
        pass

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _make_protochain(self):
        """Make ProtoChain instance for corresponding protocol."""
        self._protos = ProtoChain(self.__class__.__name__, None, self.alias)
