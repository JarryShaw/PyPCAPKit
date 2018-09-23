# -*- coding: utf-8 -*-
"""root transport layer protocol

`pcapkit.protocols.transport.transport` contains both
`TP_PROTO` and `Transport`. The former is a dictionary
of transport layer protocol numbers, registered in IANA.
And the latter is a base class for transport layer
protocols, eg. TCP and UDP.

"""
from pcapkit._common.tp_proto import TransType as TP_PROTO
from pcapkit.protocols.null import NoPayload
from pcapkit.protocols.protocol import Protocol
from pcapkit.utilities.decorators import beholder_ng

###############################################################################
# from pcapkit.fundation.analysis import analyse
###############################################################################

__all__ = ['Transport', 'TP_PROTO']


class Transport(Protocol):
    """Abstract base class for transport layer protocol family.

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * layer -- str, `Transport`
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
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    __layer__ = 'Transport'

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

    def _import_next_layer(self, proto, length):
        """Import next layer extractor.

        Positional arguments:
            * proto -- str, next layer protocol name
            * length -- int, valid (not padding) length

        Returns:
            * bool -- flag if extraction of next layer succeeded
            * Info -- info of next layer
            * ProtoChain -- protocol chain of next layer
            * str -- alias of next layer

        """
        from pcapkit.foundation.analysis import analyse
        if length == 0:
            next_ = NoPayload()
        elif self._onerror:
            next_ = beholder_ng(analyse)(self._file, length, _termination=self._sigterm)
        else:
            next_ = analyse(self._file, length, _termination=self._sigterm)
        return next_
