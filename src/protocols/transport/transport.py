# -*- coding: utf-8 -*-
"""root transport layer protocol

`jspcap.protocols.transport.transport` contains both
`TP_PROTO` and `Transport`. The former is a dictionary
of transport layer protocol numbers, registered in IANA.
And the latter is a base class for transport layer
protocols, eg. TCP and UDP.

"""
import io

from jspcap.protocols.protocol import Protocol
from jspcap.utilities.decorators import beholder_ng

###############################################################################
# from jspcap.fundation.analysis import analyse
###############################################################################


__all__ = ['Transport', 'TP_PROTO']


# Transport Layer Protocol Numbers
TP_PROTO = {
    # Internet Layer
    1:  'ICMP',     # Internet Control Message Protocol
    2:  'IGMP',     # Internet Group Management Protocol
    4:  'IP',       # IP in IP (encapsulation)
   41:  'IPv6',     # IPv6 Encapsulation
   58:  'ICMPv6',   # ICMP for IPv6

    # IPv6 Extension Header Types
    0:  'HOPOPT',       # IPv6 Hop-by-Hop Option
   43:  'IPv6-Route',   # Routing Header for IPv6
   44:  'IPv6-Frag',    # Fragment Header for IPv6
   50:  'ESP',          # Encapsulating Security Payload
   51:  'AH',           # Authentication Header
   59:  'IPv6-NoNxt',   # No Next Header for IPv6
   60:  'IPv6-Opts',    # Destination Options for IPv6 (before routing / upper-layer header)
  135:  'Mobility',     # Mobility Extension Header for IPv6 (currently without upper-layer header)
  139:  'HIP',          # Host Identity Protocol
  140:  'Shim6',        # Site Multihoming by IPv6 Intermediation

   # Transport Layer
    6:  'TCP',      # Transmission Control Protocol
   17:  'UDP',      # User Datagram Protocol
   89:  'OSPF',     # Open Shortest Path First
  132:  'SCTP',     # Stream Control Transmission Protocol
}


class Transport(Protocol):
    """Abstract base class for transport layer protocol family.

    Properties:
        * name -- str, name of corresponding procotol
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
        from jspcap.foundation.analysis import Analysis
        if self._onerror:
            next_ = beholder_ng(Analysis.analyse)(io.BytesIO(self._read_fileng(length)), length, _termination=self._sigterm)
        else:
            next_ = Analysis.analyse(io.BytesIO(self._read_fileng(length)), length, _termination=self._sigterm)
        return True, next_.info, next_.protochain, next_.alias
