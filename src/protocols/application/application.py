# -*- coding: utf-8 -*-
"""root application layer protocol

`jspcap.protocols.application.application` contains only
`Application`, which is a base class for application
layer protocols, eg. HTTP/1.*, HTTP/2 and etc.

"""
# TODO: Implements BGP, DHCP, DNS, FTP, IMAP, IDAP, MQTT, NNTP, NTP, ONC:RPC, POP, RIP, RTP, SIP, SMTP, SNMP, SSH, SSL, TELNET, TLS, XMPP.


# Application Layer Protocols
# Table of corresponding protocols


from jspcap.exceptions import UnsupportedCall
from jspcap.utilities import ProtoChain
from jspcap.protocols.protocol import Protocol


__all__ = ['Application']


# ##############################################################################
# # for unknown reason and never-encountered situation, at current time
# # we have to change the working directory to import from parent folders
#
# import os
# import sys
# sys.path.insert(1, os.path.join(sys.path[0], '..'))
#
# from protocol import Protocol
#
# del sys.path[1]
#
# # and afterwards, we recover the whole scene back to its original state
# ##############################################################################


class Application(Protocol):
    """Abstract base class for transport layer protocol family.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
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
        * _make_protochain -- make ProtoChain instance for corresponding protocol

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

    def _make_protochain(self):
        """Make ProtoChain instance for corresponding protocol."""
        self._protos = ProtoChain(self.__class__.__name__, None, self.alias)

    def _decode_next_layer(self, dict_, proto=None, length=None):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_decode_next_layer'")

    def _import_next_layer(self, proto, length):
        """Deprecated."""
        raise UnsupportedCall(f"'{self.__class__.__name__}' object has no attribute '_import_next_layer'")
