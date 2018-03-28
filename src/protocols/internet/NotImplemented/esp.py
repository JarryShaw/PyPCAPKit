# -*- coding: utf-8 -*-
"""encapsulating security payload

``jspcap.protocols.internet.esp`` contains ``ESP`` only,
which implements Encapsulating Security Payload header
(ESP), whose structure is described as below.

 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
|               Security Parameters Index (SPI)                 | ^Int.
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
|                      Sequence Number                          | |ered
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
|                    Payload Data* (variable)                   | |   ^
~                                                               ~ |   |
|                                                               | |Conf.
+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
|               |     Padding (0-255 bytes)                     | |ered*
+-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
|                               |  Pad Length   | Next Header   | v   v
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
|         Integrity Check Value-ICV   (variable)                |
~                                                               ~
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

"""
# Encapsulating Security Payload
# Analyser for ESP header


from jspcap.utilities import Info
from jspcap.protocols.internet.ipsec import IPsec


__all__ = ['ESP']


class ESP(IPsec):
    """This class implements Encapsulating Security Payload.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding procotol
        * layer -- str, `Internet`
        * length -- int, header length of corresponding protocol
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_esp -- read Encapsulating Security Payload (ESP)

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries
        * _decode_next_layer -- decode next layer protocol type
        * _import_next_layer -- import next layer protocol extractor

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def name(self):
        """Name of corresponding procotol."""
        return 'Encapsulating Security Payload'

    @property
    def length(self):
        """Info dict of current instance."""
        return self._info.length

    @property
    def protocol(self):
        """Name of next layer protocol."""
        return self._info.next

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_esp(self, length, version):
        """Read Encapsulating Security Payload.

        Structure of ESP header [RFC 4303]:

            0                   1                   2                   3
            0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ----
           |               Security Parameters Index (SPI)                 | ^Int.
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |                      Sequence Number                          | |ered
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ | ----
           |                    Payload Data* (variable)                   | |   ^
           ~                                                               ~ |   |
           |                                                               | |Conf.
           +               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |Cov-
           |               |     Padding (0-255 bytes)                     | |ered*
           +-+-+-+-+-+-+-+-+               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ |   |
           |                               |  Pad Length   | Next Header   | v   v
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ ------
           |         Integrity Check Value-ICV   (variable)                |
           ~                                                               ~
           |                                                               |
           +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

        """
        pass

    ##########################################################################
    # Data models.
    ##########################################################################

    def __init__(self, _file, *, version=4):
        self._file = _file
        self._info = Info(self.read_esp(length, version))

    def __len__(self):
        return self._info.length

    def __length_hint__(self):
        return 256
