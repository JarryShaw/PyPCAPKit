"""hypertext transfer protocol version 2

``jspcap.protocols.application.httpv2`` contains ``HTTPv2``
only, which implements extractor for Hypertext Transfer
Protocol version 2 (HTTP/2), whose structure is described
as below.

+-----------------------------------------------+
|                 Length (24)                   |
+---------------+---------------+---------------+
|   Type (8)    |   Flags (8)   |
+-+-------------+---------------+-------------------------------+
|R|                 Stream Identifier (31)                      |
+=+=============================================================+
|                   Frame Payload (0...)                      ...
+---------------------------------------------------------------+

"""
# Hypertext Transfer Protocol version 2
# Analyser for HTTP/2 packets


from jspcap.exceptions import ProtocolError
from jspcap.utilities import Info
from jspcap.protocols.application.http import HTTP


class HTTPv2(HTTP):
    """This class implements Hypertext Transfer Protocol version 2.

    Properties:
        * name -- str, name of corresponding procotol
        * info -- Info, info dict of current instance
        * layer -- str, `Application`
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_http -- read Hypertext Transfer Protocol version 2 (HTTP/2)

    Attributes:
        * _file -- BytesIO, bytes to be extracted
        * _info -- Info, info dict of current instance
        * _protos -- ProtoChain, protocol chain of current instance

    Utilities:
        * _read_protos -- read next layer protocol type
        * _read_fileng -- read file buffer
        * _read_unpack -- read bytes and unpack to integers
        * _read_binary -- read bytes and convert into binaries

    """
    ##########################################################################
    # Methods.
    ##########################################################################

    def read_http(self, length):
        """Read Hypertext Transfer Protocol version 2.

        Structure of HTTP/2 packet [RFC 7230]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +=+=============================================================+
            |                   Frame Payload (0...)                      ...
            +---------------------------------------------------------------+

        """
        _plen = self._read_binary(3)
        _type = self._read_unpack(1)
        _flag = self._read_binary(1)
        _stid = self._read_binary(4)
