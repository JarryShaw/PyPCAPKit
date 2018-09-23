"""hypertext transfer protocol (HTTP/2)

`pcapkit.protocols.application.httpv2` contains `HTTPv2`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/2), whose structure is described as below.

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
import collections

from pcapkit._common.http_error_code import ErrCode as _ERROR_CODE
from pcapkit._common.http_para_name import Settings as _PARA_NAME
from pcapkit._common.http_type import PktType as _HTTP_TYPE
from pcapkit.corekit.infoclass import Info
from pcapkit.protocols.application.http import HTTP
from pcapkit.utilities.exceptions import ProtocolError

# TODO: Considering replacing flags with `aenum.IntFlag`.
__all__ = ['HTTPv2']

# HTTP/2 Functions
_HTTP_FUNC = collections.defaultdict(
    lambda self, size, kind, flag: self._read_http_none(size, kind, flag),                      # Unsigned
    {
        0x00: lambda self, size, kind, flag: self._read_http_data(size, kind, flag),            # DATA
        0x01: lambda self, size, kind, flag: self._read_http_headers(size, kind, flag),         # HEADERS
        0x02: lambda self, size, kind, flag: self._read_http_priority(size, kind, flag),        # PRIORITY
        0x03: lambda self, size, kind, flag: self._read_http_rst_stream(size, kind, flag),      # RST_STREAM
        0x04: lambda self, size, kind, flag: self._read_http_settings(size, kind, flag),        # SETTINGS
        0x05: lambda self, size, kind, flag: self._read_http_push_promise(size, kind, flag),    # PUSH_PROMISE
        0x06: lambda self, size, kind, flag: self._read_http_ping(size, kind, flag),            # PING
        0x07: lambda self, size, kind, flag: self._read_http_goaway(size, kind, flag),          # GOAWAY
        0x08: lambda self, size, kind, flag: self._read_http_window_update(size, kind, flag),   # WINDOW_UPDATE
        0x09: lambda self, size, kind, flag: self._read_http_continuation(size, kind, flag),    # CONTINUATION
    }
)


class HTTPv2(HTTP):
    """This class implements Hypertext Transfer Protocol (HTTP/2).

    Properties:
        * name -- str, name of corresponding protocol
        * info -- Info, info dict of current instance
        * alias -- str, acronym of corresponding protocol
        * layer -- str, `Application`
        * protocol -- str, name of next layer protocol
        * protochain -- ProtoChain, protocol chain of current instance

    Methods:
        * read_http -- read Hypertext Transfer Protocol (HTTP/2)

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
        * _read_http_data -- read HTTP/2 DATA frames
        * _read_http_headers -- read HTTP/2 HEADERS frames
        * _read_http_priority -- read HTTP/2 PRIORITY frames
        * _read_http_rst_stream -- read HTTP/2 RST_STREAM frames
        * _read_http_settings -- read HTTP/2 SETTINGS frames
        * _read_http_push_promise -- read HTTP/2 PUSH_PROMISE frames
        * _read_http_ping -- read HTTP/2 PING frames
        * _read_http_goaway -- read HTTP/2 GOAWAY frames
        * _read_http_window_update -- read HTTP/2 WINDOW_UPDATE frames
        * _read_http_continuation -- read HTTP/2 CONTINUATION frames

    """
    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self):
        """Acronym of current protocol."""
        return 'HTTP/2'

    ##########################################################################
    # Methods.
    ##########################################################################

    def read_http(self, length):
        """Read Hypertext Transfer Protocol (HTTP/2).

        Structure of HTTP/2 packet [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +=+=============================================================+
            |                   Frame Payload (0...)                      ...
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.payload            Frame Payload

        """
        if length is None:
            length = len(self)

        if length < 9:
            raise ProtocolError('HTTP/2: invalid format'.format(), quiet=True)

        _tlen = self._read_unpack(3)
        _type = self._read_unpack(1)
        _flag = self._read_binary(1)
        _rsid = self._read_binary(4)

        if _tlen != length:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(_type), quiet=True)

        if int(_rsid[0], base=2):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(_type), quiet=True)

        http = dict(
            length=_tlen,
            type=_HTTP_TYPE.get(_type),
            sid=int(_rsid[1:], base=2),
            packet=self._read_packet(_tlen),
        )

        if http['type'] is None:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(_type), quiet=True)

        if http['type'] in ('SETTINGS', 'PING') and http['sid'] != 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(_type), quiet=True)

        _http = _HTTP_FUNC[_type](self, _tlen, _type, _flag)
        http.update(_http)

        return http

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        return 9

    @classmethod
    def __index__(cls):
        return cls.__name__

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_http_none(self, size, kind, flag):
        """Read HTTP packet with unsigned type."""
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=None,
            payload=self._read_fileng(size - 9) or None,
        )

        return data

    def _read_http_data(self, size, kind, flag):
        """Read HTTP/2 DATA frames.

        Structure of HTTP/2 DATA frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------+-----------------------------------------------+
            |Pad Length? (8)|
            +---------------+-----------------------------------------------+
            |                            Data (*)                         ...
            +---------------------------------------------------------------+
            |                           Padding (*)                       ...
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (0)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.pad_len            Pad Length (Optional)
              10         80     http.data               Data
              ?           ?     -                       Padding (Optional)

        """
        _plen = 0
        _flag = dict(
            END_STREAM=False,   # bit 0
            PADDED=False,       # bit 3
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['END_STREAM'] = True
            elif index == 3 and bit:
                _flag['PADDED'] = True
                _plen = self._read_unpack(1)
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        if _plen > size - 10:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        if _flag['PADDED']:
            _dlen = size - _plen - 1
        else:
            _dlen = size - _plen
        if _dlen < 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _data = self._read_fileng(_dlen)

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=_flag,
            data=_data,
        )
        if _flag['PADDED']:
            data['ped_len'] = _plen

        return data

    def _read_http_headers(self, size, kind, flag):
        """Read HTTP/2 HEADERS frames.

        Structure of HTTP/2 HEADERS frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------+-----------------------------------------------+
            |Pad Length? (8)|
            +-+-------------+-----------------------------------------------+
            |E|                 Stream Dependency? (31)                     |
            +-+-------------+-----------------------------------------------+
            |  Weight? (8)  |
            +-+-------------+-----------------------------------------------+
            |                   Header Block Fragment (*)                 ...
            +---------------------------------------------------------------+
            |                           Padding (*)                       ...
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (1)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.pad_len            Pad Length (Optional)
              10         80     http.exclusive          Exclusive Flag
              10         81     http.deps               Stream Dependency (Optional)
              14        112     http.weight             Weight (Optional)
              15        120     http.frag               Header Block Fragment
              ?           ?     -                       Padding (Optional)

        """
        _plen = 0
        _elen = 0
        _flag = dict(
            END_STREAM=False,       # bit 0
            END_HEADERS=False,      # bit 2
            PADDED=False,           # bit 3
            PRIORITY=False,         # bit 5
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['END_STREAM'] = True
            elif index == 2 and bit:
                _flag['END_HEADERS'] = True
            elif index == 3 and bit:
                _flag['PADDED'] = True
                _plen = self._read_unpack(1)
            elif index == 5 and bit:
                _flag['PRIORITY'] = True
                _edep = self._read_binary(4)
                _wght = self._read_unpack(1)
                _elen = 5
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        if _flag['PADDED']:
            _dlen = size - _plen - _elen - 1
        else:
            _dlen = size - _plen - _elen
        if _dlen < 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _frag = self._read_fileng(_dlen) or None

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=_flag,
            frag=_frag,
        )
        if _flag['PADDED']:
            data['ped_len'] = _plen
        if _flag['PRIORITY']:
            data['exclusive'] = True if int(_edep[0], base=2) else False
            data['deps'] = int(_edep[1:], base=2)
            data['weight'] = _wght + 1

        return data

    def _read_http_priority(self, size, kind, flag):
        """Read HTTP/2 PRIORITY frames.

        Structure of HTTP/2 PRIORITY frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +-+-------------------------------------------------------------+
            |E|                  Stream Dependency (31)                     |
            +-+-------------+-----------------------------------------------+
            |   Weight (8)  |
            +-+-------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.exclusive          Exclusive Flag
              9          73     http.deps               Stream Dependency
              13        104     http.weight             Weight

        """
        if size != 9:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _edep = self._read_binary(4)
        _wght = self._read_unpack(1)

        data = dict(
            flags=None,
            exclusive=True if int(_edep[0], base=2) else False,
            deps=int(_edep[1:], base=2),
            weight=_wght + 1,
        )

        return data

    def _read_http_rst_stream(self, size, kind, flag):
        """Read HTTP/2 RST_STREAM frames.

        Structure of HTTP/2 RST_STREAM frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |                        Error Code (32)                        |
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.error              Error Code

        """
        if size != 8:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _code = self._read_unpack(4)

        data = dict(
            flags=None,
            error=_ERROR_CODE.get(_code, _code),
        )

        return data

    def _read_http_settings(self, size, kind, flag):
        """Read HTTP/2 SETTINGS frames.

        Structure of HTTP/2 SETTINGS frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |       Identifier (16)         |
            +-------------------------------+-------------------------------+
            |                        Value (32)                             |
            +---------------------------------------------------------------+
            |                          ......                               |

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.settings           Settings
              9          72     http.settings.id        Identifier
              10         80     http.settings.value     Value

        """
        if size % 5 != 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _flag = dict(
            ACK=False,      # bit 0
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['ACK'] = True
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        if _flag['ACK'] and size:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _para = dict()
        counter = 0
        while counter < size:
            _stid = self._read_unpack(1)
            _pval = self._read_unpack(4)
            _pkey = _PARA_NAME.get(_stid, 'Unsigned')
            if _pkey in _para:
                if isinstance(_para[_pkey], tuple):
                    _para[_pkey] += (_pval,)
                else:
                    _para[_pkey] = (_para[_pkey], _pval)
            else:
                _para[_pkey] = _pval

        data = dict(
            flags=_flag,
        )
        data.update(_para)

        return data

    def _read_http_push_promise(self, size, kind, flag):
        """Read HTTP/2 PUSH_PROMISE frames.

        Structure of HTTP/2 PUSH_PROMISE frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------+-----------------------------------------------+
            |Pad Length? (8)|
            +-+-------------+-----------------------------------------------+
            |R|                  Promised Stream ID (31)                    |
            +-+-----------------------------+-------------------------------+
            |                   Header Block Fragment (*)                 ...
            +---------------------------------------------------------------+
            |                           Padding (*)                       ...
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (1)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.pad_len            Pad Length (Optional)
              10         80     -                       Reserved
              10         81     http.pid                Promised Stream ID
              14        112     http.frag               Header Block Fragment
              ?           ?     -                       Padding (Optional)

        """
        if size < 4:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _plen = 0
        _flag = dict(
            END_HEADERS=False,      # bit 2
            PADDED=False,           # bit 3
        )
        for index, bit in enumerate(flag):
            if index == 2 and bit:
                _flag['END_HEADERS'] = True
            elif index == 3 and bit:
                _flag['PADDED'] = True
                _plen = self._read_unpack(1)
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        if _flag['PADDED']:
            _dlen = size - _plen - 5
        else:
            _dlen = size - _plen - 4
        if _dlen < 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _rpid = self._read_binary(4)
        _frag = self._read_fileng(_dlen) or None

        if int(_rpid[0], base=2):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=_flag,
            pid=int(_rpid[1:], base=2),
            frag=_frag,
        )
        if _flag['PADDED']:
            data['ped_len'] = _plen

        return data

    def _read_http_ping(self, size, kind, flag):
        """Read HTTP/2 PING frames.

        Structure of HTTP/2 PING frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |                                                               |
            |                      Opaque Data (64)                         |
            |                                                               |
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     http.data               Opaque Data

        """
        if size != 8:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _flag = dict(
            ACK=False,      # bit 0
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['ACK'] = True
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        _data = self._read_fileng(8)

        data = dict(
            flags=_flag,
            data=_data,
        )

        return data

    def _read_http_goaway(self, size, kind, flag):
        """Read HTTP/2 GOAWAY frames.

        Structure of HTTP/2 GOAWAY frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +-+-------------+---------------+-------------------------------+
            |R|                  Last-Stream-ID (31)                        |
            +-+-------------------------------------------------------------+
            |                      Error Code (32)                          |
            +---------------------------------------------------------------+
            |                  Additional Debug Data (*)                    |
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     -                       Reserved
              9          73     http.last_sid           Last Stream ID
              13        104     http.error              Error Code
              17        136     http.data               Additional Debug Data (Optional)

        """
        _dlen = size - 8
        if _dlen < 0:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _rsid = self._read_binary(4)
        _code = self._read_unpack(4)
        _data = self._read_fileng(_dlen) or None

        if int(_rsid[0], base=2):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=None,
            last_sid=int(_rsid[1:], base=2),
            error=_ERROR_CODE.get(_code, _code),
            data=_data,
        )

        return data

    def _read_http_window_update(self, size, kind, flag):
        """Read HTTP/2 WINDOW_UPDATE frames.

        Structure of HTTP/2 WINDOW_UPDATE frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +-+-------------+---------------+-------------------------------+
            |R|              Window Size Increment (31)                     |
            +-+-------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          72     -                       Reserved
              9          73     http.window             Window Size Increment

        """
        if size != 4:
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        _size = self._read_binary(4)

        if int(_size[0], base=2):
            raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)

        data = dict(
            flags=None,
            window=int(_size[1:], base=2),
        )

        return data

    def _read_http_continuation(self, size, kind, flag):
        """Read HTTP/2 WINDOW_UPDATE frames.

        Structure of HTTP/2 WINDOW_UPDATE frame [RFC 7540]:
            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |                   Header Block Fragment (*)                 ...
            +---------------------------------------------------------------+

            Octets      Bits        Name                    Description
              0           0     http.length             Length
              3          24     http.type               Type (2)
              4          32     http.flags              Flags
              5          40     -                       Reserved
              5          41     http.sid                Stream Identifier
              9          73     http.frag               Header Block Fragment

        """
        _flag = dict(
            END_HEADERS=False,      # bit 2
        )
        for index, bit in enumerate(flag):
            if index == 2 and bit:
                _flag['END_HEADERS'] = True
            elif bit:
                raise ProtocolError('HTTP/2: [Type {}] invalid format'.format(kind), quiet=True)
            else:
                continue

        _frag = self._read_fileng(size) or None

        data = dict(
            flags=_flag,
            frag=_frag,
        )

        return data
