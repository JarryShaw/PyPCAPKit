# -*- coding: utf-8 -*-
"""hypertext transfer protocol (HTTP/2)

:mod:`pcapkit.protocols.application.httpv2` contains
:class:`~pcapkit.protocols.application.httpv2.HTTPv2`
only, which implements extractor for Hypertext Transfer
Protocol (HTTP/2) [*]_, whose structure is described as
below:

======= ========= ===================== ==========================
Octets      Bits        Name                    Description
======= ========= ===================== ==========================
  0           0   ``http.length``             Length
  3          24   ``http.type``               Type
  4          32   ``http.flags``              Flags
  5          40                               Reserved
  5          41   ``http.sid``                Stream Identifier
  9          72   ``http.payload``            Frame Payload
======= ========= ===================== ==========================

.. [*] https://en.wikipedia.org/wiki/HTTP/2

"""
# pylint: disable=protected-access
import collections

from pcapkit.const.http.error_code import ErrorCode as _ERROR_CODE
from pcapkit.const.http.frame import Frame as _HTTP_TYPE
from pcapkit.const.http.setting import Setting as _PARA_NAME
from pcapkit.protocols.application.http import HTTP
from pcapkit.utilities.exceptions import ProtocolError

__all__ = ['HTTPv2']

#: HTTP/2 functions.
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
    """This class implements Hypertext Transfer Protocol (HTTP/2)."""

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self):
        """Acronym of current protocol.

        :rtype: Literal['HTTP/2']
        """
        return 'HTTP/2'

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length=None, **kwargs):  # pylint: disable=unused-argument
        """Read Hypertext Transfer Protocol (HTTP/2).

        Structure of HTTP/2 packet [:rfc:`7540`]::

            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +=+=============================================================+
            |                   Frame Payload (0...)                      ...
            +---------------------------------------------------------------+

        Args:
            length (Optional[int]): Length of packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            DataType_HTTPv2: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        if length < 9:
            raise ProtocolError('HTTP/2: invalid format', quiet=True)

        _tlen = self._read_unpack(3)
        _type = self._read_unpack(1)
        _flag = self._read_binary(1)
        _rsid = self._read_binary(4)

        if _tlen != length:
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format', quiet=True)

        if int(_rsid[0], base=2):
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format', quiet=True)

        http = dict(
            length=_tlen,
            type=_HTTP_TYPE.get(_type),
            sid=int(_rsid[1:], base=2),
            packet=self._read_packet(_tlen),
        )

        if http['type'] is None:
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format', quiet=True)

        if http['type'] in ('SETTINGS', 'PING') and http['sid'] != 0:
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format', quiet=True)

        _http = _HTTP_FUNC[_type](self, _tlen, _type, _flag)
        http.update(_http)

        return http

    def make(self, **kwargs):
        """Make (construct) packet data.

        Keyword Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            bytes: Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls):
        """Index ID of the protocol.

        Returns:
            Literal['HTTPv2']: Index ID of the protocol.

        """
        return cls.__name__

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self):
        """Total length of corresponding protocol.

        :rtype: Literal[9]
        """
        return 9

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_http_none(self, size, kind, flag):
        """Read HTTP packet with unassigned type.

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_Unassigned: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=None,
            payload=self._read_fileng(size - 9) or None,
        )

        return data

    def _read_http_data(self, size, kind, flag):
        """Read HTTP/2 ``DATA`` frames.

        Structure of HTTP/2 ``DATA`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_DATA: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

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
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        if _plen > size - 10:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        if _flag['PADDED']:
            _dlen = size - _plen - 1
        else:
            _dlen = size - _plen
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _data = self._read_fileng(_dlen)

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=_flag,
            data=_data,
        )
        if _flag['PADDED']:
            data['ped_len'] = _plen

        return data

    def _read_http_headers(self, size, kind, flag):
        """Read HTTP/2 ``HEADERS`` frames.

        Structure of HTTP/2 ``HEADERS`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_HEADERS: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

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
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        if _flag['PADDED']:
            _dlen = size - _plen - _elen - 1
        else:
            _dlen = size - _plen - _elen
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _frag = self._read_fileng(_dlen) or None

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=_flag,
            frag=_frag,
        )
        if _flag['PADDED']:
            data['pad_len'] = _plen
        if _flag['PRIORITY']:
            data['exclusive'] = bool(int(_edep[0], base=2))
            data['deps'] = int(_edep[1:], base=2)
            data['weight'] = _wght + 1

        return data

    def _read_http_priority(self, size, kind, flag):
        """Read HTTP/2 ``PRIORITY`` frames.

        Structure of HTTP/2 ``PRIORITY`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_PRIORITY: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size != 9:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _edep = self._read_binary(4)
        _wght = self._read_unpack(1)

        data = dict(
            flags=None,
            exclusive=bool(int(_edep[0], base=2)),
            deps=int(_edep[1:], base=2),
            weight=_wght + 1,
        )

        return data

    def _read_http_rst_stream(self, size, kind, flag):
        """Read HTTP/2 ``RST_STREAM`` frames.

        Structure of HTTP/2 ``RST_STREAM`` frame [:rfc:`7540`]::

            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |                        Error Code (32)                        |
            +---------------------------------------------------------------+

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_RST_STREAM: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size != 8:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _code = self._read_unpack(4)

        data = dict(
            flags=None,
            error=_ERROR_CODE.get(_code, _code),
        )

        return data

    def _read_http_settings(self, size, kind, flag):
        """Read HTTP/2 ``SETTINGS`` frames.

        Structure of HTTP/2 ``SETTINGS`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_SETTINGS: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size % 5 != 0:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _flag = dict(
            ACK=False,      # bit 0
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['ACK'] = True
            elif bit:
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        if _flag['ACK'] and size:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _list = list()
        _para = dict()
        counter = 0
        while counter < size:
            _stid = self._read_unpack(1)
            _pval = self._read_unpack(4)
            _pkey = _PARA_NAME.get(_stid, 'Unsigned')

            _name = _pkey.name
            if _pkey in _para:
                if isinstance(_para[_name], tuple):
                    _para[_name] += (_pval,)
                else:
                    _para[_name] = (_para[_name], _pval)
            else:
                _para[_name] = _pval
                _list.append(_pkey)

        data = dict(
            flags=_flag,
            settings=tuple(_pkey),
        )
        data.update(_para)

        return data

    def _read_http_push_promise(self, size, kind, flag):
        """Read HTTP/2 ``PUSH_PROMISE`` frames.

        Structure of HTTP/2 ``PUSH_PROMISE`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_PUSH_PROMISE: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size < 4:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

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
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        if _flag['PADDED']:
            _dlen = size - _plen - 5
        else:
            _dlen = size - _plen - 4
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _rpid = self._read_binary(4)
        _frag = self._read_fileng(_dlen) or None

        if int(_rpid[0], base=2):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        padding = self._read_binary(_plen)
        if any((int(bit, base=2) for bit in padding)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=_flag,
            pid=int(_rpid[1:], base=2),
            frag=_frag,
        )
        if _flag['PADDED']:
            data['pad_len'] = _plen

        return data

    def _read_http_ping(self, size, kind, flag):
        """Read HTTP/2 ``PING`` frames.

        Structure of HTTP/2 ``PING`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_PING: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size != 8:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _flag = dict(
            ACK=False,      # bit 0
        )
        for index, bit in enumerate(flag):
            if index == 0 and bit:
                _flag['ACK'] = True
            elif bit:
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        _data = self._read_fileng(8)

        data = dict(
            flags=_flag,
            data=_data,
        )

        return data

    def _read_http_goaway(self, size, kind, flag):
        """Read HTTP/2 ``GOAWAY`` frames.

        Structure of HTTP/2 ``GOAWAY`` frame [:rfc:`7540`]::

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

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_GOAWAY: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _dlen = size - 8
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _rsid = self._read_binary(4)
        _code = self._read_unpack(4)
        _data = self._read_fileng(_dlen) or None

        if int(_rsid[0], base=2):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=None,
            last_sid=int(_rsid[1:], base=2),
            error=_ERROR_CODE.get(_code, _code),
            data=_data,
        )

        return data

    def _read_http_window_update(self, size, kind, flag):
        """Read HTTP/2 ``WINDOW_UPDATE`` frames.

        Structure of HTTP/2 ``WINDOW_UPDATE`` frame [:rfc:`7540`]::

            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +-+-------------+---------------+-------------------------------+
            |R|              Window Size Increment (31)                     |
            +-+-------------------------------------------------------------+

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_WINDOW_UPDATE: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if size != 4:
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
        if any((int(bit, base=2) for bit in flag)):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        _size = self._read_binary(4)

        if int(_size[0], base=2):
            raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)

        data = dict(
            flags=None,
            window=int(_size[1:], base=2),
        )

        return data

    def _read_http_continuation(self, size, kind, flag):
        """Read HTTP/2 ``CONTINUATION`` frames.

        Structure of HTTP/2 ``CONTINUATION`` frame [:rfc:`7540`]::

            +-----------------------------------------------+
            |                 Length (24)                   |
            +---------------+---------------+---------------+
            |   Type (8)    |   Flags (8)   |
            +-+-------------+---------------+-------------------------------+
            |R|                 Stream Identifier (31)                      |
            +---------------------------------------------------------------+
            |                   Header Block Fragment (*)                 ...
            +---------------------------------------------------------------+

        Args:
            size (int): length of packet data
            kind (int): packet type
            flag (str): packet flags (8 bits)

        Returns:
            DataType_HTTPv2_CONTINUATION: Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _flag = dict(
            END_HEADERS=False,      # bit 2
        )
        for index, bit in enumerate(flag):
            if index == 2 and bit:
                _flag['END_HEADERS'] = True
            elif bit:
                raise ProtocolError(f'HTTP/2: [Type {kind}] invalid format', quiet=True)
            else:
                continue

        _frag = self._read_fileng(size) or None

        data = dict(
            flags=_flag,
            frag=_frag,
        )

        return data
