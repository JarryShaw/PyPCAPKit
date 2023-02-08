# -*- coding: utf-8 -*-
"""HTTP/2 - Hypertext Transfer Protocol
==========================================

:mod:`pcapkit.protocols.application.httpv2` contains
:class:`~pcapkit.protocols.application.httpv2.HTTP`
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
import collections
from typing import TYPE_CHECKING

from pcapkit.const.http.error_code import ErrorCode as Enum_ErrorCode
from pcapkit.const.http.frame import Frame as Enum_Frame
from pcapkit.const.http.setting import Setting as Enum_Setting
from pcapkit.corekit.multidict import OrderedMultiDict
from pcapkit.protocols.application.http import HTTP as HTTPBase
from pcapkit.protocols.data.application.httpv2 import HTTP as Data_HTTP
from pcapkit.protocols.data.application.httpv2 import ContinuationFrame as Data_ContinuationFrame
from pcapkit.protocols.data.application.httpv2 import \
    ContinuationFrameFlags as Data_ContinuationFrameFlags
from pcapkit.protocols.data.application.httpv2 import DataFrame as Data_DataFrame
from pcapkit.protocols.data.application.httpv2 import DataFrameFlags as Data_DataFrameFlags
from pcapkit.protocols.data.application.httpv2 import GoawayFrame as Data_GoawayFrame
from pcapkit.protocols.data.application.httpv2 import HeadersFrame as Data_HeadersFrame
from pcapkit.protocols.data.application.httpv2 import HeadersFrameFlags as Data_HeadersFrameFlags
from pcapkit.protocols.data.application.httpv2 import PingFrame as Data_PingFrame
from pcapkit.protocols.data.application.httpv2 import PingFrameFlags as Data_PingFrameFlags
from pcapkit.protocols.data.application.httpv2 import PriorityFrame as Data_PriorityFrame
from pcapkit.protocols.data.application.httpv2 import PushPromiseFrame as Data_PushPromiseFrame
from pcapkit.protocols.data.application.httpv2 import \
    PushPromiseFrameFlags as Data_PushPromiseFrameFlags
from pcapkit.protocols.data.application.httpv2 import RstStreamFrame as Data_RstStreamFrame
from pcapkit.protocols.data.application.httpv2 import SettingsFrame as Data_SettingsFrame
from pcapkit.protocols.data.application.httpv2 import SettingsFrameFlags as Data_SettingsFrameFlags
from pcapkit.protocols.data.application.httpv2 import UnassignedFrame as Data_UnassignedFrame
from pcapkit.protocols.data.application.httpv2 import WindowUpdateFrame as Data_WindowUpdateFrame
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Any, Callable, DefaultDict, NoReturn, Optional

    from typing_extensions import Literal

    FrameParser = Callable[['HTTP', Enum_Frame, int, str, int], Data_HTTP]

__all__ = ['HTTP']


class HTTP(HTTPBase[Data_HTTP]):
    """This class implements Hypertext Transfer Protocol (HTTP/2).

    This class currently supports parsing of the following HTTP/2 frames,
    which are directly mapped to the :class:`pcapkit.const.http.frame.Frame`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Frame Code
         - Frame Parser
       * - :attr:`~pcapkit.const.http.frame.Frame.DATA`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_data`
       * - :attr:`~pcapkit.const.http.frame.Frame.HEADERS`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_headers`
       * - :attr:`~pcapkit.const.http.frame.Frame.PRIORITY`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_priority`
       * - :attr:`~pcapkit.const.http.frame.Frame.RST_STREAM`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_rst_stream`
       * - :attr:`~pcapkit.const.http.frame.Frame.SETTINGS`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_settings`
       * - :attr:`~pcapkit.const.http.frame.Frame.PUSH_PROMISE`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_push_promise`
       * - :attr:`~pcapkit.const.http.frame.Frame.PING`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_ping`
       * - :attr:`~pcapkit.const.http.frame.Frame.GOAWAY`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_goaway`
       * - :attr:`~pcapkit.const.http.frame.Frame.WINDOW_UPDATE`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_window_update`
       * - :attr:`~pcapkit.const.http.frame.Frame.CONTINUATION`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_continuation`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Frame, str | FrameParser]: Frame code to method
    #: mapping, c.f. :meth:`read`. Method names are expected to be referred to
    #: the class by ``_read_http_${name}``, and if such name not found, the
    #: value should then be a method that can parse the frame by itself.
    __frame__ = collections.defaultdict(
        lambda: 'none',
        {
            Enum_Frame.DATA: 'data',                    # DATA
            Enum_Frame.HEADERS: 'headers',              # HEADERS
            Enum_Frame.PRIORITY: 'priority',            # PRIORITY
            Enum_Frame.RST_STREAM: 'rst_stream',        # RST_STREAM
            Enum_Frame.SETTINGS: 'settings',            # SETTINGS
            Enum_Frame.PUSH_PROMISE: 'push_promise',    # PUSH_PROMISE
            Enum_Frame.PING: 'ping',                    # PING
            Enum_Frame.GOAWAY: 'goaway',                # GOAWAY
            Enum_Frame.WINDOW_UPDATE: 'window_update',  # WINDOW_UPDATE
            Enum_Frame.CONTINUATION: 'continuation',    # CONTINUATION
        },
    )  # type: DefaultDict[int, str | FrameParser]

    ##########################################################################
    # Properties.
    ##########################################################################

    @property
    def alias(self) -> 'Literal["HTTP/2"]':
        """Acronym of current protocol."""
        return 'HTTP/2'

    @property
    def length(self) -> 'Literal[9]':
        """Header length of current protocol."""
        return 9

    @property
    def version(self) -> 'Literal["2"]':
        """Version of current protocol."""
        return '2'

    ##########################################################################
    # Methods.
    ##########################################################################

    def read(self, length: 'Optional[int]' = None, **kwargs: 'Any') -> 'Data_HTTP':
        """Read Hypertext Transfer Protocol (HTTP/2).

        Structure of HTTP/2 packet [:rfc:`7540`]:

        .. code-block:: text

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
            length: Length of packet data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length is None:
            length = len(self)

        if length < 9:
            raise ProtocolError('HTTP/2: invalid format')

        _tlen = self._read_unpack(3)
        _type = self._read_unpack(1)
        _flag = self._read_binary(1)
        _rsid = self._read_binary(4)

        if _tlen != length:
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format')

        http_type = Enum_Frame.get(_type)
        http_sid = int(_rsid[1:], base=2)

        if http_type in (Enum_Frame.SETTINGS, Enum_Frame.PING) and http_sid != 0:
            raise ProtocolError(f'HTTP/2: [Type {_type}] invalid format')

        name = self.__frame__[http_type]  # type: str | FrameParser
        if isinstance(name, str):
            meth_name = f'_read_http_{name}'
            meth = getattr(
                self, meth_name,
                self._read_http_none
            )  # type: Callable[[Enum_Frame, int, str, int], Data_HTTP]
            http = meth(http_type, length, _flag, http_sid)
        else:
            http = name(self, http_type, length, _flag, http_sid)

        return http

    def make(self, **kwargs: 'Any') -> 'NoReturn':
        """Make (construct) packet data.

        Args:
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        raise NotImplementedError

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTP"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return (cls.__name__,)  # type: ignore[return-value]

    @classmethod
    def register_frame(cls, code: 'Enum_Frame', meth: 'str | FrameParser') -> 'None':
        """Register a frame parser.

        Args:
            code: HTTP frame type code.
            meth: Method name or callable to parse the frame.

        """
        cls.__frame__[code] = meth

    ##########################################################################
    # Data models.
    ##########################################################################

    def __length_hint__(self) -> 'Literal[9]':
        """Total length of corresponding protocol."""
        return 9

    ##########################################################################
    # Utilities.
    ##########################################################################

    def _read_http_none(self, frame: 'Enum_Frame', length: 'int',
                        flags: 'str', sid: 'int') -> 'Data_UnassignedFrame':
        """Read HTTP packet with unassigned type.

        Args:
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if any((int(bit, base=2) for bit in flags)):
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        data = Data_UnassignedFrame(
            length=length,
            type=frame,
            flags=None,
            sid=sid,
            data=self._read_fileng(length - 9) or None,
        )

        return data

    def _read_http_data(self, frame: 'Enum_Frame', length: 'int', flags: 'str', sid: 'int') -> 'Data_DataFrame':
        """Read HTTP/2 ``DATA`` frames.

        Structure of HTTP/2 ``DATA`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _flag = Data_DataFrameFlags(
            END_STREAM=bool(int(flags[0], base=2)),  # bit 0
            PADDED=bool(int(flags[3], base=2)),      # bit 3
        )

        if _flag.PADDED:
            _plen = self._read_unpack(1)
        else:
            _plen = 0

        if _plen > length - 10:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        if _flag.PADDED:
            _dlen = length - _plen - 1
        else:
            _dlen = length - _plen
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _data = self._read_fileng(_dlen)
        _pads = self._read_binary(_plen)

        data = Data_DataFrame(
            length=length,
            type=frame,
            flags=_flag,
            pad_len=_plen,
            sid=sid,
            data=_data,
        )

        return data

    def _read_http_headers(self, frame: 'Enum_Frame', length: 'int',
                           flags: 'str', sid: 'int') -> 'Data_HeadersFrame':
        """Read HTTP/2 ``HEADERS`` frames.

        Structure of HTTP/2 ``HEADERS`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _flag = Data_HeadersFrameFlags(
            END_STREAM=bool(int(flags[0], base=2)),       # bit 0
            END_HEADERS=bool(int(flags[2], base=2)),      # bit 2
            PADDED=bool(int(flags[3], base=2)),           # bit 3
            PRIORITY=bool(int(flags[5], base=2)),         # bit 5
        )

        if _flag.PRIORITY:
            _edep = self._read_binary(4)
            _wght = self._read_unpack(1)
            _elen = 5
            _excl = bool(int(_edep[0], base=2))
            _deps = int(_edep[1:], base=2)
        else:
            _edep = _wght = _excl = _deps = None  # type: ignore[assignment]
            _elen = 0

        if _flag.PADDED:
            _plen = self._read_unpack(1)
            _dlen = length - _plen - _elen - 1
        else:
            _plen = 0
            _dlen = length - _plen - _elen

        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _frag = self._read_fileng(_dlen) or None
        _pads = self._read_binary(_plen)

        data = Data_HeadersFrame(
            length=length,
            type=frame,
            flags=_flag,
            pad_len=_plen,
            sid=sid,
            excl_dependency=_excl,
            stream_dependency=_deps,
            weight=_wght,
            fragment=_frag,
        )

        return data

    def _read_http_priority(self, frame: 'Enum_Frame', length: 'int',
                            flags: 'str', sid: 'int') -> 'Data_PriorityFrame':  # pylint: disable=unused-argument
        """Read HTTP/2 ``PRIORITY`` frames.

        Structure of HTTP/2 ``PRIORITY`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length != 9:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _edep = self._read_binary(4)
        _wght = self._read_unpack(1)

        data = Data_PriorityFrame(
            length=length,
            type=frame,
            flags=None,
            sid=sid,
            excl_dependency=bool(int(_edep[0], base=2)),
            stream_dependency=int(_edep[1:], base=2),
            weight=_wght + 1,
        )

        return data

    def _read_http_rst_stream(self, frame: 'Enum_Frame', length: 'int',
                              flags: 'str', sid: 'int') -> 'Data_RstStreamFrame':  # pylint: disable=unused-argument
        """Read HTTP/2 ``RST_STREAM`` frames.

        Structure of HTTP/2 ``RST_STREAM`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length != 4:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _code = self._read_unpack(4)

        data = Data_RstStreamFrame(
            length=length,
            type=frame,
            flags=None,
            sid=sid,
            error=Enum_ErrorCode.get(_code, _code),
        )

        return data

    def _read_http_settings(self, frame: 'Enum_Frame', length: 'int',
                            flags: 'str', sid: 'int') -> 'Data_SettingsFrame':
        """Read HTTP/2 ``SETTINGS`` frames.

        Structure of HTTP/2 ``SETTINGS`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length % 6 != 0 or sid != 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _flag = Data_SettingsFrameFlags(
            ACK=bool(int(flags[0], base=2)),  # bit 0
        )

        if _flag.ACK and length != 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _sets = OrderedMultiDict()  # type: OrderedMultiDict[Enum_Setting, int]
        for _ in range(length // 6):
            _stid = self._read_unpack(2)
            _pval = self._read_unpack(4)

            _pkey = Enum_Setting.get(_stid)
            _sets.add(_pkey, _pval)

        data = Data_SettingsFrame(
            length=length,
            type=frame,
            flags=_flag,
            sid=sid,
            settings=_sets,
        )

        return data

    def _read_http_push_promise(self, frame: 'Enum_Frame', length: 'int',
                                flags: 'str', sid: 'int') -> 'Data_PushPromiseFrame':
        """Read HTTP/2 ``PUSH_PROMISE`` frames.

        Structure of HTTP/2 ``PUSH_PROMISE`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length < 4:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _flag = Data_PushPromiseFrameFlags(
            END_HEADERS=bool(int(flags[2], base=2)),  # bit 2
            PADDED=bool(int(flags[3], base=2)),       # bit 3
        )

        if _flag.PADDED:
            _plen = self._read_unpack(1)
            _dlen = length - _plen - 5
        else:
            _plen = 0
            _dlen = length - _plen - 4

        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _rpid = self._read_binary(4)
        _frag = self._read_fileng(_dlen) or None
        _pads = self._read_binary(_plen)

        data = Data_PushPromiseFrame(
            length=length,
            type=frame,
            flags=_flag,
            sid=sid,
            pad_len=_plen,
            promised_sid=int(_rpid[1:], base=2),
            fragment=_frag,
        )

        return data

    def _read_http_ping(self, frame: 'Enum_Frame', length: 'int',
                        flags: 'str', sid: 'int') -> 'Data_PingFrame':
        """Read HTTP/2 ``PING`` frames.

        Structure of HTTP/2 ``PING`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length != 8:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _flag = Data_PingFrameFlags(
            ACK=bool(int(flags[0], base=2)),  # bit 0
        )

        _data = self._read_fileng(8)

        data = Data_PingFrame(
            length=length,
            type=frame,
            flags=_flag,
            sid=sid,
            data=_data,
        )

        return data

    def _read_http_goaway(self, frame: 'Enum_Frame', length: 'int',
                          flags: 'str', sid: 'int') -> 'Data_GoawayFrame':  # pylint: disable=unused-argument
        """Read HTTP/2 ``GOAWAY`` frames.

        Structure of HTTP/2 ``GOAWAY`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _dlen = length - 8
        if _dlen < 0:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _rsid = self._read_binary(4)
        _code = self._read_unpack(4)
        _data = self._read_fileng(_dlen) or None

        data = Data_GoawayFrame(
            length=length,
            type=frame,
            flags=None,
            sid=sid,
            last_sid=int(_rsid[1:], base=2),
            error=Enum_ErrorCode.get(_code),
            debug_data=_data,
        )

        return data

    def _read_http_window_update(self, frame: 'Enum_Frame', length: 'int',
                                 flags: 'str', sid: 'int') -> 'Data_WindowUpdateFrame':  # pylint: disable=unused-argument
        """Read HTTP/2 ``WINDOW_UPDATE`` frames.

        Structure of HTTP/2 ``WINDOW_UPDATE`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if length != 4:
            raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')

        _size = self._read_binary(4)

        data = Data_WindowUpdateFrame(
            length=length,
            type=frame,
            flags=None,
            sid=sid,
            increment=int(_size[1:], base=2),
        )

        return data

    def _read_http_continuation(self, frame: 'Enum_Frame', length: 'int',
                                flags: 'str', sid: 'int') -> 'Data_ContinuationFrame':
        """Read HTTP/2 ``CONTINUATION`` frames.

        Structure of HTTP/2 ``CONTINUATION`` frame [:rfc:`7540`]:

        .. code-block:: text

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
            frame: Frame type.
            length: Length of packet data.
            flags: Flags of the frame.
            sid: Stream ID.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        _flag = Data_ContinuationFrameFlags(
            END_HEADERS=bool(int(flags[2], base=2)),  # bit 2
        )

        _frag = self._read_fileng(length) or None

        data = Data_ContinuationFrame(
            length=length,
            type=frame,
            flags=_flag,
            sid=sid,
            fragment=_frag,
        )

        return data
