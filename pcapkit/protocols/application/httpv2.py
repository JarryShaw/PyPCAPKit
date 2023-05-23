# -*- coding: utf-8 -*-
"""HTTP/2 - Hypertext Transfer Protocol
==========================================

.. module:: pcapkit.protocols.application.httpv2

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
from typing import TYPE_CHECKING, cast

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
from pcapkit.protocols.data.application.httpv2 import RSTStreamFrame as Data_RSTStreamFrame
from pcapkit.protocols.data.application.httpv2 import SettingsFrame as Data_SettingsFrame
from pcapkit.protocols.data.application.httpv2 import SettingsFrameFlags as Data_SettingsFrameFlags
from pcapkit.protocols.data.application.httpv2 import UnassignedFrame as Data_UnassignedFrame
from pcapkit.protocols.data.application.httpv2 import WindowUpdateFrame as Data_WindowUpdateFrame
from pcapkit.protocols.schema.application.httpv2 import HTTP as Schema_HTTP
from pcapkit.protocols.schema.application.httpv2 import \
    ContinuationFrame as Schema_ContinuationFrame
from pcapkit.protocols.schema.application.httpv2 import DataFrame as Schema_DataFrame
from pcapkit.protocols.schema.application.httpv2 import FrameType as Schema_FrameType
from pcapkit.protocols.schema.application.httpv2 import GoawayFrame as Schema_GoawayFrame
from pcapkit.protocols.schema.application.httpv2 import HeadersFrame as Schema_HeadersFrame
from pcapkit.protocols.schema.application.httpv2 import PingFrame as Schema_PingFrame
from pcapkit.protocols.schema.application.httpv2 import PriorityFrame as Schema_PriorityFrame
from pcapkit.protocols.schema.application.httpv2 import PushPromiseFrame as Schema_PushPromiseFrame
from pcapkit.protocols.schema.application.httpv2 import RSTStreamFrame as Schema_RSTStreamFrame
from pcapkit.protocols.schema.application.httpv2 import SettingPair as Schema_SettingPair
from pcapkit.protocols.schema.application.httpv2 import SettingsFrame as Schema_SettingsFrame
from pcapkit.protocols.schema.application.httpv2 import UnassignedFrame as Schema_UnassignedFrame
from pcapkit.protocols.schema.application.httpv2 import \
    WindowUpdateFrame as Schema_WindowUpdateFrame
from pcapkit.protocols.schema.schema import Schema
from pcapkit.utilities.exceptions import ProtocolError
from pcapkit.utilities.warnings import ProtocolWarning, RegistryWarning, warn

if TYPE_CHECKING:
    from enum import IntEnum as StdlibEnum
    from typing import Any, Callable, DefaultDict, Optional, Tuple, Type

    from aenum import IntEnum as AenumEnum
    from mypy_extensions import DefaultArg, KwArg, NamedArg
    from typing_extensions import Literal

    Flags = Schema_FrameType.Flags

    FrameParser = Callable[[Schema_FrameType, NamedArg(Schema_HTTP, 'header')], Data_HTTP]
    FrameConstructor = Callable[[Enum_Frame, DefaultArg(Optional[Data_HTTP]),
                                 KwArg(Any)], Tuple[Schema_FrameType, 'Flags']]

__all__ = ['HTTP']


class HTTP(HTTPBase[Data_HTTP, Schema_HTTP],
           schema=Schema_HTTP, data=Data_HTTP):
    """This class implements Hypertext Transfer Protocol (HTTP/2).

    This class currently supports parsing of the following HTTP/2 frames,
    which are directly mapped to the :class:`pcapkit.const.http.frame.Frame`
    enumeration:

    .. list-table::
       :header-rows: 1

       * - Frame Code
         - Frame Parser
         - Frame Constructor
       * - :attr:`~pcapkit.const.http.frame.Frame.DATA`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_data`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_data`
       * - :attr:`~pcapkit.const.http.frame.Frame.HEADERS`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_headers`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_headers`
       * - :attr:`~pcapkit.const.http.frame.Frame.PRIORITY`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_priority`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_priority`
       * - :attr:`~pcapkit.const.http.frame.Frame.RST_STREAM`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_rst_stream`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_rst_stream`
       * - :attr:`~pcapkit.const.http.frame.Frame.SETTINGS`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_settings`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_settings`
       * - :attr:`~pcapkit.const.http.frame.Frame.PUSH_PROMISE`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_push_promise`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_push_promise`
       * - :attr:`~pcapkit.const.http.frame.Frame.PING`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_ping`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_ping`
       * - :attr:`~pcapkit.const.http.frame.Frame.GOAWAY`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_goaway`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_goaway`
       * - :attr:`~pcapkit.const.http.frame.Frame.WINDOW_UPDATE`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_window_update`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_window_update`
       * - :attr:`~pcapkit.const.http.frame.Frame.CONTINUATION`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._read_http_continuation`
         - :meth:`~pcapkit.protocols.application.httpv2.HTTP._make_http_continuation`

    """

    ##########################################################################
    # Defaults.
    ##########################################################################

    #: DefaultDict[Enum_Frame, str | tuple[FrameParser, FrameConstructor]]: Frame
    #: code to method mapping. Method names are expected to be referred to
    #: the class by ``_read_http_${name}`` and/or ``_make_http_${name}``, and if
    #: such name not found, the value should then be a method that can parse the
    #: frame by itself.
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
    )  # type: DefaultDict[Enum_Frame | int, str | tuple[FrameParser, FrameConstructor]]

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
        schema = self.__header__

        if schema.length < 9:
            raise ProtocolError(f'HTTP/2: [Type {schema.type}] invalid format')
        if schema.type in (Enum_Frame.SETTINGS, Enum_Frame.PING) and schema.stream['sid'] != 0:
            raise ProtocolError(f'HTTP/2: [Type {schema.type}] invalid format')

        name = self.__frame__[schema.type]
        if isinstance(name, str):
            meth_name = f'_read_http_{name}'
            meth = cast('FrameParser',
                        getattr(self, meth_name, self._read_http_none))
        else:
            meth = name[0]
        http = meth(schema.frame, header=schema)

        return http

    def make(self,  # type: ignore[override]
             type: 'Enum_Frame | StdlibEnum | AenumEnum | str | int' = Enum_Frame.DATA,
             type_default: 'Optional[int]' = None,
             type_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
             type_reversed: 'bool' = False,
             flags: 'Flags' = 0,  # type: ignore[assignment]
             sid: 'int' = 0,
             frame: 'bytes | Data_HTTP | Schema_FrameType | dict[str, Any]' = b'',
             **kwargs: 'Any') -> 'Schema_HTTP':
        """Make (construct) packet data.

        Args:
            type: Type of HTTP/2 frame.
            type_default: Default frame type.
            type_namespace: Namespace of frame type.
            type_reversed: Whether to reverse the namespace.
            flags: Flags of HTTP/2 frame.
            sid: Stream ID of HTTP/2 frame.
            frame: Frame data of HTTP/2 frame.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed packet data.

        """
        type_val = cast('Enum_Frame',
                        self._make_index(type, type_default, namespace=type_namespace,
                                         reversed=type_reversed, pack=False))

        if isinstance(frame, bytes):
            length = len(frame) + 9
            frame_val = frame  # type: bytes | Schema_FrameType
        elif isinstance(frame, (dict, Data_HTTP)):
            name = self.__frame__[type_val]
            if isinstance(name, str):
                meth_name = f'_make_http_{name}'
                meth = cast('FrameConstructor',
                            getattr(self, meth_name, self._make_http_none))
            else:
                meth = name[1]

            if isinstance(frame, dict):
                frame_val, flags = meth(type_val, **frame)
            else:
                frame_val, flags = meth(type_val, frame)
            length = len(frame_val.pack()) + 9
        elif isinstance(frame, Schema):
            length = len(frame.pack()) + 9
            frame_val = frame
        else:
            raise ProtocolError(f'HTTP/2: [Type {type_val}] invalid format')

        flags_val = {}  # type: dict[str, int]
        for bit in range(8):
            flags_val[f'bit_{bit}'] = (flags & (1 << bit)) >> bit

        return Schema_HTTP(
            length=length,
            type=type_val,
            flags=flags_val,  # type: ignore[arg-type]
            stream={
                'sid': sid,
            },
            frame=frame_val,
        )

    @classmethod
    def id(cls) -> 'tuple[Literal["HTTP"], Literal["HTTPv2"]]':  # type: ignore[override]
        """Index ID of the protocol.

        Returns:
            Index ID of the protocol.

        """
        return (cls.__name__, 'HTTPv2')  # type: ignore[return-value]

    @classmethod
    def register_frame(cls, code: 'Enum_Frame', meth: 'str | tuple[FrameParser, FrameConstructor]') -> 'None':
        """Register a frame parser.

        Args:
            code: HTTP frame type code.
            meth: Method name or callable to parse and/or construct the frame.

        """
        if code in cls.__frame__:
            warn(f'HTTP/2: [Type {code}] frame already registered', RegistryWarning)
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

    @classmethod
    def _make_data(cls, data: 'Data_HTTP') -> 'dict[str, Any]':  # type: ignore[override]
        """Create key-value pairs from ``data`` for protocol construction.

        Args:
            data: protocol data

        Returns:
            Key-value pairs for protocol construction.

        """
        return {
            'length': data.length,
            'type': data.type,
            'flags': data.flags.__value__ if data.flags is not None else 0,
            'sid': data.sid,
            'frame': data,
        }

    def _read_http_none(self, schema: 'Schema_UnassignedFrame', *,
                        header: 'Schema_HTTP') -> 'Data_UnassignedFrame':
        """Read HTTP packet with unassigned type.

        Args:
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if any(header.flags):
            #raise ProtocolError(f'HTTP/2: [Type {frame}] invalid format')
            warn(f'HTTP/2: [Type {header.type}] invalid format', ProtocolWarning)

        data = Data_UnassignedFrame(
            length=header.length,
            type=header.type,
            flags=None,
            sid=header.stream['sid'],
            data=schema.data,
        )
        return data

    def _read_http_data(self, schema: 'Schema_DataFrame', *,
                        header: 'Schema_HTTP') -> 'Data_DataFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        flag = Data_DataFrameFlags(
            END_STREAM=bool(header.flags['bit_0']),  # bit 0
            PADDED=bool(header.flags['bit_3']),      # bit 3
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        data = Data_DataFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            pad_len=schema.pad_len if flag.PADDED else 0,
            sid=header.stream['sid'],
            data=schema.data,
        )
        return data

    def _read_http_headers(self, schema: 'Schema_HeadersFrame', *,
                           header: 'Schema_HTTP') -> 'Data_HeadersFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        flag = Data_HeadersFrameFlags(
            END_STREAM=bool(header.flags['bit_0']),   # bit 0
            END_HEADERS=bool(header.flags['bit_2']),  # bit 2
            PADDED=bool(header.flags['bit_3']),       # bit 3
            PRIORITY=bool(header.flags['bit_5']),     # bit 5
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        data = Data_HeadersFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            pad_len=schema.pad_len if flag.PADDED else 0,
            sid=header.stream['sid'],
            excl_dependency=bool(schema.stream_dep['exclusive']) if flag.PRIORITY else False,
            stream_dependency=schema.stream_dep['sid'] if flag.PRIORITY else 0,
            weight=(schema.weight + 1) if flag.PRIORITY else 0,
            fragment=schema.fragment,
        )
        return data

    def _read_http_priority(self, schema: 'Schema_PriorityFrame', *,
                            header: 'Schema_HTTP') -> 'Data_PriorityFrame':  # pylint: disable=unused-argument
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if header.length != 9:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        data = Data_PriorityFrame(
            length=header.length,
            type=header.type,
            flags=None,
            sid=header.stream['sid'],
            excl_dependency=bool(schema.stream['exclusive']),
            stream_dependency=schema.stream['sid'],
            weight=schema.weight + 1,
        )
        return data

    def _read_http_rst_stream(self, schema: 'Schema_RSTStreamFrame', *,
                              header: 'Schema_HTTP') -> 'Data_RSTStreamFrame':  # pylint: disable=unused-argument
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if header.length != 13:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        data = Data_RSTStreamFrame(
            length=header.length,
            type=header.type,
            flags=None,
            sid=header.stream['sid'],
            error=schema.error,
        )
        return data

    def _read_http_settings(self, schema: 'Schema_SettingsFrame', *,
                            header: 'Schema_HTTP') -> 'Data_SettingsFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if (header.length - 9) % 6 != 0 or header.stream['sid'] != 0:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        flag = Data_SettingsFrameFlags(
            ACK=bool(header.flags['bit_0']),  # bit 0
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        if flag.ACK and header.length - 9 != 0:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        sets = OrderedMultiDict()  # type: OrderedMultiDict[Enum_Setting, int]
        for setting in schema.settings:
            sets[setting.id] = setting.value

        data = Data_SettingsFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            sid=header.stream['sid'],
            settings=sets,
        )
        return data

    def _read_http_push_promise(self, schema: 'Schema_PushPromiseFrame', *,
                                header: 'Schema_HTTP') -> 'Data_PushPromiseFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if header.length < 13:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        flag = Data_PushPromiseFrameFlags(
            END_HEADERS=bool(header.flags['bit_2']),  # bit 2
            PADDED=bool(header.flags['bit_3']),       # bit 3
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        data = Data_PushPromiseFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            sid=header.stream['sid'],
            pad_len=schema.pad_len if flag.PADDED else 0,
            promised_sid=schema.stream['sid'],
            fragment=schema.fragment,
        )

        return data

    def _read_http_ping(self, schema: 'Schema_PingFrame', *,
                        header: 'Schema_HTTP') -> 'Data_PingFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if header.length != 17:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        flag = Data_PingFrameFlags(
            ACK=bool(header.flags['bit_0']),  # bit 0
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        data = Data_PingFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            sid=header.stream['sid'],
            data=schema.data,
        )
        return data

    def _read_http_goaway(self, schema: 'Schema_GoawayFrame', *,
                          header: 'Schema_HTTP') -> 'Data_GoawayFrame':  # pylint: disable=unused-argument
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        data = Data_GoawayFrame(
            length=header.length,
            type=header.type,
            flags=None,
            sid=header.stream['sid'],
            last_sid=schema.stream['sid'],
            error=schema.error,
            debug_data=schema.debug,
        )
        return data

    def _read_http_window_update(self, schema: 'Schema_WindowUpdateFrame', *,
                                 header: 'Schema_HTTP') -> 'Data_WindowUpdateFrame':  # pylint: disable=unused-argument
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        if header.length != 13:
            raise ProtocolError(f'HTTP/2: [Type {header.type}] invalid format')

        data = Data_WindowUpdateFrame(
            length=header.length,
            type=header.type,
            flags=None,
            sid=header.stream['sid'],
            increment=schema.size['incr'],
        )
        return data

    def _read_http_continuation(self, schema: 'Schema_ContinuationFrame', *,
                                header: 'Schema_HTTP') -> 'Data_ContinuationFrame':
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
            schema: Parsed frame schema.
            header: Parsed HTTP/2 header schema.

        Returns:
            Parsed packet data.

        Raises:
            ProtocolError: If the packet is malformed.

        """
        flag = Data_ContinuationFrameFlags(
            END_HEADERS=bool(header.flags['bit_2']),  # bit 2
        )
        flag.__update__({
            '__value__': schema.__flags__,
        })

        data = Data_ContinuationFrame(
            length=header.length,
            type=header.type,
            flags=flag,
            sid=header.stream['sid'],
            fragment=schema.fragment,
        )
        return data

    def _make_http_none(self, frame: 'Optional[Data_UnassignedFrame]' = None, *,
                        data: 'bytes' = b'',
                        **kwargs: 'Any') -> 'tuple[Schema_UnassignedFrame, Flags]':
        """Make HTTP/2 unassigned frame type.

        Args:
            frame: Frame data model.
            data: Unspecified frame data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            data = frame.data

        return Schema_UnassignedFrame(
            data=data,
        ), Schema_UnassignedFrame.Flags(0)

    def _make_http_data(self, frame: 'Optional[Data_DataFrame]' = None, *,
                        end_stream: 'bool' = False,
                        pad_len: 'int' = 0,
                        data: 'bytes' = b'',
                        **kwargs: 'Any') -> 'tuple[Schema_DataFrame, Flags]':
        """Make HTTP/2 ``DATA`` frame.

        Args:
            frame: Frame data model.
            end_stream: End of stream flag.
            data: Frame data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            pad_len = frame.pad_len
            data = frame.data

        flags = Schema_DataFrame.Flags(0)
        if end_stream:
            flags |= Schema_DataFrame.Flags.END_STREAM
        if pad_len:
            flags |= Schema_DataFrame.Flags.PADDED

        return Schema_DataFrame(
            pad_len=pad_len,
            data=data,
        ), flags

    def _make_http_headers(self, frame: 'Optional[Data_HeadersFrame]' = None, *,
                           end_stream: 'bool' = False,
                           end_headers: 'bool' = False,
                           pad_len: 'int' = 0,
                           excl_dep: 'bool' = False,
                           sid_dep: 'Optional[int]' = None,
                           weight: 'int' = 0,
                           fragment: 'bytes' = b'',
                           **kwargs: 'Any') -> 'tuple[Schema_HeadersFrame, Flags]':
        """Make HTTP/2 ``HEADERS`` frame.

        Args:
            frame: Frame data model.
            end_stream: End of stream flag.
            end_headers: End of headers flag.
            excl_dep: Exclusive dependency flag.
            sid_dep: Dependency stream identifier.
            weight: Priority weight value.
            fragment: Header block fragment.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            priority = frame.flags.PRIORITY
            end_headers = frame.flags.END_HEADERS
            end_stream = frame.flags.END_STREAM

            pad_len = frame.pad_len
            excl_dep = frame.excl_dependency
            sid_dep = frame.stream_dependency
            weight = frame.weight
            fragment = frame.fragment
        else:
            priority = sid_dep is not None
            sid_dep = sid_dep or 0

        flags = Schema_HeadersFrame.Flags(0)
        if end_stream:
            flags |= Schema_HeadersFrame.Flags.END_STREAM
        if end_headers:
            flags |= Schema_HeadersFrame.Flags.END_HEADERS
        if pad_len:
            flags |= Schema_HeadersFrame.Flags.PADDED
        if priority:
            flags |= Schema_HeadersFrame.Flags.PRIORITY

        return Schema_HeadersFrame(
            pad_len=pad_len,
            stream_dep={
                'exclusive': excl_dep,
                'sid': sid_dep,
            },
            weight=weight - 1 if weight else 0,
            fragment=fragment,
        ), flags

    def _make_http_priority(self, frame: 'Optional[Data_PriorityFrame]' = None, *,
                            sid_dep: 'int' = 0,
                            excl_dep: 'bool' = False,
                            weight: 'int' = 0,
                            **kwargs: 'Any') -> 'tuple[Schema_PriorityFrame, Flags]':
        """Make HTTP/2 ``PRIORITY`` frame.

        Args:
            frame: Frame data model.
            excl_dep: Exclusive dependency flag.
            sid_dep: Dependency stream identifier.
            weight: Priority weight value.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            excl_dep = frame.excl_dependency
            sid_dep = frame.stream_dependency
            weight = frame.weight

        return Schema_PriorityFrame(
            stream={
                'exclusive': excl_dep,
                'sid': sid_dep,
            },
            weight=weight - 1 if weight else 0,
        ), Schema_PriorityFrame.Flags(0)

    def _make_http_rst_stream(self, frame: 'Optional[Data_RSTStreamFrame]' = None, *,
                              error: 'Enum_ErrorCode | str | int | StdlibEnum | AenumEnum' = Enum_ErrorCode.HTTP_1_1_REQUIRED,
                              error_default: 'Optional[int]' = None,
                              error_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                              error_reversed: 'bool' = False,
                              **kwargs: 'Any') -> 'tuple[Schema_RSTStreamFrame, Flags]':
        """Make HTTP/2 ``RST_STREAM`` frame.

        Args:
            frame: Frame data model.
            error: Error code.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            error_val = frame.error
        else:
            error_val = self._make_index(error, error_default, namespace=error_namespace,  # type: ignore[assignment]
                                         reversed=error_reversed, pack=False)

        return Schema_RSTStreamFrame(
            error=error_val,
        ), Schema_RSTStreamFrame.Flags(0)

    def _make_http_settings(self, frame: 'Optional[Data_SettingsFrame]' = None, *,
                            ack: 'bool' = False,
                            settings: 'Optional[OrderedMultiDict[Enum_Setting, int] | bytes | list[Schema_SettingPair | tuple[Enum_Setting, int]]]' = None,  # pylint: disable=line-too-long
                            **kwargs: 'Any') -> 'tuple[Schema_SettingsFrame, Flags]':
        """Make HTTP/2 ``SETTINGS`` frame.

        Args:
            frame: Frame data model.
            ack: Acknowledge flag.
            settings: Settings.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            ack = frame.flags.ACK
            settings = frame.settings

        flags = Schema_SettingsFrame.Flags(0)
        if ack:
            flags |= Schema_SettingsFrame.Flags.ACK

        if isinstance(settings, bytes):
            settings_val = settings  # type: bytes | list[Schema_SettingPair]
        elif isinstance(settings, dict):
            settings_val = []
            for key, val in settings.items(multi=True):
                settings_val.append(Schema_SettingPair(
                    id=key,
                    value=val,
                ))
        elif isinstance(settings, list):
            settings_val = []
            for item in settings:
                if isinstance(item, Schema_SettingPair):
                    temp = item
                else:
                    id, value = item
                    temp = Schema_SettingPair(
                        id=id,
                        value=value,
                    )
                settings_val.append(temp)
        else:
            raise ProtocolError(f'HTTP/2 : [Type {Enum_Frame.SETTINGS}] invalid settings')

        return Schema_SettingsFrame(
            settings=settings_val,
        ), flags

    def _make_http_push_promise(self, frame: 'Optional[Data_PushPromiseFrame]' = None, *,
                                end_headers: 'bool' = False,
                                pad_len: 'int' = 0,
                                promised_sid: 'int' = 0,
                                fragment: 'bytes' = b'',
                                **kwargs: 'Any') -> 'tuple[Schema_PushPromiseFrame, Flags]':
        """Make HTTP/2 ``PUSH_PROMISE`` frame.

        Args:
            frame: Frame data model.
            end_headers: End of headers flag.
            pad_len: Padding length.
            promised_sid: Promised stream identifier.
            fragment: Header block fragment.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            end_headers = frame.flags.END_HEADERS
            pad_len = frame.pad_len
            promised_sid = frame.promised_sid
            fragment = frame.fragment

        flags = Schema_PushPromiseFrame.Flags(0)
        if end_headers:
            flags |= Schema_PushPromiseFrame.Flags.END_HEADERS
        if pad_len:
            flags |= Schema_PushPromiseFrame.Flags.PADDED

        return Schema_PushPromiseFrame(
            pad_len=pad_len,
            stream={
                'sid': promised_sid,
            },
            fragment=fragment,
        ), flags

    def _make_http_ping(self, frame: 'Optional[Data_PingFrame]' = None, *,
                        ack: 'bool' = False,
                        opaque_data: 'bytes' = b'',
                        **kwargs: 'Any') -> 'tuple[Schema_PingFrame, Flags]':
        """Make HTTP/2 ``PING`` frame.

        Args:
            frame: Frame data model.
            ack: Acknowledge flag.
            opaque_data: Opaque data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            ack = frame.flags.ACK
            opaque_data = frame.data

        flags = Schema_PingFrame.Flags(0)
        if ack:
            flags |= Schema_PingFrame.Flags.ACK

        return Schema_PingFrame(
            data=opaque_data,
        ), flags

    def _make_http_goaway(self, frame: 'Optional[Data_GoawayFrame]' = None, *,
                          last_sid: 'int' = 0,
                          error: 'Enum_ErrorCode | str | int | StdlibEnum | AenumEnum' = Enum_ErrorCode.HTTP_1_1_REQUIRED,
                          error_default: 'Optional[int]' = None,
                          error_namespace: 'Optional[dict[str, int] | dict[int, str] | Type[StdlibEnum] | Type[AenumEnum]]' = None,  # pylint: disable=line-too-long
                          error_reversed: 'bool' = False,
                          debug_data: 'bytes' = b'',
                          **kwargs: 'Any') -> 'tuple[Schema_GoawayFrame, Flags]':
        """Make HTTP/2 ``GOAWAY`` frame.

        Args:
            frame: Frame data model.
            last_sid: Last stream identifier.
            error: Error code.
            error_default: Default value of error code.
            error_namespace: Namespace of error code.
            error_reversed: Reversed namespace of error code.
            debug_data: Additional debug data.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            last_sid = frame.last_sid
            error_val = frame.error
            debug = frame.debug_data
        else:
            error_val = self._make_index(error, error_default, namespace=error_namespace,  # type: ignore[assignment]
                                         reversed=error_reversed, pack=False)

        return Schema_GoawayFrame(
            stream={
                'sid': last_sid,
            },
            error=error_val,
            debug=debug,
        ), Schema_GoawayFrame.Flags(0)

    def _make_http_window_update(self, frame: 'Optional[Data_WindowUpdateFrame]' = None, *,
                                 incr: 'int' = 0,
                                 **kwargs: 'Any') -> 'tuple[Schema_WindowUpdateFrame, Flags]':
        """Make HTTP/2 ``WINDOW_UPDATE`` frame.

        Args:
            frame: Frame data model.
            incr: Window size increment.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            incr = frame.increment

        return Schema_WindowUpdateFrame(
            size={
                'incr': incr,
            }
        ), Schema_WindowUpdateFrame.Flags(0)

    def _make_http_continuation(self, frame: 'Optional[Data_ContinuationFrame]' = None, *,
                                end_headers: 'bool' = False,
                                fragment: 'bytes' = b'',
                                **kwargs: 'Any') -> 'tuple[Schema_ContinuationFrame, Flags]':
        """Make HTTP/2 ``CONTINUATION`` frame.

        Args:
            frame: Frame data model.
            end_headers: End of headers flag.
            fragment: Header block fragment.
            **kwargs: Arbitrary keyword arguments.

        Returns:
            Constructed frame schema and updated flags.

        """
        if frame is not None:
            end_headers = frame.flags.END_HEADERS
            fragment = frame.fragment

        flags = Schema_ContinuationFrame.Flags(0)
        if end_headers:
            flags |= Schema_ContinuationFrame.Flags.END_HEADERS

        return Schema_ContinuationFrame(
            fragment=fragment,
        ), flags
