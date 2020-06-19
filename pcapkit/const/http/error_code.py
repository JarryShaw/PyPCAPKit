# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Error Code"""

from aenum import IntEnum, extend_enum

__all__ = ['ErrorCode']


class ErrorCode(IntEnum):
    """[ErrorCode] HTTP/2 Error Code"""

    #: desc
    NO_ERROR = 0x00000000

    #: desc
    PROTOCOL_ERROR = 0x00000001

    #: desc
    INTERNAL_ERROR = 0x00000002

    #: desc
    FLOW_CONTROL_ERROR = 0x00000003

    #: desc
    SETTINGS_TIMEOUT = 0x00000004

    #: desc
    STREAM_CLOSED = 0x00000005

    #: desc
    FRAME_SIZE_ERROR = 0x00000006

    #: desc
    REFUSED_STREAM = 0x00000007

    #: desc
    CANCEL = 0x00000008

    #: desc
    COMPRESSION_ERROR = 0x00000009

    #: desc
    CONNECT_ERROR = 0x0000000A

    #: desc
    ENHANCE_YOUR_CALM = 0x0000000B

    #: desc
    INADEQUATE_SECURITY = 0x0000000C

    #: desc
    HTTP_1_1_REQUIRED = 0x0000000D

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ErrorCode(key)
        if key not in ErrorCode._member_map_:  # pylint: disable=no-member
            extend_enum(ErrorCode, key, default)
        return ErrorCode[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000000E <= value <= 0xFFFFFFFF:
            #: Unassigned
            temp = hex(value)[2:].upper().zfill(8)
            extend_enum(cls, 'Unassigned_0x%s' % (temp[:4]+'_'+temp[4:]), value)
            return cls(value)
        return super()._missing_(value)
