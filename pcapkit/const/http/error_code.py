# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Error Code"""

from aenum import IntEnum, extend_enum

__all__ = ['ErrorCode']


class ErrorCode(IntEnum):
    """[ErrorCode] HTTP/2 Error Code"""

    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    #: [:rfc:`7540, Section 7`] Graceful shutdown
    ErrorCode['NO_ERROR'] = 0x00000000

    #: [:rfc:`7540, Section 7`] Protocol error detected
    ErrorCode['PROTOCOL_ERROR'] = 0x00000001

    #: [:rfc:`7540, Section 7`] Implementation fault
    ErrorCode['INTERNAL_ERROR'] = 0x00000002

    #: [:rfc:`7540, Section 7`] Flow-control limits exceeded
    ErrorCode['FLOW_CONTROL_ERROR'] = 0x00000003

    #: [:rfc:`7540, Section 7`] Settings not acknowledged
    ErrorCode['SETTINGS_TIMEOUT'] = 0x00000004

    #: [:rfc:`7540, Section 7`] Frame received for closed stream
    ErrorCode['STREAM_CLOSED'] = 0x00000005

    #: [:rfc:`7540, Section 7`] Frame size incorrect
    ErrorCode['FRAME_SIZE_ERROR'] = 0x00000006

    #: [:rfc:`7540, Section 7`] Stream not processed
    ErrorCode['REFUSED_STREAM'] = 0x00000007

    #: [:rfc:`7540, Section 7`] Stream cancelled
    ErrorCode['CANCEL'] = 0x00000008

    #: [:rfc:`7540, Section 7`] Compression state not updated
    ErrorCode['COMPRESSION_ERROR'] = 0x00000009

    #: [:rfc:`7540, Section 7`] TCP connection error for CONNECT method
    ErrorCode['CONNECT_ERROR'] = 0x0000000A

    #: [:rfc:`7540, Section 7`] Processing capacity exceeded
    ErrorCode['ENHANCE_YOUR_CALM'] = 0x0000000B

    #: [:rfc:`7540, Section 7`] Negotiated TLS parameters not acceptable
    ErrorCode['INADEQUATE_SECURITY'] = 0x0000000C

    #: [:rfc:`7540, Section 7`] Use HTTP/1.1 for the request
    ErrorCode['HTTP_1_1_REQUIRED'] = 0x0000000D

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
            temp = hex(value)[2:].upper().zfill(8)
            extend_enum(cls, 'Unassigned [0x%s]' % (temp[:4]+'_'+temp[4:]), value)
            return cls(value)
        return super()._missing_(value)
