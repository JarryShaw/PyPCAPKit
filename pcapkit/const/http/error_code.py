# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HTTP/2 Error Code
=======================

.. module:: pcapkit.const.http.error_code

This module contains the constant enumeration for **HTTP/2 Error Code**,
which is automatically generated from :class:`pcapkit.vendor.http.error_code.ErrorCode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ErrorCode']


class ErrorCode(IntEnum):
    """[ErrorCode] HTTP/2 Error Code"""

    #: NO_ERROR, Graceful shutdown [:rfc:`9113#section-7`]
    NO_ERROR = 0x00000000

    #: PROTOCOL_ERROR, Protocol error detected [:rfc:`9113#section-7`]
    PROTOCOL_ERROR = 0x00000001

    #: INTERNAL_ERROR, Implementation fault [:rfc:`9113#section-7`]
    INTERNAL_ERROR = 0x00000002

    #: FLOW_CONTROL_ERROR, Flow-control limits exceeded [:rfc:`9113#section-7`]
    FLOW_CONTROL_ERROR = 0x00000003

    #: SETTINGS_TIMEOUT, Settings not acknowledged [:rfc:`9113#section-7`]
    SETTINGS_TIMEOUT = 0x00000004

    #: STREAM_CLOSED, Frame received for closed stream [:rfc:`9113#section-7`]
    STREAM_CLOSED = 0x00000005

    #: FRAME_SIZE_ERROR, Frame size incorrect [:rfc:`9113#section-7`]
    FRAME_SIZE_ERROR = 0x00000006

    #: REFUSED_STREAM, Stream not processed [:rfc:`9113#section-7`]
    REFUSED_STREAM = 0x00000007

    #: CANCEL, Stream cancelled [:rfc:`9113#section-7`]
    CANCEL = 0x00000008

    #: COMPRESSION_ERROR, Compression state not updated [:rfc:`9113#section-7`]
    COMPRESSION_ERROR = 0x00000009

    #: CONNECT_ERROR, TCP connection error for CONNECT method
    #: [:rfc:`9113#section-7`]
    CONNECT_ERROR = 0x0000000A

    #: ENHANCE_YOUR_CALM, Processing capacity exceeded [:rfc:`9113#section-7`]
    ENHANCE_YOUR_CALM = 0x0000000B

    #: INADEQUATE_SECURITY, Negotiated TLS parameters not acceptable
    #: [:rfc:`9113#section-7`]
    INADEQUATE_SECURITY = 0x0000000C

    #: HTTP_1_1_REQUIRED, Use HTTP/1.1 for the request [:rfc:`9113#section-7`]
    HTTP_1_1_REQUIRED = 0x0000000D

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ErrorCode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return ErrorCode(key)
        if key not in ErrorCode._member_map_:  # pylint: disable=no-member
            return extend_enum(ErrorCode, key, default)
        return ErrorCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ErrorCode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000000E <= value <= 0xFFFFFFFF:
            #: Unassigned
            temp = hex(value)[2:].upper().zfill(8)
            return extend_enum(cls, 'Unassigned_0x%s' % (temp[:4]+'_'+temp[4:]), value)
        return super()._missing_(value)
