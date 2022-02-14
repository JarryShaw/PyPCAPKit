# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Error Code"""

from aenum import IntEnum, extend_enum

__all__ = ['ErrorCode']


class ErrorCode(IntEnum):
    """[ErrorCode] HTTP/2 Error Code"""

    #: NO_ERROR, Graceful shutdown [RFC-ietf-httpbis-http2bis-07, Section 7]
    NO_ERROR = 0x00000000

    #: PROTOCOL_ERROR, Protocol error detected [RFC-ietf-httpbis-http2bis-07,
    #: Section 7]
    PROTOCOL_ERROR = 0x00000001

    #: INTERNAL_ERROR, Implementation fault [RFC-ietf-httpbis-http2bis-07, Section
    #: 7]
    INTERNAL_ERROR = 0x00000002

    #: FLOW_CONTROL_ERROR, Flow-control limits exceeded [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    FLOW_CONTROL_ERROR = 0x00000003

    #: SETTINGS_TIMEOUT, Settings not acknowledged [RFC-ietf-httpbis-http2bis-07,
    #: Section 7]
    SETTINGS_TIMEOUT = 0x00000004

    #: STREAM_CLOSED, Frame received for closed stream [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    STREAM_CLOSED = 0x00000005

    #: FRAME_SIZE_ERROR, Frame size incorrect [RFC-ietf-httpbis-http2bis-07,
    #: Section 7]
    FRAME_SIZE_ERROR = 0x00000006

    #: REFUSED_STREAM, Stream not processed [RFC-ietf-httpbis-http2bis-07, Section
    #: 7]
    REFUSED_STREAM = 0x00000007

    #: CANCEL, Stream cancelled [RFC-ietf-httpbis-http2bis-07, Section 7]
    CANCEL = 0x00000008

    #: COMPRESSION_ERROR, Compression state not updated [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    COMPRESSION_ERROR = 0x00000009

    #: CONNECT_ERROR, TCP connection error for CONNECT method [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    CONNECT_ERROR = 0x0000000A

    #: ENHANCE_YOUR_CALM, Processing capacity exceeded [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    ENHANCE_YOUR_CALM = 0x0000000B

    #: INADEQUATE_SECURITY, Negotiated TLS parameters not acceptable [RFC-ietf-
    #: httpbis-http2bis-07, Section 7]
    INADEQUATE_SECURITY = 0x0000000C

    #: HTTP_1_1_REQUIRED, Use HTTP/1.1 for the request [RFC-ietf-httpbis-
    #: http2bis-07, Section 7]
    HTTP_1_1_REQUIRED = 0x0000000D

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ErrorCode':
        """Backport support for original codes."""
        if isinstance(key, int):
            return ErrorCode(key)
        if key not in ErrorCode._member_map_:  # pylint: disable=no-member
            extend_enum(ErrorCode, key, default)
        return ErrorCode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'ErrorCode':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000000E <= value <= 0xFFFFFFFF:
            #: Unassigned
            temp = hex(value)[2:].upper().zfill(8)
            extend_enum(cls, 'Unassigned_0x%s' % (temp[:4]+'_'+temp[4:]), value)
            return cls(value)
        return super()._missing_(value)
