# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class ErrorCode(IntEnum):
    """Enumeration class for ErrorCode."""
    _ignore_ = 'ErrorCode _'
    ErrorCode = vars()

    # HTTP/2 Error Code
    ErrorCode['NO_ERROR'] = 0x00000000                                          # [RFC 7540, Section 7] Graceful shutdown
    ErrorCode['PROTOCOL_ERROR'] = 0x00000001                                    # [RFC 7540, Section 7] Protocol error detected
    ErrorCode['INTERNAL_ERROR'] = 0x00000002                                    # [RFC 7540, Section 7] Implementation fault
    ErrorCode['FLOW_CONTROL_ERROR'] = 0x00000003                                # [RFC 7540, Section 7] Flow-control limits exceeded
    ErrorCode['SETTINGS_TIMEOUT'] = 0x00000004                                  # [RFC 7540, Section 7] Settings not acknowledged
    ErrorCode['STREAM_CLOSED'] = 0x00000005                                     # [RFC 7540, Section 7] Frame received for closed stream
    ErrorCode['FRAME_SIZE_ERROR'] = 0x00000006                                  # [RFC 7540, Section 7] Frame size incorrect
    ErrorCode['REFUSED_STREAM'] = 0x00000007                                    # [RFC 7540, Section 7] Stream not processed
    ErrorCode['CANCEL'] = 0x00000008                                            # [RFC 7540, Section 7] Stream cancelled
    ErrorCode['COMPRESSION_ERROR'] = 0x00000009                                 # [RFC 7540, Section 7] Compression state not updated
    ErrorCode['CONNECT_ERROR'] = 0x0000000A                                     # [RFC 7540, Section 7] TCP connection error for CONNECT method
    ErrorCode['ENHANCE_YOUR_CALM'] = 0x0000000B                                 # [RFC 7540, Section 7] Processing capacity exceeded
    ErrorCode['INADEQUATE_SECURITY'] = 0x0000000C                               # [RFC 7540, Section 7] Negotiated TLS parameters not acceptable
    ErrorCode['HTTP_1_1_REQUIRED'] = 0x0000000D                                 # [RFC 7540, Section 7] Use HTTP/1.1 for the request

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ErrorCode(key)
        if key not in ErrorCode._member_map_:
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
        super()._missing_(value)
