# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class ErrCode(IntEnum):
    """Enumeration class for ErrCode."""
    _ignore_ = 'ErrCode _'
    ErrCode = vars()

    # HTTP/2 Error Code
    ErrCode['NO_ERROR'] = 0x0000_0000                                           # [RFC 7540, Section 7] Graceful shutdown
    ErrCode['PROTOCOL_ERROR'] = 0x0000_0001                                     # [RFC 7540, Section 7] Protocol error detected
    ErrCode['INTERNAL_ERROR'] = 0x0000_0002                                     # [RFC 7540, Section 7] Implementation fault
    ErrCode['FLOW_CONTROL_ERROR'] = 0x0000_0003                                 # [RFC 7540, Section 7] Flow-control limits exceeded
    ErrCode['SETTINGS_TIMEOUT'] = 0x0000_0004                                   # [RFC 7540, Section 7] Settings not acknowledged
    ErrCode['STREAM_CLOSED'] = 0x0000_0005                                      # [RFC 7540, Section 7] Frame received for closed stream
    ErrCode['FRAME_SIZE_ERROR'] = 0x0000_0006                                   # [RFC 7540, Section 7] Frame size incorrect
    ErrCode['REFUSED_STREAM'] = 0x0000_0007                                     # [RFC 7540, Section 7] Stream not processed
    ErrCode['CANCEL'] = 0x0000_0008                                             # [RFC 7540, Section 7] Stream cancelled
    ErrCode['COMPRESSION_ERROR'] = 0x0000_0009                                  # [RFC 7540, Section 7] Compression state not updated
    ErrCode['CONNECT_ERROR'] = 0x0000_000A                                      # [RFC 7540, Section 7] TCP connection error for CONNECT method
    ErrCode['ENHANCE_YOUR_CALM'] = 0x0000_000B                                  # [RFC 7540, Section 7] Processing capacity exceeded
    ErrCode['INADEQUATE_SECURITY'] = 0x0000_000C                                # [RFC 7540, Section 7] Negotiated TLS parameters not acceptable
    ErrCode['HTTP_1_1_REQUIRED'] = 0x0000_000D                                  # [RFC 7540, Section 7] Use HTTP/1.1 for the request

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return ErrCode(key)
        if key not in ErrCode._member_map_:
            extend_enum(ErrCode, key, default)
        return ErrCode[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000_0000 <= value <= 0xFFFF_FFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0000_000E <= value <= 0xFFFF_FFFF:
            temp = hex(value)[2:].upper().zfill(8)
            extend_enum(cls, 'Unassigned [0x%s]' % (temp[:4]+'_'+temp[4:]), value)
            return cls(value)
        super()._missing_(value)
