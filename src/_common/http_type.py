# -*- coding: utf-8 -*-


from aenum import IntEnum, extend_enum


class PktType(IntEnum):
    """Enumeration class for PktType."""
    _ignore_ = 'PktType _'
    PktType = vars()

    # HTTP/2 Frame Type
    PktType['DATA'] = 0x00                                                      # [RFC 7540, Section 6.1]
    PktType['HEADERS'] = 0x01                                                   # [RFC 7540, Section 6.2]
    PktType['PRIORITY'] = 0x02                                                  # [RFC 7540, Section 6.3]
    PktType['RST_STREAM'] = 0x03                                                # [RFC 7540, Section 6.4]
    PktType['SETTINGS'] = 0x04                                                  # [RFC 7540, Section 6.5]
    PktType['PUSH_PROMISE'] = 0x05                                              # [RFC 7540, Section 6.6]
    PktType['PING'] = 0x06                                                      # [RFC 7540, Section 6.7]
    PktType['GOAWAY'] = 0x07                                                    # [RFC 7540, Section 6.8]
    PktType['WINDOW_UPDATE'] = 0x08                                             # [RFC 7540, Section 6.9]
    PktType['CONTINUATION'] = 0x09                                              # [RFC 7540, Section 6.10]
    PktType['ALTSVC'] = 0x0A                                                    # [RFC 7838, Section 4]
    PktType['Unassigned'] = 0x0B
    PktType['ORIGIN'] = 0x0C                                                    # [RFC 8336]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return PktType(key)
        if key not in PktType._member_map_:
            extend_enum(PktType, key, default)
        return PktType[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0D <= value <= 0xEF:
            extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(2), value)
            return cls(value)
        if 0xF0 <= value <= 0xFF:
            # [RFC 7540]
            extend_enum(cls, 'Reserved for Experimental Use [0x%s]' % hex(value)[2:].upper().zfill(2), value)
            return cls(value)
        super()._missing_(value)
