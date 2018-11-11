# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Frame(IntEnum):
    """Enumeration class for Frame."""
    _ignore_ = 'Frame _'
    Frame = vars()

    # HTTP/2 Frame Type
    Frame['DATA'] = 0x00                                                        # [RFC 7540, Section 6.1]
    Frame['HEADERS'] = 0x01                                                     # [RFC 7540, Section 6.2]
    Frame['PRIORITY'] = 0x02                                                    # [RFC 7540, Section 6.3]
    Frame['RST_STREAM'] = 0x03                                                  # [RFC 7540, Section 6.4]
    Frame['SETTINGS'] = 0x04                                                    # [RFC 7540, Section 6.5]
    Frame['PUSH_PROMISE'] = 0x05                                                # [RFC 7540, Section 6.6]
    Frame['PING'] = 0x06                                                        # [RFC 7540, Section 6.7]
    Frame['GOAWAY'] = 0x07                                                      # [RFC 7540, Section 6.8]
    Frame['WINDOW_UPDATE'] = 0x08                                               # [RFC 7540, Section 6.9]
    Frame['CONTINUATION'] = 0x09                                                # [RFC 7540, Section 6.10]
    Frame['ALTSVC'] = 0x0A                                                      # [RFC 7838, Section 4]
    Frame['Unassigned'] = 0x0B
    Frame['ORIGIN'] = 0x0C                                                      # [RFC 8336]

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Frame(key)
        if key not in Frame._member_map_:
            extend_enum(Frame, key, default)
        return Frame[key]

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
