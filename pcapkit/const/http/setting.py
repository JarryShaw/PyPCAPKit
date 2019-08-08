# -*- coding: utf-8 -*-

from aenum import IntEnum, extend_enum


class Setting(IntEnum):
    """Enumeration class for Setting."""
    _ignore_ = 'Setting _'
    Setting = vars()

    # HTTP/2 Settings
    Setting['Reserved'] = 0x0000                                                # [RFC 7540]
    Setting['HEADER_TABLE_SIZE'] = 0x0001                                       # [RFC 7540, Section 6.5.2] 4096
    Setting['ENABLE_PUSH'] = 0x0002                                             # [RFC 7540, Section 6.5.2] 1
    Setting['MAX_CONCURRENT_STREAMS'] = 0x0003                                  # [RFC 7540, Section 6.5.2] infinite
    Setting['INITIAL_WINDOW_SIZE'] = 0x0004                                     # [RFC 7540, Section 6.5.2] 65535
    Setting['MAX_FRAME_SIZE'] = 0x0005                                          # [RFC 7540, Section 6.5.2] 16384
    Setting['MAX_HEADER_LIST_SIZE'] = 0x0006                                    # [RFC 7540, Section 6.5.2] infinite
    Setting['Unassigned'] = 0x0007
    Setting['SETTINGS_ENABLE_CONNECT_PROTOCOL'] = 0x0008                        # [RFC 8441] 0
    Setting['TLS_RENEG_PERMITTED'] = 0x0010                                     # [MS-HTTP2E][Gabriel_Montenegro] 0x00

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Setting(key)
        if key not in Setting._member_map_:
            extend_enum(Setting, key, default)
        return Setting[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0009 <= value <= 0x000F:
            extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0011 <= value <= 0xEFFF:
            extend_enum(cls, 'Unassigned [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0xF000 <= value <= 0xFFFF:
            # [RFC 7540]
            extend_enum(cls, 'Reserved for Experimental Use [0x%s]' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        super()._missing_(value)
