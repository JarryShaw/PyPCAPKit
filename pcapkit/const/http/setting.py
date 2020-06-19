# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Settings"""

from aenum import IntEnum, extend_enum

__all__ = ['Setting']


class Setting(IntEnum):
    """[Setting] HTTP/2 Settings"""

    #: Reserved [:rfc:`7540`]
    Reserved = 0x0000

    #: HEADER_TABLE_SIZE [:rfc:`7540, Section 6.5.2`] 4096
    HEADER_TABLE_SIZE = 0x0001

    #: ENABLE_PUSH [:rfc:`7540, Section 6.5.2`] 1
    ENABLE_PUSH = 0x0002

    #: MAX_CONCURRENT_STREAMS [:rfc:`7540, Section 6.5.2`] infinite
    MAX_CONCURRENT_STREAMS = 0x0003

    #: INITIAL_WINDOW_SIZE [:rfc:`7540, Section 6.5.2`] 65535
    INITIAL_WINDOW_SIZE = 0x0004

    #: MAX_FRAME_SIZE [:rfc:`7540, Section 6.5.2`] 16384
    MAX_FRAME_SIZE = 0x0005

    #: MAX_HEADER_LIST_SIZE [:rfc:`7540, Section 6.5.2`] infinite
    MAX_HEADER_LIST_SIZE = 0x0006

    #: Unassigned
    Unassigned = 0x0007

    #: SETTINGS_ENABLE_CONNECT_PROTOCOL [:rfc:`8441`] 0
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x0008

    #: TLS_RENEG_PERMITTED [MS-HTTP2E][Gabriel Montenegro] 0x00
    TLS_RENEG_PERMITTED = 0x0010

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Setting(key)
        if key not in Setting._member_map_:  # pylint: disable=no-member
            extend_enum(Setting, key, default)
        return Setting[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0009 <= value <= 0x000F:
            #: Unassigned
            extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0011 <= value <= 0xEFFF:
            #: Unassigned
            extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0xF000 <= value <= 0xFFFF:
            #: Reserved for Experimental Use [:rfc:`7540`]
            extend_enum(cls, 'Reserved_for_Experimental_Use_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        return super()._missing_(value)
