# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Frame Type"""

from aenum import IntEnum, extend_enum

__all__ = ['Frame']


class Frame(IntEnum):
    """[Frame] HTTP/2 Frame Type"""

    #: DATA [:rfc:`7540, Section 6.1`]
    DATA = 0x00

    #: HEADERS [:rfc:`7540, Section 6.2`]
    HEADERS = 0x01

    #: PRIORITY [:rfc:`7540, Section 6.3`]
    PRIORITY = 0x02

    #: RST_STREAM [:rfc:`7540, Section 6.4`]
    RST_STREAM = 0x03

    #: SETTINGS [:rfc:`7540, Section 6.5`]
    SETTINGS = 0x04

    #: PUSH_PROMISE [:rfc:`7540, Section 6.6`]
    PUSH_PROMISE = 0x05

    #: PING [:rfc:`7540, Section 6.7`]
    PING = 0x06

    #: GOAWAY [:rfc:`7540, Section 6.8`]
    GOAWAY = 0x07

    #: WINDOW_UPDATE [:rfc:`7540, Section 6.9`]
    WINDOW_UPDATE = 0x08

    #: CONTINUATION [:rfc:`7540, Section 6.10`]
    CONTINUATION = 0x09

    #: ALTSVC [:rfc:`7838, Section 4`]
    ALTSVC = 0x0A

    #: Unassigned
    Unassigned = 0x0B

    #: ORIGIN [:rfc:`8336`]
    ORIGIN = 0x0C

    @staticmethod
    def get(key, default=-1):
        """Backport support for original codes."""
        if isinstance(key, int):
            return Frame(key)
        if key not in Frame._member_map_:  # pylint: disable=no-member
            extend_enum(Frame, key, default)
        return Frame[key]

    @classmethod
    def _missing_(cls, value):
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x0D <= value <= 0xEF:
            #: Unassigned
            extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(2), value)
            return cls(value)
        if 0xF0 <= value <= 0xFF:
            #: Reserved for Experimental Use [:rfc:`7540`]
            extend_enum(cls, 'Reserved for Experimental Use_0x%s' % hex(value)[2:].upper().zfill(2), value)
            return cls(value)
        return super()._missing_(value)
