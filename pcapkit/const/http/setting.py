# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HTTP/2 Settings"""

from aenum import IntEnum, extend_enum

__all__ = ['Setting']


class Setting(IntEnum):
    """[Setting] HTTP/2 Settings"""

    #: ``Reserved`` [RFC-ietf-httpbis-http2bis-07]
    Reserved_0x0000 = 0x0000

    #: ``HEADER_TABLE_SIZE`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2] (Initial
    #: Value: 4096)
    HEADER_TABLE_SIZE = 0x0001

    #: ``ENABLE_PUSH`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2] (Initial
    #: Value: 1)
    ENABLE_PUSH = 0x0002

    #: ``MAX_CONCURRENT_STREAMS`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2]
    #: (Initial Value: infinite)
    MAX_CONCURRENT_STREAMS = 0x0003

    #: ``INITIAL_WINDOW_SIZE`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2]
    #: (Initial Value: 65535)
    INITIAL_WINDOW_SIZE = 0x0004

    #: ``MAX_FRAME_SIZE`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2] (Initial
    #: Value: 16384)
    MAX_FRAME_SIZE = 0x0005

    #: ``MAX_HEADER_LIST_SIZE`` [RFC-ietf-httpbis-http2bis-07, Section 6.5.2]
    #: (Initial Value: infinite)
    MAX_HEADER_LIST_SIZE = 0x0006

    #: ``Unassigned``
    Unassigned_0x0007 = 0x0007

    #: ``SETTINGS_ENABLE_CONNECT_PROTOCOL`` [:rfc:`8441`] (Initial Value: 0)
    SETTINGS_ENABLE_CONNECT_PROTOCOL = 0x0008

    #: ``SETTINGS_NO_RFC7540_PRIORITIES`` [RFC-ietf-httpbis-priority-12] (Initial
    #: Value: 0)
    SETTINGS_NO_RFC7540_PRIORITIES = 0x0009

    #: ``TLS_RENEG_PERMITTED`` [MS-HTTP2E][Gabriel Montenegro] (Initial Value:
    #: 0x00)
    TLS_RENEG_PERMITTED = 0x0010

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Setting':
        """Backport support for original codes."""
        if isinstance(key, int):
            return Setting(key)
        if key not in Setting._member_map_:  # pylint: disable=no-member
            extend_enum(Setting, key, default)
        return Setting[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Setting':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0x0000 <= value <= 0xFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0x000A <= value <= 0x000F:
            #: ``Unassigned``
            extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        if 0x0011 <= value <= 0xFFFF:
            #: ``Unassigned``
            extend_enum(cls, 'Unassigned_0x%s' % hex(value)[2:].upper().zfill(4), value)
            return cls(value)
        return super()._missing_(value)
