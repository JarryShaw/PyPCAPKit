# -*- coding: utf-8 -*-
# pylint: disable=line-too-long
"""HIP Transport Modes"""

from aenum import IntEnum, extend_enum

__all__ = ['Transport']


class Transport(IntEnum):
    """[Transport] HIP Transport Modes"""

    #: RESERVED [:rfc:`6261`]
    RESERVED_0 = 0

    #: DEFAULT [:rfc:`6261`]
    DEFAULT = 1

    #: ESP [:rfc:`6261`]
    ESP = 2

    #: ESP-TCP [:rfc:`6261`]
    ESP_TCP = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Transport':
        """Backport support for original codes."""
        if isinstance(key, int):
            return Transport(key)
        if key not in Transport._member_map_:  # pylint: disable=no-member
            extend_enum(Transport, key, default)
        return Transport[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Transport':
        """Lookup function used when value is not found."""
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
