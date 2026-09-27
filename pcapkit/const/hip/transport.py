# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""HIP Transport Modes
=========================

.. module:: pcapkit.const.hip.transport

This module contains the constant enumeration for **HIP Transport Modes**,
which is automatically generated from :class:`pcapkit.vendor.hip.transport.Transport`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['Transport']


class Transport(EnumRegistry, IntEnum):
    """[Transport] HIP Transport Modes"""

    #: RESERVED [:rfc:`6261`]
    RESERVED_0 = 0

    #: DEFAULT [:rfc:`6261`]
    DEFAULT = 1

    #: ESP [:rfc:`6261`]
    ESP = 2

    #: ESP-TCP [:rfc:`6261`]
    ESP_TCP = 3

    @classmethod
    def _missing_(cls, value: 'int') -> 'Transport':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return super()._missing_(value)
