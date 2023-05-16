# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Link-Layer Address (LLA) Option Code
==========================================

.. module:: pcapkit.const.mh.lla_code

This module contains the constant enumeration for **Link-Layer Address (LLA) Option Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.lla_code.LLACode`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['LLACode']


class LLACode(IntEnum):
    """[LLACode] Link-Layer Address (LLA) Option Code"""

    Wilcard = 0

    New_Access_Point = 1

    MH = 2

    NAR = 3

    RtSolPr_or_PrRtAdv = 4

    access_point = 5

    no_prefix_information = 6

    no_fast_handover_support = 7

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'LLACode':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return LLACode(key)
        if key not in LLACode._member_map_:  # pylint: disable=no-member
            return extend_enum(LLACode, key, default)
        return LLACode[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'LLACode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
