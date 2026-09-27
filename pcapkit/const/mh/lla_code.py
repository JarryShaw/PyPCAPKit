# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Link-Layer Address (LLA) Option Code
==========================================

.. module:: pcapkit.const.mh.lla_code

This module contains the constant enumeration for **Link-Layer Address (LLA) Option Code**,
which is automatically generated from :class:`pcapkit.vendor.mh.lla_code.LLACode`.

"""

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['LLACode']


class LLACode(EnumRegistry, IntEnum):
    """[LLACode] Link-Layer Address (LLA) Option Code"""

    Wilcard = 0

    New_Access_Point = 1

    MH = 2

    NAR = 3

    RtSolPr_or_PrRtAdv = 4

    access_point = 5

    no_prefix_information = 6

    no_fast_handover_support = 7

    @classmethod
    def _missing_(cls, value: 'int') -> 'LLACode':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return cls._unregistered_member(value, 'Unassigned')
