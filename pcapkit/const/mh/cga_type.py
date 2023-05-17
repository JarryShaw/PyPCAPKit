# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""CGA Extension Type Tags
=============================

.. module:: pcapkit.const.mh.cga_type

This module contains the constant enumeration for **CGA Extension Type Tags**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_type.CGAType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['CGAType']


class CGAType(IntEnum):
    """[CGAType] CGA Extension Type Tags"""

    #: 0x086F CA5E 10B2 00C9 9C8C E001 6427 7C08 [:rfc:`3971`]
    Tag_086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08 = 0x086F_CA5E_10B2_00C9_9C8C_E001_6427_7C08

    #: 0x5F27 0586 8D6C 4C56 A246 9EBB 9B2A 2E13 [:rfc:`4866`]
    Tag_5F27_0586_8D6C_4C56_A246_9EBB_9B2A_2E13 = 0x5F27_0586_8D6C_4C56_A246_9EBB_9B2A_2E13

    #: 0xF0EF F02F BFF4 3D0F E793 0C3C 6E61 74EA [:rfc:`7401`]
    Tag_F0EF_F02F_BFF4_3D0F_E793_0C3C_6E61_74EA = 0xF0EF_F02F_BFF4_3D0F_E793_0C3C_6E61_74EA

    #: 0x4A30 5662 4858 574B 3655 416F 506A 6D48 [:rfc:`5533`]
    Tag_4A30_5662_4858_574B_3655_416F_506A_6D48 = 0x4A30_5662_4858_574B_3655_416F_506A_6D48

    #: 0x09F5 2BE5 3B62 4C76 CB96 4E7F CDC9 2804 [:rfc:`6496`]
    Tag_09F5_2BE5_3B62_4C76_CB96_4E7F_CDC9_2804 = 0x09F5_2BE5_3B62_4C76_CB96_4E7F_CDC9_2804

    #: 0x8701 55C8 0CCA DD32 6AB7 E415 F148 84D0 [:rfc:`8928`]
    Tag_8701_55C8_0CCA_DD32_6AB7_E415_F148_84D0 = 0x8701_55C8_0CCA_DD32_6AB7_E415_F148_84D0

    #: 0x00B5 A69C 795D F5D5 F008 7F56 843F 2C40 [:rfc:`9374`]
    Tag_00B5_A69C_795D_F5D5_F008_7F56_843F_2C40 = 0x00B5_A69C_795D_F5D5_F008_7F56_843F_2C40

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'CGAType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return CGAType(key)
        if key not in CGAType._member_map_:  # pylint: disable=no-member
            return extend_enum(CGAType, key, default)
        return CGAType[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'CGAType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Tag_%s' % ('_'.join(__import__('textwrap').wrap('%032x' % value, 4))), value)
