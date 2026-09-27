# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""CGA SEC
=============

.. module:: pcapkit.const.mh.cga_sec

This module contains the constant enumeration for **CGA SEC**,
which is automatically generated from :class:`pcapkit.vendor.mh.cga_sec.CGASec`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['CGASec']


class CGASec(EnumRegistry, IntEnum):
    """[CGASec] CGA SEC"""

    #: SHA-1_0hash2bits [:rfc:`4982`]
    SHA_1_0hash2bits = 0b000

    #: SHA-1_16hash2bits [:rfc:`4982`]
    SHA_1_16hash2bits = 0b001

    #: SHA-1_32hash2bits [:rfc:`4982`]
    SHA_1_32hash2bits = 0b010

    @classmethod
    def _missing_(cls, value: 'int') -> 'CGASec':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 0b111):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unspecified in the IANA registry
        return extend_enum(cls, 'Unassigned_%s' % bin(value)[2:], value)
