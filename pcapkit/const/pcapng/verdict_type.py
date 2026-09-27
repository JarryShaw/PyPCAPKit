# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Verdict Types
===================

.. module:: pcapkit.const.pcapng.verdict_type

This module contains the constant enumeration for **Verdict Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.verdict_type.VerdictType`.

"""

from aenum import IntEnum, extend_enum

from pcapkit.corekit.enum import EnumRegistry

__all__ = ['VerdictType']


class VerdictType(EnumRegistry, IntEnum):
    """[VerdictType] Verdict Types"""

    Hardware = 0

    Linux_eBPF_TC = 1

    Linux_eBPF_XDP = 2

    @classmethod
    def _missing_(cls, value: 'int') -> 'VerdictType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00 <= value <= 0xFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
