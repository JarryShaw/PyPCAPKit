# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Option Actions
====================

.. module:: pcapkit.const.ipv6.option_action

This module contains the constant enumeration for **Option Actions**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.option_action.OptionAction`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['OptionAction']


class OptionAction(IntEnum):
    """[OptionAction] Option Actions"""

    skip = 0

    discard = 1

    discard_icmp_any = 2

    discard_icmp_unicast = 3

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'OptionAction':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return OptionAction(key)
        if key not in OptionAction._member_map_:  # pylint: disable=no-member
            return extend_enum(OptionAction, key, default)
        return OptionAction[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'OptionAction':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 3):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        return extend_enum(cls, 'Unassigned_%d' % value, value)
