# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Registration Types
========================

.. module:: pcapkit.const.hip.registration

This module contains the constant enumeration for **Registration Types**,
which is automatically generated from :class:`pcapkit.vendor.hip.registration.Registration`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['Registration']


class Registration(IntEnum):
    """[Registration] Registration Types"""

    #: Unassigned
    Unassigned_0 = 0

    #: RENDEZVOUS [:rfc:`8004`]
    RENDEZVOUS = 1

    #: RELAY_UDP_HIP [:rfc:`5770`]
    RELAY_UDP_HIP = 2

    #: RELAY_UDP_ESP [:rfc:`9028`]
    RELAY_UDP_ESP = 3

    #: CANDIDATE_DISCOVERY [:rfc:`9028`]
    CANDIDATE_DISCOVERY = 4

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'Registration':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return Registration(key)
        if key not in Registration._member_map_:  # pylint: disable=no-member
            return extend_enum(Registration, key, default)
        return Registration[key]  # type: ignore[misc]

    @classmethod
    def _missing_(cls, value: 'int') -> 'Registration':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 5 <= value <= 200:
            #: Unassigned
            return extend_enum(cls, 'Unassigned_%d' % value, value)
        if 201 <= value <= 255:
            #: Reserved for Private Use [:rfc:`8003`]
            return extend_enum(cls, 'Reserved_for_Private_Use_%d' % value, value)
        return super()._missing_(value)
