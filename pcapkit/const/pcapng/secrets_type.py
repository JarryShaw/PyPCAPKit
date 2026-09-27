# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""Secrets Types
===================

.. module:: pcapkit.const.pcapng.secrets_type

This module contains the constant enumeration for **Secrets Types**,
which is automatically generated from :class:`pcapkit.vendor.pcapng.secrets_type.SecretsType`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['SecretsType']


class SecretsType(IntEnum):
    """[SecretsType] Secrets Types"""

    TLS_Key_Log = 0x544c534b

    WireGuard_Key_Log = 0x57474b4c

    ZigBee_NWK_Key = 0x5a4e574b

    ZigBee_APS_Key = 0x5a415053

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'SecretsType':
        """Backport support for original codes.

        Args:
            key: Key to get enum item.
            default: Default value if not found. The placeholder ``-1`` stands
                for *no default*, in which case an unresolvable key propagates
                the lookup error instead of falling back.

        :meta private:
        """
        if isinstance(key, int):
            try:
                return SecretsType(key)
            except ValueError:
                if default == -1:
                    raise
                return SecretsType(default)
        try:
            return SecretsType[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return SecretsType(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'SecretsType':
        """Explicitly register a new member.

        Unlike :meth:`get` and :meth:`_missing_`, which resolve a key or a
        value without minting anything new, this is the caller-named entry
        point that still grows the registry, via :func:`aenum.extend_enum`.

        Args:
            value: Value of the new member.
            name: Name of the new member.

        Returns:
            The newly registered member.

        """
        return extend_enum(cls, name, value)

    @classmethod
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'SecretsType':
        """Build a member absent from this registry's own lookup tables.

        Used by :meth:`_missing_` for a bounded-but-unassigned value it
        resolves without anyone asking for a name, so that such a lookup no
        longer grows the registry -- contrast :meth:`register`, the explicit
        path that still does.

        Args:
            value: The member's value.
            name: The member's name.

        Returns:
            The unregistered member.

        """
        obj = int.__new__(cls, value)
        obj._name_ = name  # pylint: disable=protected-access
        obj._value_ = value  # pylint: disable=protected-access
        return obj

    @classmethod
    def _missing_(cls, value: 'int') -> 'SecretsType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0x00000000 <= value <= 0xFFFFFFFF):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        extend_enum(cls, 'Unassigned_0x%08x' % value, value)
        return cls(value)
