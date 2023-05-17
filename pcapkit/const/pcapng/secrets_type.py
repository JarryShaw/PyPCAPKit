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
            default: Default value if not found.

        :meta private:
        """
        if isinstance(key, int):
            return SecretsType(key)
        if key not in SecretsType._member_map_:  # pylint: disable=no-member
            return extend_enum(SecretsType, key, default)
        return SecretsType[key]  # type: ignore[misc]

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
