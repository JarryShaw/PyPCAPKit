# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""ESP Transform Suite IDs
=============================

.. module:: pcapkit.const.hip.esp_transform_suite

This module contains the constant enumeration for **ESP Transform Suite IDs**,
which is automatically generated from :class:`pcapkit.vendor.hip.esp_transform_suite.ESPTransformSuite`.

"""

from aenum import IntEnum, extend_enum

__all__ = ['ESPTransformSuite']


class ESPTransformSuite(IntEnum):
    """[ESPTransformSuite] ESP Transform Suite IDs"""

    #: RESERVED [:rfc:`7402`]
    RESERVED_0 = 0

    #: AES-128-CBC with HMAC-SHA1 [:rfc:`3602`][:rfc:`2404`]
    AES_128_CBC_with_HMAC_SHA1 = 1

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_2 = 2

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_3 = 3

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_4 = 4

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_5 = 5

    #: DEPRECATED [:rfc:`7402`]
    DEPRECATED_6 = 6

    #: NULL with HMAC-SHA-256 [:rfc:`2410`][:rfc:`4868`]
    NULL_with_HMAC_SHA_256 = 7

    #: AES-128-CBC with HMAC-SHA-256 [:rfc:`3602`][:rfc:`4868`]
    AES_128_CBC_with_HMAC_SHA_256 = 8

    #: AES-256-CBC with HMAC-SHA-256 [:rfc:`3602`][:rfc:`4868`]
    AES_256_CBC_with_HMAC_SHA_256 = 9

    #: AES-CCM-8 [:rfc:`4309`]
    AES_CCM_8 = 10

    #: AES-CCM-16 [:rfc:`4309`]
    AES_CCM_16 = 11

    #: AES-GCM with an 8 octet ICV [:rfc:`4106`]
    AES_GCM_with_an_8_octet_ICV = 12

    #: AES-GCM with a 16 octet ICV [:rfc:`4106`]
    AES_GCM_with_a_16_octet_ICV = 13

    #: AES-CMAC-96 [:rfc:`4493`][:rfc:`4494`]
    AES_CMAC_96 = 14

    #: AES-GMAC [:rfc:`4543`]
    AES_GMAC = 15

    @staticmethod
    def get(key: 'int | str', default: 'int' = -1) -> 'ESPTransformSuite':
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
                return ESPTransformSuite(key)
            except ValueError:
                if default == -1:
                    raise
                return ESPTransformSuite(default)
        try:
            return ESPTransformSuite[key]  # type: ignore[misc]
        except KeyError:
            if default == -1:
                raise
            return ESPTransformSuite(default)

    @classmethod
    def register(cls, value: 'int', name: 'str') -> 'ESPTransformSuite':
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
    def _unregistered_member(cls, value: 'int', name: 'str') -> 'ESPTransformSuite':
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
    def _missing_(cls, value: 'int') -> 'ESPTransformSuite':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 65535):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 16 <= value <= 65535:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
