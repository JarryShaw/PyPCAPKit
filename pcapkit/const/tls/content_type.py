# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS/DTLS Content Types
============================

.. module:: pcapkit.const.tls.content_type

This module contains the constant enumeration for **TLS/DTLS Content Types**,
which is automatically generated from :class:`pcapkit.vendor.tls.content_type.ContentType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['ContentType']


class ContentType(EnumRegistry, IntEnum):
    """[ContentType] TLS/DTLS Content Types"""

    #: change_cipher_spec [:rfc:`9846`]
    change_cipher_spec = 20

    #: alert [:rfc:`9846`]
    alert = 21

    #: handshake [:rfc:`9846`]
    handshake = 22

    #: application_data [:rfc:`9846`]
    application_data = 23

    #: heartbeat [:rfc:`6520`]
    heartbeat = 24

    #: tls12_cid [:rfc:`9146`]
    tls12_cid = 25

    #: ACK [:rfc:`9147`]
    ack = 26

    #: return_routability_check [:rfc:`9853`]
    return_routability_check = 27

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Overrides :meth:`~pcapkit.corekit.enum.EnumLookup._validate_value`
        with that check and the message it raises, so
        :meth:`~pcapkit.corekit.enum.EnumRegistry.register` refuses exactly the
        values :meth:`~pcapkit.corekit.enum.EnumLookup.get` refuses, in the
        same words (:issue:`1816`).

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check. A
                :exc:`ValueError`, so an ``except ValueError`` caller is
                unaffected.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise EnumValueError('%r is not a valid %s' % (value, cls.__name__))

    @classmethod
    def _missing_(cls, value: 'int') -> 'ContentType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 0 <= value <= 19:
            #: Unassigned (Requires coordination; see [RFC 9443])
    #: [:rfc:`5764`][:rfc:`9443`]
            return cls._unregistered_member(value, 'Unassigned')
        if 28 <= value <= 31:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 32 <= value <= 63:
            #: Reserved [:rfc:`9147`]
            return cls._unregistered_member(value, 'Reserved')
        if 64 <= value <= 255:
            #: Unassigned (Requires coordination; see [RFC 9443])
    #: [:rfc:`5764`][:rfc:`9443`]
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
