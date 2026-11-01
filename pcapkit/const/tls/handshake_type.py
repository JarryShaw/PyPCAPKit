# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS/DTLS HandshakeType
============================

.. module:: pcapkit.const.tls.handshake_type

This module contains the constant enumeration for **TLS/DTLS HandshakeType**,
which is automatically generated from :class:`pcapkit.vendor.tls.handshake_type.HandshakeType`.

"""

from typing import TYPE_CHECKING

from aenum import IntEnum

from pcapkit.corekit.enum import EnumRegistry
from pcapkit.utilities.exceptions import EnumValueError

if TYPE_CHECKING:
    from typing import Any

__all__ = ['HandshakeType']


class HandshakeType(EnumRegistry, IntEnum):
    """[HandshakeType] TLS/DTLS HandshakeType"""

    #: hello_request [:rfc:`9846`] -- Used in TLS versions prior to 1.3.
    hello_request = 0

    #: client_hello [:rfc:`9846`]
    client_hello = 1

    #: server_hello [:rfc:`9846`]
    server_hello = 2

    #: hello_verify_request [:rfc:`6347`][:rfc:`9846`] -- Assigned for interim
    #: draft, but the functionality was moved to a different message.
    hello_verify_request = 3

    #: new_session_ticket [:rfc:`4507`][:rfc:`9846`][:rfc:`8447`][RFC Errata 7250]
    new_session_ticket = 4

    #: end_of_early_data [:rfc:`9846`]
    end_of_early_data = 5

    #: hello_retry_request [:rfc:`9846`] -- Assigned for interim draft, but the
    #: functionality was moved to an extension.
    hello_retry_request = 6

    #: Unassigned
    unassigned_7 = 7

    #: encrypted_extensions [:rfc:`9846`]
    encrypted_extensions = 8

    #: request_connection_id [:rfc:`9147`]
    request_connection_id = 9

    #: new_connection_id [:rfc:`9147`]
    new_connection_id = 10

    #: certificate [:rfc:`9846`]
    certificate = 11

    #: server_key_exchange [:rfc:`9846`] -- Used in TLS versions prior to 1.3.
    server_key_exchange = 12

    #: certificate_request [:rfc:`9846`]
    certificate_request = 13

    #: server_hello_done [:rfc:`9846`] -- Used in TLS versions prior to 1.3.
    server_hello_done = 14

    #: certificate_verify [:rfc:`9846`]
    certificate_verify = 15

    #: client_key_exchange [:rfc:`9846`] -- Used in TLS versions prior to 1.3.
    client_key_exchange = 16

    #: client_certificate_request [:rfc:`9261`] -- Used in TLS versions prior to
    #: 1.3.
    client_certificate_request = 17

    #: finished [:rfc:`9846`]
    finished = 20

    #: certificate_url [:rfc:`6066`][:rfc:`9846`] -- Used in TLS versions prior to
    #: 1.3.
    certificate_url = 21

    #: certificate_status [:rfc:`6066`][:rfc:`9846`] -- Used in TLS versions prior
    #: to 1.3.
    certificate_status = 22

    #: supplemental_data [:rfc:`4680`][:rfc:`9846`] -- Used in TLS versions prior
    #: to 1.3.
    supplemental_data = 23

    #: key_update [:rfc:`9846`]
    key_update = 24

    #: compressed_certificate [:rfc:`8879`]
    compressed_certificate = 25

    #: ekt_key [:rfc:`8870`]
    ekt_key = 26

    #: message_hash [:rfc:`9846`]
    message_hash = 254

    #: Unassigned
    unassigned_255 = 255

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
    def _missing_(cls, value: 'int') -> 'HandshakeType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        if 18 <= value <= 19:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        if 27 <= value <= 253:
            #: Unassigned
            return cls._unregistered_member(value, 'Unassigned')
        return super()._missing_(value)
