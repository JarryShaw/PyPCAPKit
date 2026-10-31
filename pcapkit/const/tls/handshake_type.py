# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS/DTLS HandshakeType
============================

.. module:: pcapkit.const.tls.handshake_type

This module contains the constant enumeration for **TLS/DTLS HandshakeType**,
as assigned by IANA in the ``TLS HandshakeType`` registry [*]_, including the
DTLS-only connection-ID messages :rfc:`9147#section-5.2` adds to that same
registry. Every value IANA assigns is named below; the ranges it lists as
Unassigned fall through to :meth:`_missing_` like any other unassigned value.

Each member's name is the message name the protocol uses on the wire. IANA
suffixes ``_RESERVED`` onto the ones TLS 1.3 retired -- it keeps the code point
reserved rather than reassigning it -- which is a statement about the registry
rather than a different message name, so the suffix is not carried into the
member name and each such member instead records IANA's own comment on why the
assignment is retired.

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-7

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

    #: ``hello_request`` -- TLS 1.2 and earlier only [:rfc:`5246`]
    hello_request = 0

    #: ``client_hello`` [:rfc:`9846`]
    client_hello = 1

    #: ``server_hello`` [:rfc:`9846`]
    server_hello = 2

    #: ``hello_verify_request`` -- DTLS 1.2 and earlier only; DTLS 1.3 moved
    #: its return-routability role to the ``cookie`` extension
    #: (:rfc:`9147#section-5.1`) [:rfc:`6347`]
    hello_verify_request = 3

    #: ``new_session_ticket`` [:rfc:`9846`]
    new_session_ticket = 4

    #: ``end_of_early_data`` [:rfc:`9846`]
    end_of_early_data = 5

    #: ``hello_retry_request`` -- historical; the functionality moved to an
    #: extension, and TLS 1.3 carries it on a ``server_hello`` instead
    #: (:rfc:`9846#section-4.2.4`) [:rfc:`9846`]
    hello_retry_request = 6

    #: ``encrypted_extensions`` [:rfc:`9846`]
    encrypted_extensions = 8

    #: ``request_connection_id`` -- DTLS 1.3 only [:rfc:`9147`]
    request_connection_id = 9

    #: ``new_connection_id`` -- DTLS 1.3 only [:rfc:`9147`]
    new_connection_id = 10

    #: ``certificate`` [:rfc:`9846`]
    certificate = 11

    #: ``server_key_exchange`` -- TLS 1.2 and earlier only [:rfc:`5246`]
    server_key_exchange = 12

    #: ``certificate_request`` [:rfc:`9846`]
    certificate_request = 13

    #: ``server_hello_done`` -- TLS 1.2 and earlier only [:rfc:`5246`]
    server_hello_done = 14

    #: ``certificate_verify`` [:rfc:`9846`]
    certificate_verify = 15

    #: ``client_key_exchange`` -- TLS 1.2 and earlier only [:rfc:`5246`]
    client_key_exchange = 16

    #: ``client_certificate_request`` -- TLS 1.2 and earlier only, per IANA's
    #: own comment on this assignment [:rfc:`9261`]
    client_certificate_request = 17

    #: ``finished`` [:rfc:`9846`]
    finished = 20

    #: ``certificate_url`` -- TLS 1.2 and earlier only [:rfc:`6066`]
    certificate_url = 21

    #: ``certificate_status`` -- TLS 1.2 and earlier only [:rfc:`6066`]
    certificate_status = 22

    #: ``supplemental_data`` -- TLS 1.2 and earlier only [:rfc:`4680`]
    supplemental_data = 23

    #: ``key_update`` [:rfc:`9846`]
    key_update = 24

    #: ``compressed_certificate`` [:rfc:`8879`]
    compressed_certificate = 25

    #: ``ekt_key`` [:rfc:`8870`]
    ekt_key = 26

    #: ``message_hash`` [:rfc:`9846`]
    message_hash = 254

    @classmethod
    def _validate_value(cls, value: 'Any') -> 'None':
        """Reject ``value`` unless it passes the range check :meth:`_missing_` makes.

        Args:
            value: Value about to be looked up or minted.

        Raises:
            EnumValueError: If ``value`` fails that check.

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
        #: Unassigned
        return cls._unregistered_member(value, 'Unassigned')
