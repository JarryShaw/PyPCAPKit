# -*- coding: utf-8 -*-
# pylint: disable=line-too-long,consider-using-f-string
"""TLS/DTLS Content Types
============================

.. module:: pcapkit.const.tls.content_type

This module contains the constant enumeration for **TLS/DTLS Content Types**,
as assigned by IANA in the ``TLS ContentType`` registry [*]_. The record-layer
header -- :rfc:`9846#section-5.1` for TLS, :rfc:`9147#section-4` for DTLS --
is identical in shape between the two, and this is the type it dispatches on.

Every value IANA assigns is named below. Everything else in the 0-255 range it
lists as Unassigned (0-19 and 28-31, plus 64-255, which :rfc:`9443` reserves
for multiplexing with other protocols on the same port) or as Reserved (32-63,
:rfc:`9147`), and :meth:`ContentType._missing_` resolves those to an
``Unassigned`` member without growing the registry.

.. [*] https://www.iana.org/assignments/tls-parameters/tls-parameters.xhtml#tls-parameters-5

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

    #: Invalid -- a sentinel :rfc:`9846#section-5.1` names so that a record
    #: carrying it can be rejected, never a value sent on the wire; IANA keeps
    #: 0 inside its Unassigned 0-19 band rather than assigning it [:rfc:`9846`]
    invalid = 0

    #: ChangeCipherSpec [:rfc:`9846`]
    change_cipher_spec = 20

    #: Alert [:rfc:`9846`]
    alert = 21

    #: Handshake [:rfc:`9846`]
    handshake = 22

    #: Application Data [:rfc:`9846`]
    application_data = 23

    #: Heartbeat [:rfc:`6520`]
    heartbeat = 24

    #: ``tls12_cid`` [:rfc:`9146`]
    tls12_cid = 25

    #: ACK -- DTLS 1.3 only [:rfc:`9147`]
    ack = 26

    #: ``return_routability_check`` -- DTLS connection-ID path validation
    #: [:rfc:`9853`]
    return_routability_check = 27

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
    def _missing_(cls, value: 'int') -> 'ContentType':
        """Lookup function used when value is not found.

        Args:
            value: Value to get enum item.

        """
        if not (isinstance(value, int) and 0 <= value <= 255):
            raise ValueError('%r is not a valid %s' % (value, cls.__name__))
        #: Unassigned
        return cls._unregistered_member(value, 'Unassigned')
