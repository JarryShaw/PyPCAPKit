# -*- coding: utf-8 -*-
"""Reassembled Payload Analysis
==================================

.. module:: pcapkit.foundation.analysis

:mod:`pcapkit.foundation.analysis` parses what a
:mod:`pcapkit.foundation.reassembly` engine reassembled into a usable result,
so that a caller does not interpret the raw reassembled octets itself
(:ref:`reassembly-integration`).

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.const.tls.content_type import ContentType as Enum_ContentType
from pcapkit.protocols.application.dtls import DTLS
from pcapkit.protocols.data.application.dtls import DTLSHandshake as Data_DTLSHandshake
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram

__all__ = ['dtls_handshake']

#: Legacy record version of the record :func:`dtls_handshake` parses a message
#: in, DTLS 1.2's (:rfc:`6347#section-4.1`). Every tier lays out a handshake
#: message alike, so the version does not change how it decodes.
_RECORD_VERSION = 0xFEFD
#: Longest message a record's 16-bit ``length`` holds (:rfc:`6347#section-4.1`).
_MAX_RECORD_FRAGMENT = 0xFFFF


def dtls_handshake(datagram: 'DTLS_Datagram') -> 'Optional[Data_DTLSHandshake]':
    """Parse a DTLS handshake message reassembled by
    :class:`~pcapkit.foundation.reassembly.dtls.DTLS`.

    The message is read as if it had arrived unfragmented, ``fragment_offset``
    0 and ``fragment_length`` its ``length`` (:rfc:`6347#section-4.2.3`), by
    :class:`~pcapkit.protocols.application.dtls.DTLS` itself in a cleartext
    ``handshake`` record. So a ``ClientHello`` or ``ServerHello`` body decodes
    as an unfragmented one does, and any other body stays raw octets.

    Args:
        datagram: Reassembled message (:term:`reasm.dtls.datagram`).

    Returns:
        The message, unfragmented. Its body stays the raw reassembled octets if
        they do not decode as its ``msg_type``, or if the message is too long
        for one record to carry. :data:`None` if ``datagram`` is incomplete,
        as its missing octets cannot be decoded.

    """
    if not datagram.completed:
        return None
    # NOTE: a complete message is always one contiguous run.
    body = cast('bytes', datagram.body)
    message = (bytes([int(datagram.msg_type)]) + datagram.length.to_bytes(3, 'big')
               + datagram.message_seq.to_bytes(2, 'big') + bytes(3)
               + datagram.length.to_bytes(3, 'big') + body)

    if len(message) <= _MAX_RECORD_FRAGMENT:
        record = (bytes([int(Enum_ContentType.handshake)]) + _RECORD_VERSION.to_bytes(2, 'big')
                  + bytes(8)  # epoch 0, i.e. cleartext, and sequence number 0
                  + len(message).to_bytes(2, 'big') + message)
        try:
            content = DTLS(record, len(record)).info.content
        except ProtocolError:
            content = None
        if isinstance(content, tuple) and len(content) == 1:
            return cast('Data_DTLSHandshake', content[0])

    return Data_DTLSHandshake(
        msg_type=datagram.msg_type,
        length=datagram.length,
        body=body,
        message_seq=datagram.message_seq,
        fragment_offset=0,
        fragment_length=datagram.length,
        is_fragmented=False,
    )
