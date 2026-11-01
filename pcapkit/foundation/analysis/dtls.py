# -*- coding: utf-8 -*-
"""DTLS Handshake-Message Analysis
=====================================

.. module:: pcapkit.foundation.analysis.dtls

:mod:`pcapkit.foundation.analysis.dtls` contains
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` only, which decodes a
DTLS handshake message that :class:`~pcapkit.foundation.reassembly.dtls.DTLS`
reassembled (:rfc:`6347#section-4.2.3`).

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.protocols.application.dtls import DTLS
from pcapkit.protocols.data.application.dtls import DTLSHandshake as Data_DTLSHandshake
from pcapkit.utilities.exceptions import ProtocolError

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram

__all__ = ['dtls_handshake']


def dtls_handshake(datagram: 'DTLS_Datagram') -> 'Optional[Data_DTLSHandshake]':
    """Parse a DTLS handshake message reassembled by
    :class:`~pcapkit.foundation.reassembly.dtls.DTLS`.

    The message is read as if it had arrived unfragmented, ``fragment_offset``
    0 and ``fragment_length`` its ``length`` (:rfc:`6347#section-4.2.3`), by
    :meth:`DTLS.read_handshake
    <pcapkit.protocols.application.dtls.DTLS.read_handshake>`. So a
    ``ClientHello`` or ``ServerHello`` body decodes as an unfragmented one
    does, whatever its length, and any other body stays raw octets.

    Args:
        datagram: Reassembled message (:term:`reasm.dtls.datagram`).

    Returns:
        The message, unfragmented. Its body stays the raw reassembled octets if
        they do not decode as its ``msg_type``. :data:`None` if ``datagram`` is
        incomplete, as its missing octets cannot be decoded.

    """
    if not datagram.completed:
        return None
    # NOTE: a complete message is always one contiguous run.
    body = cast('bytes', datagram.body)
    message = (bytes([int(datagram.msg_type)]) + datagram.length.to_bytes(3, 'big')
               + datagram.message_seq.to_bytes(2, 'big') + bytes(3)  # fragment_offset 0
               + datagram.length.to_bytes(3, 'big') + body)
    try:
        return DTLS.read_handshake(message)
    except ProtocolError:
        return Data_DTLSHandshake(
            msg_type=datagram.msg_type,
            length=datagram.length,
            body=body,
            message_seq=datagram.message_seq,
            fragment_offset=0,
            fragment_length=datagram.length,
            is_fragmented=False,
        )
