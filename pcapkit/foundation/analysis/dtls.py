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

    from pcapkit.const.tls.handshake_type import HandshakeType as Enum_HandshakeType
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

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.dtls.Datagram.packet>`
        holds the same result, decoded on its first read.

    """
    if not datagram.completed:
        return None
    # NOTE: a complete message is always one contiguous run.
    return _read_handshake((datagram.msg_type, datagram.length, datagram.message_seq),
                           cast('bytes', datagram.body))


def _read_handshake(header: 'tuple[Enum_HandshakeType, int, int]', body: 'bytes') -> 'Data_DTLSHandshake':
    """Decode a complete handshake message from its header and body.

    :func:`dtls_handshake` runs this, and so does the
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred` that
    :class:`~pcapkit.foundation.reassembly.dtls.DTLS` stores as a complete
    message's ``packet``.

    Args:
        header: The message's ``(msg_type, length, message_seq)``.
        body: The reassembled body.

    Returns:
        The message, unfragmented, its body raw if it does not decode.

    """
    msg_type, length, message_seq = header
    message = (bytes([int(msg_type)]) + length.to_bytes(3, 'big')
               + message_seq.to_bytes(2, 'big') + bytes(3)  # fragment_offset 0
               + length.to_bytes(3, 'big') + body)
    try:
        return DTLS.read_handshake(message)
    except ProtocolError:
        return Data_DTLSHandshake(
            msg_type=msg_type,
            length=length,
            body=body,
            message_seq=message_seq,
            fragment_offset=0,
            fragment_length=length,
            is_fragmented=False,
        )
