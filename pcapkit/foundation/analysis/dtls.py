# -*- coding: utf-8 -*-
"""DTLS Handshake-Message Analysis
=====================================

.. module:: pcapkit.foundation.analysis.dtls

:mod:`pcapkit.foundation.analysis.dtls` contains
:func:`~pcapkit.foundation.analysis.dtls.dtls_handshake` only, which decodes a
DTLS handshake message that :class:`~pcapkit.foundation.reassembly.dtls.DTLS`
reassembled (:rfc:`6347#section-4.2.3`). The decode itself is
:meth:`DTLS.analyze_handshake
<pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>` (:issue:`2622`).

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.protocols.application.dtls.protocol import DTLS

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.foundation.reassembly.data.dtls import Datagram as DTLS_Datagram
    from pcapkit.protocols.application.dtls.data import DTLSHandshake as Data_DTLSHandshake

__all__ = ['dtls_handshake']


def dtls_handshake(datagram: 'DTLS_Datagram') -> 'Optional[Data_DTLSHandshake]':
    """Parse a DTLS handshake message reassembled by
    :class:`~pcapkit.foundation.reassembly.dtls.DTLS`.

    The message is decoded by :meth:`DTLS.analyze_handshake
    <pcapkit.protocols.application.dtls.protocol.DTLS.analyze_handshake>`, which reads
    it as if it had arrived unfragmented, ``fragment_offset`` 0 and
    ``fragment_length`` its ``length`` (:rfc:`6347#section-4.2.3`). So a
    ``ClientHello``, ``ServerHello`` or ``EncryptedExtensions`` body decodes
    as an unfragmented one does, whatever its length, and any other body stays
    raw octets.

    Args:
        datagram: Reassembled message (:term:`reasm.dtls.datagram`).

    Returns:
        The message, unfragmented. Its body stays the raw reassembled octets if
        they do not decode as its ``msg_type``. :data:`None` if ``datagram`` is
        incomplete, as its missing octets cannot be decoded.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.dtls.Datagram.packet>`
        holds the same result, decoded on its first read, unless the
        reassembly's ``__protocol_type__`` names another protocol, whose
        ``analyze_handshake`` then decodes it instead.

    """
    if not datagram.completed:
        return None
    # NOTE: a complete message is always one contiguous run.
    return DTLS.analyze_handshake((datagram.msg_type, datagram.length, datagram.message_seq),
                                  cast('bytes', datagram.body))
