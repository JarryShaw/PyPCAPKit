# -*- coding: utf-8 -*-
"""TLS Record Analysis
=========================

.. module:: pcapkit.foundation.analysis.tls

:mod:`pcapkit.foundation.analysis.tls` contains
:func:`~pcapkit.foundation.analysis.tls.tls_record` only, which decodes a TLS record
that :class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS` reassembled from a TCP
stream (:rfc:`9846#section-5`). The decode itself is :meth:`TLS.analyze_record
<pcapkit.protocols.application.tls.protocol.TLS.analyze_record>`.

.. versionadded:: 1.9.0

"""
from typing import TYPE_CHECKING, cast

from pcapkit.protocols.application.tls.protocol import TLS

if TYPE_CHECKING:
    from typing import Optional

    from pcapkit.foundation.reassembly.tls.data import Datagram as TLS_Datagram
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['tls_record']


def tls_record(datagram: 'TLS_Datagram') -> 'Optional[ProtocolBase]':
    """Parse a TLS record reassembled by
    :class:`~pcapkit.foundation.reassembly.tls.reassembly.TLS`.

    The record is decoded by :meth:`TLS.analyze_record
    <pcapkit.protocols.application.tls.protocol.TLS.analyze_record>`, as a segment's
    first record is, so a record split across segments decodes as a whole one does.

    Args:
        datagram: Reassembled record (:term:`reasm.tls.datagram`).

    Returns:
        The record, as a :class:`~pcapkit.protocols.application.tls.protocol.TLS`
        instance, or :class:`~pcapkit.protocols.misc.raw.protocol.Raw` if it does not
        decode. :data:`None` if ``datagram`` is incomplete, as its missing octets
        cannot be decoded.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.tls.data.Datagram.packet>`
        holds the same result, decoded on its first read, unless the reassembly's
        ``__protocol_type__`` names another protocol, whose ``analyze_record`` then
        decodes it instead.

    """
    if not datagram.completed:
        return None
    # NOTE: a complete record's fragment is always one contiguous run.
    return TLS.analyze_record((datagram.content_type, datagram.version), cast('bytes', datagram.fragment))
