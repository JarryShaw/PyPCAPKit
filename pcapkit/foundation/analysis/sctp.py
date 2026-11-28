# -*- coding: utf-8 -*-
"""SCTP User-Message Analysis
================================

.. module:: pcapkit.foundation.analysis.sctp

:mod:`pcapkit.foundation.analysis.sctp` contains
:func:`~pcapkit.foundation.analysis.sctp.sctp_message` only, which parses the
user data of an SCTP user message that
:class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` reassembled.

.. versionadded:: 1.9.0

"""
from typing import TYPE_CHECKING

from pcapkit.protocols.transport.sctp.protocol import SCTP

if TYPE_CHECKING:
    from typing import Any, Iterable, Mapping, Optional, Type

    from pcapkit.const.sctp.payload_protocol_identifier import \
        PayloadProtocolIdentifier as Enum_PayloadProtocolIdentifier
    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.foundation.reassembly.sctp.data import Datagram as SCTP_Datagram
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['sctp_message']


def sctp_message(datagram: 'SCTP_Datagram', *,
                 layer: 'Optional[str]' = None,
                 protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                 context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None) -> 'Optional[ProtocolBase]':  # pylint: disable=line-too-long
    """Parse the user data of an SCTP user message reassembled by
    :class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP`.

    The user data is dispatched on the message's payload protocol identifier
    by :meth:`SCTP.analyze <pcapkit.protocols.transport.sctp.protocol.SCTP.analyze>`,
    as a frame's first DATA or I-DATA chunk is.

    Args:
        datagram: Reassembled message (:term:`reasm.sctp.datagram`).
        layer: Layer to parse until, by name; :data:`None` sets no stop.
        protocol: Protocol to parse until, by name, class or instance;
            :data:`None` sets no stop.
        context: Caller supplied parsing context, in any shape
            :func:`~pcapkit.interface.core.extract` takes (cf.
            :mod:`pcapkit.corekit.context`); :data:`None` supplies none.

    Returns:
        The parsed user data. A payload reported as one contiguous run is
        parsed whether or not ``datagram`` is complete, as ``strict=False``
        reports an incomplete one. :data:`None` if the payload is the tuple of
        runs received, as ``strict=True`` reports an incomplete one.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.sctp.data.Datagram.packet>`
        holds what this returns given the stops and context the extraction's
        engine parses its frames with, parsed on its first read, unless the
        reassembly's ``__protocol_type__`` names another protocol, which then
        parses it instead.

    """
    if isinstance(datagram.payload, tuple):
        return None
    # NOTE: Only those set, as the engine hands them (``EngineBase._setup_reassembly``).
    options = (('layer', layer), ('protocol', protocol), ('context', context))
    kwargs = {name: value for (name, value) in options if value is not None}  # type: dict[str, Any]
    return _analyze_payload(SCTP, datagram.ppid, datagram.payload, **kwargs)


def _analyze_payload(protocol: 'Type[SCTP]', ppid: 'Optional[Enum_PayloadProtocolIdentifier]',
                     payload: 'bytes', /, **kwargs: 'Any') -> 'ProtocolBase':
    """Parse a reassembled user message by its payload protocol identifier.

    :func:`sctp_message` runs this, and so does the
    :class:`~pcapkit.foundation.reassembly.data.Deferred` that
    :class:`~pcapkit.foundation.reassembly.sctp.reassembly.SCTP` stores as a
    datagram's ``packet``, with the reassembly's own protocol bound as
    ``protocol`` and the keywords its engine hands it as ``kwargs``.

    Args:
        protocol: The SCTP protocol whose ``analyze`` parses ``payload``.
        ppid: The message's payload protocol identifier.
        payload: The reassembled user data.
        **kwargs: Keyword arguments for ``analyze``: the stops and context
            the engine parses its frames with, which the reassembly hands on,
            or those :func:`sctp_message` is given.

    Returns:
        The parsed user data.

    """
    return protocol.analyze(ppid, payload, **kwargs)
