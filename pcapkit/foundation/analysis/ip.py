# -*- coding: utf-8 -*-
"""IP Datagram Analysis
==========================

.. module:: pcapkit.foundation.analysis.ip

:mod:`pcapkit.foundation.analysis.ip` contains
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` only, which parses the
payload of an IPv4 or IPv6 datagram that
:class:`~pcapkit.foundation.reassembly.ipv4.reassembly.IPv4` or
:class:`~pcapkit.foundation.reassembly.ipv6.reassembly.IPv6` reassembled.

.. versionadded:: 1.6.0

"""
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

from pcapkit.protocols.internet.ipv4.protocol import IPv4
from pcapkit.protocols.internet.ipv6.protocol import IPv6

if TYPE_CHECKING:
    from typing import Any, Iterable, Mapping, Optional, Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.corekit.context import ContextRegistry, ProtocolContext
    from pcapkit.foundation.reassembly.ip.data import Datagram as IP_Datagram
    from pcapkit.protocols.internet.ip.protocol import IP as IP_Protocol
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['ip_datagram']


def ip_datagram(datagram: 'IP_Datagram', *,
                layer: 'Optional[str]' = None,
                protocol: 'Optional[str | ProtocolBase | Type[ProtocolBase]]' = None,
                context: 'Optional[ContextRegistry | ProtocolContext | Mapping[str, ProtocolContext] | Iterable[ProtocolContext]]' = None) -> 'Optional[ProtocolBase]':  # pylint: disable=line-too-long
    """Parse the payload of an IP datagram reassembled by
    :class:`~pcapkit.foundation.reassembly.ipv4.reassembly.IPv4` or
    :class:`~pcapkit.foundation.reassembly.ipv6.reassembly.IPv6`.

    The payload is dispatched on the datagram's payload protocol type -- the
    **Protocol** field for IPv4, the Fragment header's **Next Header** for
    IPv6 -- by :meth:`Protocol.analyze
    <pcapkit.protocols.protocol.Protocol.analyze>` of
    :class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` or
    :class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`, whichever the datagram's
    addresses belong to.

    Args:
        datagram: Reassembled datagram (:term:`reasm.ipv4.datagram` or
            :term:`reasm.ipv6.datagram`).
        layer: Layer to parse until, by name; :data:`None` sets no stop.
        protocol: Protocol to parse until, by name, class or instance;
            :data:`None` sets no stop.
        context: Caller supplied parsing context, in any shape
            :func:`~pcapkit.interface.core.extract` takes (cf.
            :mod:`pcapkit.corekit.context`); :data:`None` supplies none.

    Returns:
        The parsed payload. A payload reported as one contiguous run is parsed
        whether or not ``datagram`` is complete, as ``strict=False`` reports an
        incomplete one. :data:`None` if the payload is the tuple of runs
        received, as ``strict=True`` reports an incomplete one.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.ip.data.Datagram.packet>`
        holds what this returns given the stops and context the extraction's
        engine parses its frames with (:issue:`2933`), parsed on its first
        read, unless the reassembly's ``__protocol_type__`` names another
        protocol, which then parses it instead.

    .. versionchanged:: 1.8.0

       Takes keyword-only ``layer``, ``protocol`` and ``context``, as the
       parse behind :attr:`Datagram.packet
       <pcapkit.foundation.reassembly.ip.data.Datagram.packet>` does
       (:issue:`2947`).

    """
    if isinstance(datagram.payload, tuple):
        return None
    klass = IPv6 if isinstance(datagram.id.src, IPv6Address) else IPv4
    # NOTE: Only those set, as the engine hands them (``EngineBase._setup_reassembly``).
    options = (('layer', layer), ('protocol', protocol), ('__context__', context))
    kwargs = {name: value for (name, value) in options if value is not None}  # type: dict[str, Any]
    return _analyze_payload(klass, datagram.id.proto, datagram.payload, **kwargs)


def _analyze_payload(protocol: 'Type[IP_Protocol]', proto: 'TransType',
                     payload: 'bytes', /, **kwargs: 'Any') -> 'ProtocolBase':
    """Parse a reassembled payload by its payload protocol type.

    :func:`ip_datagram` runs this, and so does the
    :class:`~pcapkit.foundation.reassembly.data.Deferred` that
    :meth:`IP.submit <pcapkit.foundation.reassembly.ip.reassembly.IP.submit>` stores as a
    datagram's ``packet``, with the reassembly's own protocol bound as
    ``protocol`` and the keywords its engine hands it as ``kwargs``.

    Args:
        protocol: The IP protocol whose ``analyze`` parses ``payload``.
        proto: The payload protocol type.
        payload: The reassembled payload.
        **kwargs: Keyword arguments for ``analyze``: the stops and context
            the engine parses its frames with, which the reassembly hands on,
            or those :func:`ip_datagram` is given.

    Returns:
        The parsed payload.

    """
    return protocol.analyze(proto, payload, **kwargs)
