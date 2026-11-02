# -*- coding: utf-8 -*-
"""IP Datagram Analysis
========================

.. module:: pcapkit.foundation.analysis.ip

:mod:`pcapkit.foundation.analysis.ip` contains
:func:`~pcapkit.foundation.analysis.ip.ip_datagram` only, which parses the
payload of an IPv4 or IPv6 datagram that
:class:`~pcapkit.foundation.reassembly.ipv4.IPv4` or
:class:`~pcapkit.foundation.reassembly.ipv6.IPv6` reassembled.

.. versionadded:: 1.6.0

"""
from ipaddress import IPv6Address
from typing import TYPE_CHECKING

from pcapkit.protocols.internet.ipv4 import IPv4
from pcapkit.protocols.internet.ipv6 import IPv6

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.reg.transtype import TransType
    from pcapkit.foundation.reassembly.data.ip import Datagram as IP_Datagram
    from pcapkit.protocols.internet.ip import IP as IP_Protocol
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['ip_datagram']


def ip_datagram(datagram: 'IP_Datagram') -> 'Optional[ProtocolBase]':
    """Parse the payload of an IP datagram reassembled by
    :class:`~pcapkit.foundation.reassembly.ipv4.IPv4` or
    :class:`~pcapkit.foundation.reassembly.ipv6.IPv6`.

    The payload is dispatched on the datagram's payload protocol type -- the
    **Protocol** field for IPv4, the Fragment header's **Next Header** for
    IPv6 -- by :meth:`Protocol.analyze
    <pcapkit.protocols.protocol.Protocol.analyze>` of
    :class:`~pcapkit.protocols.internet.ipv4.IPv4` or
    :class:`~pcapkit.protocols.internet.ipv6.IPv6`, whichever the datagram's
    addresses belong to.

    Args:
        datagram: Reassembled datagram (:term:`reasm.ipv4.datagram` or
            :term:`reasm.ipv6.datagram`).

    Returns:
        The parsed payload. A payload reported as one contiguous run is parsed
        whether or not ``datagram`` is complete, as ``strict=False`` reports an
        incomplete one. :data:`None` if the payload is the tuple of runs
        received, as ``strict=True`` reports an incomplete one.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.ip.Datagram.packet>`
        holds the same result, parsed on its first read, unless the
        reassembly's ``__protocol_type__`` names another protocol, which then
        parses it instead.

    """
    if isinstance(datagram.payload, tuple):
        return None
    protocol = IPv6 if isinstance(datagram.id.src, IPv6Address) else IPv4
    return _analyze_payload(protocol, datagram.id.proto, datagram.payload)


def _analyze_payload(protocol: 'Type[IP_Protocol]', proto: 'TransType',
                     payload: 'bytes') -> 'ProtocolBase':
    """Parse a reassembled payload by its payload protocol type.

    :func:`ip_datagram` runs this, and so does the
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred` that
    :meth:`IP.submit <pcapkit.foundation.reassembly.ip.IP.submit>` stores as a
    datagram's ``packet``, with the reassembly's own protocol bound as
    ``protocol``.

    Args:
        protocol: The IP protocol whose ``analyze`` parses ``payload``.
        proto: The payload protocol type.
        payload: The reassembled payload.

    Returns:
        The parsed payload.

    """
    return protocol.analyze(proto, payload)
