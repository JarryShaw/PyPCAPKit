# -*- coding: utf-8 -*-
"""TCP Datagram Analysis
=========================

.. module:: pcapkit.foundation.analysis.tcp

:mod:`pcapkit.foundation.analysis.tcp` contains
:func:`~pcapkit.foundation.analysis.tcp.tcp_datagram` only, which parses the
application-layer payload of a TCP datagram that
:class:`~pcapkit.foundation.reassembly.tcp.TCP` reassembled.

.. versionadded:: 1.6.0

"""
from typing import TYPE_CHECKING

from pcapkit.const.reg.apptype import TransportProtocol as Enum_TransportProtocol
from pcapkit.protocols.transport.tcp import TCP

if TYPE_CHECKING:
    from typing import Optional, Type

    from pcapkit.const.reg.apptype import TCP as AppType_TCP
    from pcapkit.foundation.reassembly.data.tcp import Datagram as TCP_Datagram
    from pcapkit.protocols.protocol import ProtocolBase

__all__ = ['tcp_datagram']


def tcp_datagram(datagram: 'TCP_Datagram') -> 'Optional[ProtocolBase]':
    """Parse the payload of a TCP datagram reassembled by
    :class:`~pcapkit.foundation.reassembly.tcp.TCP`.

    A reassembled datagram carries no protocol number, so its payload is
    dispatched on its ``(source, destination)`` ports by
    :meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`
    of :class:`~pcapkit.protocols.transport.tcp.TCP`. Each port is resolved to
    its :class:`~pcapkit.const.reg.apptype.tcp.TCP` member by
    :meth:`Transport._make_port
    <pcapkit.protocols.transport.transport.Transport._make_port>`, as
    :meth:`TCP._make_ports <pcapkit.foundation.reassembly.tcp.TCP._make_ports>`
    resolves them for the reassembly.

    Args:
        datagram: Reassembled datagram (:term:`reasm.tcp.datagram`).

    Returns:
        The parsed payload. A payload reported as one contiguous run is parsed
        whether or not ``datagram`` is complete, as ``strict=False`` reports an
        incomplete one. :data:`None` if the payload is the tuple of runs
        received, as ``strict=True`` reports an incomplete one.

    Note:
        :attr:`Datagram.packet <pcapkit.foundation.reassembly.data.tcp.Datagram.packet>`
        holds the same result, parsed on its first read, unless the
        reassembly's ``__protocol_type__`` names another protocol, which then
        parses it instead.

    """
    if isinstance(datagram.payload, tuple):
        return None
    transport = Enum_TransportProtocol.tcp
    ports = (TCP._make_port(datagram.id.src[1], transport),  # pylint: disable=protected-access
             TCP._make_port(datagram.id.dst[1], transport))  # pylint: disable=protected-access
    return _analyze_payload(TCP, ports, datagram.payload)


def _analyze_payload(protocol: 'Type[TCP]', ports: 'tuple[AppType_TCP, AppType_TCP]',
                     payload: 'bytes') -> 'ProtocolBase':
    """Parse a reassembled payload by its datagram's ports.

    :func:`tcp_datagram` runs this, and so does the
    :class:`~pcapkit.foundation.reassembly.data.data.Deferred` that
    :meth:`TCP.submit <pcapkit.foundation.reassembly.tcp.TCP.submit>` stores as
    a datagram's ``packet``, with the reassembly's own protocol bound as
    ``protocol``.

    Args:
        protocol: The TCP protocol whose ``analyze`` parses ``payload``.
        ports: The datagram's ``(source, destination)`` ports.
        payload: The reassembled payload.

    Returns:
        The parsed payload.

    """
    return protocol.analyze(ports, payload)
