# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""UDP - User Datagram Protocol
==================================

.. module:: pcapkit.protocols.transport.udp

:mod:`pcapkit.protocols.transport.udp` holds the dissector,
:class:`~pcapkit.protocols.transport.udp.protocol.UDP`, in
:mod:`~pcapkit.protocols.transport.udp.protocol`, its header schema in
:mod:`~pcapkit.protocols.transport.udp.schema` and its data model in
:mod:`~pcapkit.protocols.transport.udp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.transport.udp.protocol import UDP

# Header Schemas
from pcapkit.protocols.transport.udp.schema import UDP as Schema_UDP

# Data Models
from pcapkit.protocols.transport.udp.data import UDP as Data_UDP

__all__ = ['UDP']
