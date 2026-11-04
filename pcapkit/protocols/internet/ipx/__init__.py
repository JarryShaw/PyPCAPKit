# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPX - Internetwork Packet Exchange
========================================

.. module:: pcapkit.protocols.internet.ipx

:mod:`pcapkit.protocols.internet.ipx` holds the dissector,
:class:`~pcapkit.protocols.internet.ipx.protocol.IPX`, in
:mod:`~pcapkit.protocols.internet.ipx.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.ipx.schema` and its data model in
:mod:`~pcapkit.protocols.internet.ipx.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.ipx.protocol import IPX

# Header Schemas
from pcapkit.protocols.internet.ipx.schema import IPX as Schema_IPX

# Data Models
from pcapkit.protocols.internet.ipx.data import IPX as Data_IPX
from pcapkit.protocols.internet.ipx.data import Address as Data_Address

__all__ = ['IPX']
