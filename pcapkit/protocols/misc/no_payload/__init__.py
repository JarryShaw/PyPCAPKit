# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""No-Payload Packet
=======================

.. module:: pcapkit.protocols.misc.no_payload

:mod:`pcapkit.protocols.misc.no_payload` holds the dissector,
:class:`~pcapkit.protocols.misc.no_payload.protocol.NoPayload`, in
:mod:`~pcapkit.protocols.misc.no_payload.protocol`, its header schema in
:mod:`~pcapkit.protocols.misc.no_payload.schema` and its data model in
:mod:`~pcapkit.protocols.misc.no_payload.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.misc.no_payload.protocol import NoPayload

# Header Schemas
from pcapkit.protocols.misc.no_payload.schema import NoPayload as Schema_NoPayload

# Data Models
from pcapkit.protocols.misc.no_payload.data import NoPayload as Data_NoPayload

__all__ = ['NoPayload']
