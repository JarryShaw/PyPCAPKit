# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Raw Packet Data
=====================

.. module:: pcapkit.protocols.misc.raw

:mod:`pcapkit.protocols.misc.raw` holds the dissector,
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`, in
:mod:`~pcapkit.protocols.misc.raw.protocol`, its header schema in
:mod:`~pcapkit.protocols.misc.raw.schema` and its data model in
:mod:`~pcapkit.protocols.misc.raw.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.misc.raw.protocol import Raw

# Header Schemas
from pcapkit.protocols.misc.raw.schema import Raw as Schema_Raw

# Data Models
from pcapkit.protocols.misc.raw.data import Raw as Data_Raw

__all__ = ['Raw']
