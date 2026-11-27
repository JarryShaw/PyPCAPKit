# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""LLC - Logical Link Control
================================

.. module:: pcapkit.protocols.link.llc

:mod:`pcapkit.protocols.link.llc` holds the dissector,
:class:`~pcapkit.protocols.link.llc.protocol.LLC`, in
:mod:`~pcapkit.protocols.link.llc.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.llc.schema` and its data model in
:mod:`~pcapkit.protocols.link.llc.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.llc.protocol import LLC

# Header Schemas
from pcapkit.protocols.link.llc.schema import LLC as Schema_LLC

# Data Models
from pcapkit.protocols.link.llc.data import LLC as Data_LLC
from pcapkit.protocols.link.llc.data import Control as Data_Control

__all__ = ['LLC']
