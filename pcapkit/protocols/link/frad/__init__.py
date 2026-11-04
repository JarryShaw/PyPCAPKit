# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""FRAD - Frame Relay Access Device
======================================

.. module:: pcapkit.protocols.link.frad

:mod:`pcapkit.protocols.link.frad` holds the dissector,
:class:`~pcapkit.protocols.link.frad.protocol.FRAD`, in
:mod:`~pcapkit.protocols.link.frad.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.frad.schema` and its data model in
:mod:`~pcapkit.protocols.link.frad.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.frad.protocol import FRAD

# Header Schemas
from pcapkit.protocols.link.frad.schema import FRAD as Schema_FRAD

# Data Models
from pcapkit.protocols.link.frad.data import FRAD as Data_FRAD

__all__ = ['FRAD']
