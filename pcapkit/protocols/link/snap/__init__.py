# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""SNAP - Subnetwork Access Protocol
=======================================

.. module:: pcapkit.protocols.link.snap

:mod:`pcapkit.protocols.link.snap` holds the dissector,
:class:`~pcapkit.protocols.link.snap.protocol.SNAP`, in
:mod:`~pcapkit.protocols.link.snap.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.snap.schema` and its data model in
:mod:`~pcapkit.protocols.link.snap.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.snap.protocol import SNAP

# Header Schemas
from pcapkit.protocols.link.snap.schema import SNAP as Schema_SNAP

# Data Models
from pcapkit.protocols.link.snap.data import SNAP as Data_SNAP

__all__ = ['SNAP']
