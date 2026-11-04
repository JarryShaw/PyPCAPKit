# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""GRE - Generic Routing Encapsulation
=========================================

.. module:: pcapkit.protocols.link.gre

:mod:`pcapkit.protocols.link.gre` holds the dissector,
:class:`~pcapkit.protocols.link.gre.protocol.GRE`, in
:mod:`~pcapkit.protocols.link.gre.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.gre.schema` and its data model in
:mod:`~pcapkit.protocols.link.gre.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.gre.protocol import GRE

# Header Schemas
from pcapkit.protocols.link.gre.schema import GRE as Schema_GRE

# Data Models
from pcapkit.protocols.link.gre.data import GRE as Data_GRE

__all__ = ['GRE']
