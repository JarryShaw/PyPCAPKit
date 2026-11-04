# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""VLAN - 802.1Q/802.1ad VLAN Tag Types
==========================================

.. module:: pcapkit.protocols.link.vlan

:mod:`pcapkit.protocols.link.vlan` holds the dissector,
:class:`~pcapkit.protocols.link.vlan.protocol.VLAN`, in
:mod:`~pcapkit.protocols.link.vlan.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.vlan.schema` and its data model in
:mod:`~pcapkit.protocols.link.vlan.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.vlan.protocol import VLAN

# Header Schemas
from pcapkit.protocols.link.vlan.schema import TCI as Schema_TCI
from pcapkit.protocols.link.vlan.schema import VLAN as Schema_VLAN

# Data Models
from pcapkit.protocols.link.vlan.data import TCI as Data_TCI
from pcapkit.protocols.link.vlan.data import VLAN as Data_VLAN

__all__ = ['VLAN']
