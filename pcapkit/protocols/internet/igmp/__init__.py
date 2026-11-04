# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IGMP - Internet Group Management Protocol
===============================================

.. module:: pcapkit.protocols.internet.igmp

:mod:`pcapkit.protocols.internet.igmp` holds the dissector,
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP`, in
:mod:`~pcapkit.protocols.internet.igmp.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.igmp.schema` and its data model in
:mod:`~pcapkit.protocols.internet.igmp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.igmp.protocol import IGMP

# Header Schemas
from pcapkit.protocols.internet.igmp.schema import IGMP as Schema_IGMP

# Data Models
from pcapkit.protocols.internet.igmp.data import IGMP as Data_IGMP

__all__ = ['IGMP']
