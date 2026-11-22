# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""PPPoE - PPP over Ethernet
===============================

.. module:: pcapkit.protocols.link.pppoe

:mod:`pcapkit.protocols.link.pppoe` holds the dissector,
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE`, in
:mod:`~pcapkit.protocols.link.pppoe.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.pppoe.schema` and its data model in
:mod:`~pcapkit.protocols.link.pppoe.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.pppoe.protocol import PPPoE

# Header Schemas
from pcapkit.protocols.link.pppoe.schema import PPPoE as Schema_PPPoE
from pcapkit.protocols.link.pppoe.schema import Tag as Schema_Tag

# Data Models
from pcapkit.protocols.link.pppoe.data import PPPoE as Data_PPPoE
from pcapkit.protocols.link.pppoe.data import Tag as Data_Tag

__all__ = ['PPPoE']
