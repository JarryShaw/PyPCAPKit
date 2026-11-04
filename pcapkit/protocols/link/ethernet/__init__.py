# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Ethernet Protocol
=======================

.. module:: pcapkit.protocols.link.ethernet

:mod:`pcapkit.protocols.link.ethernet` holds the dissector,
:class:`~pcapkit.protocols.link.ethernet.protocol.Ethernet`, in
:mod:`~pcapkit.protocols.link.ethernet.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.ethernet.schema` and its data model in
:mod:`~pcapkit.protocols.link.ethernet.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.ethernet.protocol import Ethernet

# Header Schemas
from pcapkit.protocols.link.ethernet.schema import Ethernet as Schema_Ethernet

# Data Models
from pcapkit.protocols.link.ethernet.data import Ethernet as Data_Ethernet

__all__ = ['Ethernet']
