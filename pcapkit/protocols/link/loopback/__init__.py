# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""BSD Loopback Encapsulation
================================

.. module:: pcapkit.protocols.link.loopback

:mod:`pcapkit.protocols.link.loopback` holds the dissector,
:class:`~pcapkit.protocols.link.loopback.protocol.Loopback`, in
:mod:`~pcapkit.protocols.link.loopback.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.loopback.schema` and its data model in
:mod:`~pcapkit.protocols.link.loopback.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.loopback.protocol import Loopback

# Header Schemas
from pcapkit.protocols.link.loopback.schema import Loopback as Schema_Loopback

# Data Models
from pcapkit.protocols.link.loopback.data import Loopback as Data_Loopback

__all__ = ['Loopback']
