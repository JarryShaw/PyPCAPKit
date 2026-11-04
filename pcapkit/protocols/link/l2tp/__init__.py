# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""L2TP - Layer Two Tunnelling Protocol
==========================================

.. module:: pcapkit.protocols.link.l2tp

:mod:`pcapkit.protocols.link.l2tp` holds the dissector,
:class:`~pcapkit.protocols.link.l2tp.protocol.L2TP`, in
:mod:`~pcapkit.protocols.link.l2tp.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.l2tp.schema` and its data model in
:mod:`~pcapkit.protocols.link.l2tp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.l2tp.protocol import L2TP

# Header Schemas
from pcapkit.protocols.link.l2tp.schema import L2TP as Schema_L2TP

# Data Models
from pcapkit.protocols.link.l2tp.data import L2TP as Data_L2TP
from pcapkit.protocols.link.l2tp.data import Flags as Data_Flags

__all__ = ['L2TP']
