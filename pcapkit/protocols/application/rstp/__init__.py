# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""RSTP - Rapid Spanning Tree Protocol
=========================================

.. module:: pcapkit.protocols.application.rstp

:mod:`pcapkit.protocols.application.rstp` holds the dissector,
:class:`~pcapkit.protocols.application.rstp.protocol.RSTP`, in
:mod:`~pcapkit.protocols.application.rstp.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.rstp.schema` and its data model in
:mod:`~pcapkit.protocols.application.rstp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.rstp.protocol import RSTP

# Header Schemas
from pcapkit.protocols.application.rstp.schema import RSTP as Schema_RSTP

# Data Models
from pcapkit.protocols.application.rstp.data import RSTP as Data_RSTP

__all__ = ['RSTP']
