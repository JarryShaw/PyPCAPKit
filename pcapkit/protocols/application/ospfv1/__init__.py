# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""OSPFv1 - Open Shortest Path First version 1
=================================================

.. module:: pcapkit.protocols.application.ospfv1

:mod:`pcapkit.protocols.application.ospfv1` holds the dissector,
:class:`~pcapkit.protocols.application.ospfv1.protocol.OSPFv1`, in
:mod:`~pcapkit.protocols.application.ospfv1.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.ospfv1.schema` and its data model in
:mod:`~pcapkit.protocols.application.ospfv1.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.ospfv1.protocol import OSPFv1

# Header Schemas
from pcapkit.protocols.application.ospfv1.schema import OSPFv1 as Schema_OSPFv1

# Data Models
from pcapkit.protocols.application.ospfv1.data import OSPFv1 as Data_OSPFv1

__all__ = ['OSPFv1']
