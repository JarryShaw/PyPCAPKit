# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""OSPFv3 - Open Shortest Path First version 3
=================================================

.. module:: pcapkit.protocols.application.ospfv3

:mod:`pcapkit.protocols.application.ospfv3` holds the dissector,
:class:`~pcapkit.protocols.application.ospfv3.protocol.OSPFv3`, in
:mod:`~pcapkit.protocols.application.ospfv3.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.ospfv3.schema` and its data model in
:mod:`~pcapkit.protocols.application.ospfv3.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.ospfv3.protocol import OSPFv3

# Header Schemas
from pcapkit.protocols.application.ospfv3.schema import OSPFv3 as Schema_OSPFv3

# Data Models
from pcapkit.protocols.application.ospfv3.data import OSPFv3 as Data_OSPFv3

__all__ = ['OSPFv3']
