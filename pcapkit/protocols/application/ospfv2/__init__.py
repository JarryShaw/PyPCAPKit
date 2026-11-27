# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""OSPFv2 - Open Shortest Path First version 2
=================================================

.. module:: pcapkit.protocols.application.ospfv2

:mod:`pcapkit.protocols.application.ospfv2` holds the dissector,
:class:`~pcapkit.protocols.application.ospfv2.protocol.OSPFv2`, in
:mod:`~pcapkit.protocols.application.ospfv2.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.ospfv2.schema` and its data model in
:mod:`~pcapkit.protocols.application.ospfv2.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.ospfv2.protocol import OSPFv2

# Header Schemas
from pcapkit.protocols.application.ospfv2.schema import \
    CryptographicAuthentication as Schema_CryptographicAuthentication
from pcapkit.protocols.application.ospfv2.schema import OSPFv2 as Schema_OSPFv2

# Data Models
from pcapkit.protocols.application.ospfv2.data import \
    CryptographicAuthentication as Data_CryptographicAuthentication
from pcapkit.protocols.application.ospfv2.data import OSPFv2 as Data_OSPFv2

__all__ = ['OSPFv2']
