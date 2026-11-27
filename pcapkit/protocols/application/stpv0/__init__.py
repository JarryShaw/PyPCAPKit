# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""STPv0 - Spanning Tree Protocol
====================================

.. module:: pcapkit.protocols.application.stpv0

:mod:`pcapkit.protocols.application.stpv0` holds the dissector,
:class:`~pcapkit.protocols.application.stpv0.protocol.STPv0`, in
:mod:`~pcapkit.protocols.application.stpv0.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.stpv0.schema` and its data model in
:mod:`~pcapkit.protocols.application.stpv0.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.stpv0.protocol import STPv0

# Header Schemas
from pcapkit.protocols.application.stpv0.schema import STPv0 as Schema_STPv0

# Data Models
from pcapkit.protocols.application.stpv0.data import ConfigFlags as Data_ConfigFlags
from pcapkit.protocols.application.stpv0.data import STPv0 as Data_STPv0

__all__ = ['STPv0']
