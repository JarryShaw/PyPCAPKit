# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""MSTP - Multiple Spanning Tree Protocol
============================================

.. module:: pcapkit.protocols.application.mstp

:mod:`pcapkit.protocols.application.mstp` holds the dissector,
:class:`~pcapkit.protocols.application.mstp.protocol.MSTP`, in
:mod:`~pcapkit.protocols.application.mstp.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.mstp.schema` and its data model in
:mod:`~pcapkit.protocols.application.mstp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.mstp.protocol import MSTP

# Header Schemas
from pcapkit.protocols.application.mstp.schema import MSTIMessage as Schema_MSTIMessage
from pcapkit.protocols.application.mstp.schema import MSTP as Schema_MSTP

# Data Models
from pcapkit.protocols.application.mstp.data import MSTP as Data_MSTP
from pcapkit.protocols.application.mstp.data import ConfigID as Data_ConfigID
from pcapkit.protocols.application.mstp.data import MSTIFlags as Data_MSTIFlags
from pcapkit.protocols.application.mstp.data import MSTIMessage as Data_MSTIMessage

__all__ = ['MSTP']
