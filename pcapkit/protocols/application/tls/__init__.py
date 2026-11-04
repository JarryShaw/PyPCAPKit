# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""TLS/SSL - Transport Layer Security
========================================

.. module:: pcapkit.protocols.application.tls

:mod:`pcapkit.protocols.application.tls` holds the dissector,
:class:`~pcapkit.protocols.application.tls.protocol.TLS`, in
:mod:`~pcapkit.protocols.application.tls.protocol`, its header schema in
:mod:`~pcapkit.protocols.application.tls.schema` and its data model in
:mod:`~pcapkit.protocols.application.tls.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.application.tls.protocol import TLS

# Header Schemas
from pcapkit.protocols.application.tls.schema import TLS as Schema_TLS

# Data Models
from pcapkit.protocols.application.tls.data import TLS as Data_TLS

__all__ = ['TLS']
