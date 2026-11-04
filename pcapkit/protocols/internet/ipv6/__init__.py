# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv6 - Internet Protocol version 6
========================================

.. module:: pcapkit.protocols.internet.ipv6

:mod:`pcapkit.protocols.internet.ipv6` holds the dissector,
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`, in
:mod:`~pcapkit.protocols.internet.ipv6.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.ipv6.schema` and its data model in
:mod:`~pcapkit.protocols.internet.ipv6.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.ipv6.protocol import IPv6

# Header Schemas
from pcapkit.protocols.internet.ipv6.schema import IPv6 as Schema_IPv6

# Data Models
from pcapkit.protocols.internet.ipv6.data import IPv6 as Data_IPv6

__all__ = ['IPv6']
