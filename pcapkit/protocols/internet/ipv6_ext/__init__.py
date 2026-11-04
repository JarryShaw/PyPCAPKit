# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv6-Ext - IPv6 Extension Header
======================================

.. module:: pcapkit.protocols.internet.ipv6_ext

:mod:`pcapkit.protocols.internet.ipv6_ext` holds the dissector,
:class:`~pcapkit.protocols.internet.ipv6_ext.protocol.IPv6_Ext`, in
:mod:`~pcapkit.protocols.internet.ipv6_ext.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.ipv6_ext.schema` and its data model in
:mod:`~pcapkit.protocols.internet.ipv6_ext.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.ipv6_ext.protocol import IPv6_Ext

# Header Schemas
from pcapkit.protocols.internet.ipv6_ext.schema import IPv6_Ext as Schema_IPv6_Ext

# Data Models
from pcapkit.protocols.internet.ipv6_ext.data import IPv6_Ext as Data_IPv6_Ext

__all__ = ['IPv6_Ext']
