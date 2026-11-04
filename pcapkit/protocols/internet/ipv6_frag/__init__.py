# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IPv6-Frag - Fragment Header for IPv6
==========================================

.. module:: pcapkit.protocols.internet.ipv6_frag

:mod:`pcapkit.protocols.internet.ipv6_frag` holds the dissector,
:class:`~pcapkit.protocols.internet.ipv6_frag.protocol.IPv6_Frag`, in
:mod:`~pcapkit.protocols.internet.ipv6_frag.protocol`, its header schema in
:mod:`~pcapkit.protocols.internet.ipv6_frag.schema` and its data model in
:mod:`~pcapkit.protocols.internet.ipv6_frag.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.internet.ipv6_frag.protocol import IPv6_Frag

# Header Schemas
from pcapkit.protocols.internet.ipv6_frag.schema import IPv6_Frag as Schema_IPv6_Frag

# Data Models
from pcapkit.protocols.internet.ipv6_frag.data import IPv6_Frag as Data_IPv6_Frag

__all__ = ['IPv6_Frag']
