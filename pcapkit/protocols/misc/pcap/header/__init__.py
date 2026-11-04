# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Global Header
===================

.. module:: pcapkit.protocols.misc.pcap.header

:mod:`pcapkit.protocols.misc.pcap.header` holds the dissector,
:class:`~pcapkit.protocols.misc.pcap.header.protocol.Header`, in
:mod:`~pcapkit.protocols.misc.pcap.header.protocol`, its header schema in
:mod:`~pcapkit.protocols.misc.pcap.header.schema` and its data model in
:mod:`~pcapkit.protocols.misc.pcap.header.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.misc.pcap.header.protocol import Header

# Header Schemas
from pcapkit.protocols.misc.pcap.header.schema import Header as Schema_Header

# Data Models
from pcapkit.protocols.misc.pcap.header.data import Header as Data_Header
from pcapkit.protocols.misc.pcap.header.data import MagicNumber as Data_MagicNumber

__all__ = ['Header']
