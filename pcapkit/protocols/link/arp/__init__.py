# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""ARP - Address Resolution Protocol
=======================================

.. module:: pcapkit.protocols.link.arp

:mod:`pcapkit.protocols.link.arp` holds the dissector,
:class:`~pcapkit.protocols.link.arp.protocol.ARP`, in
:mod:`~pcapkit.protocols.link.arp.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.arp.schema` and its data model in
:mod:`~pcapkit.protocols.link.arp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.arp.protocol import ARP

# Header Schemas
from pcapkit.protocols.link.arp.schema import ARP as Schema_ARP

# Data Models
from pcapkit.protocols.link.arp.data import ARP as Data_ARP
from pcapkit.protocols.link.arp.data import Address as Data_Address
from pcapkit.protocols.link.arp.data import Type as Data_Type

__all__ = ['ARP']
