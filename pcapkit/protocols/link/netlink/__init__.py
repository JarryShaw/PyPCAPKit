# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Netlink - Linux Netlink Socket Framing
============================================

.. module:: pcapkit.protocols.link.netlink

:mod:`pcapkit.protocols.link.netlink` holds the dissector,
:class:`~pcapkit.protocols.link.netlink.protocol.Netlink`, in
:mod:`~pcapkit.protocols.link.netlink.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.netlink.schema` and its data model in
:mod:`~pcapkit.protocols.link.netlink.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.netlink.protocol import Netlink

# Header Schemas
from pcapkit.protocols.link.netlink.schema import Netlink as Schema_Netlink

# Data Models
from pcapkit.protocols.link.netlink.data import Netlink as Data_Netlink

__all__ = ['Netlink']
