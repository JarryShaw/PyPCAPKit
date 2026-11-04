# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IP Pseudo-Header
======================

.. module:: pcapkit.protocols.misc.checksum.ip_pseudo

:mod:`pcapkit.protocols.misc.checksum.ip_pseudo` holds the dissector,
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol.IP_Pseudo`, in
:mod:`~pcapkit.protocols.misc.checksum.ip_pseudo.protocol`, its header schema in
:mod:`~pcapkit.protocols.misc.checksum.ip_pseudo.schema` and its data model in
:mod:`~pcapkit.protocols.misc.checksum.ip_pseudo.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.misc.checksum.ip_pseudo.protocol import IP_Pseudo

# Header Schemas
from pcapkit.protocols.misc.checksum.ip_pseudo.schema import IP_Pseudo as Schema_IP_Pseudo

# Data Models
from pcapkit.protocols.misc.checksum.ip_pseudo.data import IP_Pseudo as Data_IP_Pseudo

__all__ = ['IP_Pseudo']
