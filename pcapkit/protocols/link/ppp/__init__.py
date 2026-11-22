# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""PPP - Point-to-Point Protocol
===================================

.. module:: pcapkit.protocols.link.ppp

:mod:`pcapkit.protocols.link.ppp` holds the dissector,
:class:`~pcapkit.protocols.link.ppp.protocol.PPP`, in
:mod:`~pcapkit.protocols.link.ppp.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.ppp.schema` and its data model in
:mod:`~pcapkit.protocols.link.ppp.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.ppp.protocol import PPP

# Header Schemas
from pcapkit.protocols.link.ppp.schema import PPP as Schema_PPP
from pcapkit.protocols.link.ppp.schema import ControlHeader as Schema_ControlHeader
from pcapkit.protocols.link.ppp.schema import ControlPacket as Schema_ControlPacket

# Data Models
from pcapkit.protocols.link.ppp.data import PPP as Data_PPP
from pcapkit.protocols.link.ppp.data import ControlPacket as Data_ControlPacket

__all__ = ['PPP']
