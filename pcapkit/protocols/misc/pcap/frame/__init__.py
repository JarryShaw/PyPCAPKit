# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Frame Header
==================

.. module:: pcapkit.protocols.misc.pcap.frame

:mod:`pcapkit.protocols.misc.pcap.frame` holds the dissector,
:class:`~pcapkit.protocols.misc.pcap.frame.protocol.Frame`, in
:mod:`~pcapkit.protocols.misc.pcap.frame.protocol`, its header schema in
:mod:`~pcapkit.protocols.misc.pcap.frame.schema` and its data model in
:mod:`~pcapkit.protocols.misc.pcap.frame.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.misc.pcap.frame.protocol import Frame

# Header Schemas
from pcapkit.protocols.misc.pcap.frame.schema import Frame as Schema_Frame

# Data Models
from pcapkit.protocols.misc.pcap.frame.data import Frame as Data_Frame
from pcapkit.protocols.misc.pcap.frame.data import FrameInfo as Data_FrameInfo

__all__ = ['Frame']
