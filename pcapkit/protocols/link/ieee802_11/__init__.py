# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""IEEE 802.11 - Wireless LAN MAC Header
===========================================

.. module:: pcapkit.protocols.link.ieee802_11

:mod:`pcapkit.protocols.link.ieee802_11` holds the dissector,
:class:`~pcapkit.protocols.link.ieee802_11.protocol.IEEE802_11`, in
:mod:`~pcapkit.protocols.link.ieee802_11.protocol`, its header schema in
:mod:`~pcapkit.protocols.link.ieee802_11.schema` and its data model in
:mod:`~pcapkit.protocols.link.ieee802_11.data`.

Its schema and data classes are importable as ``Schema_*`` and ``Data_*``.

"""
from pcapkit.protocols.link.ieee802_11.protocol import IEEE802_11

# Header Schemas
from pcapkit.protocols.link.ieee802_11.schema import IEEE802_11 as Schema_IEEE802_11
from pcapkit.protocols.link.ieee802_11.schema import Layout as Schema_Layout

# Data Models
from pcapkit.protocols.link.ieee802_11.data import IEEE802_11 as Data_IEEE802_11
from pcapkit.protocols.link.ieee802_11.data import FrameControl as Data_FrameControl
from pcapkit.protocols.link.ieee802_11.data import HTControl as Data_HTControl
from pcapkit.protocols.link.ieee802_11.data import QoSControl as Data_QoSControl
from pcapkit.protocols.link.ieee802_11.data import SequenceControl as Data_SequenceControl

__all__ = ['IEEE802_11']
