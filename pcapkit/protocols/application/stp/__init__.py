# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""STP - Spanning Tree Protocol
==================================

.. module:: pcapkit.protocols.application.stp

:mod:`pcapkit.protocols.application.stp` holds the family base,
:class:`~pcapkit.protocols.application.stp.protocol.STP`, in
:mod:`~pcapkit.protocols.application.stp.protocol`, and the data models its
members share in :mod:`~pcapkit.protocols.application.stp.data`.

Its data classes are importable as ``Data_*``.

"""
from pcapkit.protocols.application.stp.protocol import STP

# Data Models
from pcapkit.protocols.application.stp.data import BridgeID as Data_BridgeID
from pcapkit.protocols.application.stp.data import Flags as Data_Flags
from pcapkit.protocols.application.stp.data import PortID as Data_PortID

__all__ = ['STP']
