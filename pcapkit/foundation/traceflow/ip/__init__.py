# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Follow IP Conversations
=============================

.. module:: pcapkit.foundation.traceflow.ip

:mod:`pcapkit.foundation.traceflow.ip` holds the IP flow tracing class,
:class:`~pcapkit.foundation.traceflow.ip.traceflow.IP`, in
:mod:`~pcapkit.foundation.traceflow.ip.traceflow`, and its data models in
:mod:`~pcapkit.foundation.traceflow.ip.data`.

Its data classes are importable as ``Data_*``.

.. versionadded:: 1.10.0

"""
from pcapkit.foundation.traceflow.ip.traceflow import IP

# Data Models
from pcapkit.foundation.traceflow.ip.data import Buffer as Data_Buffer
from pcapkit.foundation.traceflow.ip.data import Index as Data_Index
from pcapkit.foundation.traceflow.ip.data import Packet as Data_Packet

__all__ = ['IP']
