# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Follow TCP Streams
========================

.. module:: pcapkit.foundation.traceflow.tcp

:mod:`pcapkit.foundation.traceflow.tcp` holds the TCP flow tracing class,
:class:`~pcapkit.foundation.traceflow.tcp.traceflow.TCP`, in
:mod:`~pcapkit.foundation.traceflow.tcp.traceflow`, and its data models in
:mod:`~pcapkit.foundation.traceflow.tcp.data`.

Its data classes are importable as ``Data_*``.

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.traceflow.tcp.logger``, with no alias: it is in
   :mod:`~pcapkit.foundation.traceflow.tcp.traceflow`, and
   :mod:`pcapkit.foundation.traceflow.tcp` exports the flow tracing class alone
   (:issue:`2882`).

"""
from pcapkit.foundation.traceflow.tcp.traceflow import TCP

# Data Models
from pcapkit.foundation.traceflow.tcp.data import Buffer as Data_Buffer
from pcapkit.foundation.traceflow.tcp.data import Index as Data_Index
from pcapkit.foundation.traceflow.tcp.data import Packet as Data_Packet

__all__ = ['TCP']
