# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Trace Flows
=================

.. module:: pcapkit.foundation.traceflow

:mod:`pcapkit.traceflow` implements flow tracing functions for
:mod:`pcapkit` package.

.. note::

   This was implemented as the demand of my mate
   `@gousaiyang <https://github.com/gousaiyang>`__.

"""
# Base Class for TraceFlow
from pcapkit.foundation.traceflow.traceflow import TraceFlow

# TCP Flow Tracing
from pcapkit.foundation.traceflow.tcp import TCP as TCP_TraceFlow

__all__ = [
    'TCP_TraceFlow',
]


from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Optional


@info_final
class TraceFlowManager(Info):
    """TraceFlow Manager."""

    #: TCP reassembly.
    tcp: 'TCP_TraceFlow'

    if TYPE_CHECKING:
        def __init__(self, tcp: 'Optional[TCP_TraceFlow]') -> 'None': ...  # pylint: disable=unused-argument,super-init-not-called,multiple-statements,line-too-long
