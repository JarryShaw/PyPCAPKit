# -*- coding: utf-8 -*-
# pylint: disable=unused-import
"""Trace Flows
=================

.. module:: pcapkit.foundation.traceflow

:mod:`pcapkit.foundation.traceflow` implements flow tracing functions for
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
    'TraceFlowManager',                     # TraceFlow Manager, defined below
]


from typing import TYPE_CHECKING

from pcapkit.corekit.infoclass import Info, info_final

if TYPE_CHECKING:
    from typing import Iterable, Mapping, Optional

    from pcapkit.foundation.traceflow.traceflow import TraceFlowBase


@info_final
class TraceFlowManager(Info):
    """Flow tracing manager.

    The enabled flow tracers, each under the name it is registered by in
    :attr:`Extractor.__traceflow__
    <pcapkit.foundation.extraction.Extractor.__traceflow__>`, in the order they
    were given. A name given :data:`None` is left out, so the manager holds
    exactly the tracers an engine feeds.

    Args:
        dict_: flow tracers by name, as a mapping or as ``(name, tracer)`` pairs
        **kwargs: flow tracers by name

    .. versionchanged:: 1.7.0

       Holds any registered flow tracer, and only the enabled ones, as
       :class:`~pcapkit.foundation.reassembly.ReassemblyManager` holds
       reassemblers, where it had a ``tcp`` field, :data:`None` when disabled
       (:issue:`2839`).

    """

    def __init__(self, dict_: 'Optional[Mapping[str, Optional[TraceFlowBase]] | Iterable[tuple[str, Optional[TraceFlowBase]]]]' = None,  # pylint: disable=line-too-long,super-init-not-called
                 **kwargs: 'Optional[TraceFlowBase]') -> 'None':
        given = dict(dict_ or (), **kwargs)
        self.__update__({name: trace for (name, trace) in given.items() if trace is not None})
        self.__post_init__()
