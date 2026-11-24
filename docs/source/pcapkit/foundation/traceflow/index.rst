============
Flow Tracing
============

.. module:: pcapkit.foundation.traceflow

.. note::

   This approximates the *Follow TCP Stream* feature of
   `Wireshark <https://www.wireshark.org/>`__.

:mod:`pcapkit.foundation.traceflow` implements flow tracing.

.. seealso::

   :doc:`../../../ext`, on customisation and extension.

.. toctree::
   :maxdepth: 2

   traceflow
   tcp

Every flow tracing class subclasses
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase`, following the
flows of extracted packets:

.. mermaid::

   flowchart TD
       A{{TraceFlowMeta}} -.->|metaclass| B(TraceFlowBase)

       B --> TCP

       B --> C(TraceFlow)
       C --> D([user customisation ...])

       click A "traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlowMeta"
       click B "traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlowBase"
       click C "traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlow"
       click D "../../../ext.html#reassembly-and-flow-tracing"

       click TCP "tcp.html#pcapkit.foundation.traceflow.tcp.traceflow.TCP"

Auxiliary Data
--------------

.. autoclass:: pcapkit.foundation.traceflow.TraceFlowManager
   :members:
   :show-inheritance:

.. module:: pcapkit.foundation.traceflow.data

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.traceflow.data.data``, with no alias: the module moved here.
   The ``TCP_*`` data models ``pcapkit.foundation.traceflow.data`` collected, with no
   alias: they are in :mod:`pcapkit.foundation.traceflow.tcp.data`
   (:issue:`2882`).

.. currentmodule:: pcapkit.foundation.traceflow

.. autoclass:: pcapkit.foundation.traceflow.data.TraceFlowData
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.data.Deferred
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.data.FrameRecord
   :members:
   :show-inheritance:
