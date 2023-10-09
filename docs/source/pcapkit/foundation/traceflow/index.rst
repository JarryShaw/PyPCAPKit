============
Flow Tracing
============

.. module:: pcapkit.foundation.traceflow

.. note::

   This was implemented at the demand of my mate
   `@gousaiyang <https://github.com/gousaiyang>`__. It is
   a approximate functionality of *Follow TCP Streams* in
   `Wireshark <https://www.wireshark.org/>`__.

:mod:`pcapkit.traceflow` implements flow tracing functions for
:mod:`pcapkit` package.

.. seealso::

   For more information on customisation and extension, please
   refer to :doc:`../../../ext`.

.. toctree::
   :maxdepth: 2

   traceflow
   tcp

All flow tracing classes are implemented as :class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`
subclasses, which are responsible for processing extracted packets and
follow the flow and/or stream to provide more insights. Below is a brief
diagram of the class hierarchy of :mod:`pcapkit.foundation.traceflow`:

.. mermaid::

   flowchart LR
       A{{TraceFlowMeta}} -.->|metaclass| B(TraceFlowBase)

       B --> TCP

       B --> C(TraceFlow)
       C --> D([user customisation ...])

       click A "/pcapkit/foundation/traceflow/traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlowMeta"
       click B "/pcapkit/foundation/traceflow/traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlowBase"
       click C "/pcapkit/foundation/traceflow/traceflow.html#pcapkit.foundation.traceflow.traceflow.TraceFlow"
       click D "/ext.html#traceflow-and-flow-tracing"

       click TCP "/pcapkit/foundation/traceflow/tcp.html#pcapkit.foundation.traceflow.tcp.TCP"

Auxiliary Data
--------------

.. autoclass:: pcapkit.foundation.traceflow.TraceFlowManager
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.data.TraceFlowData
   :members:
   :show-inheritance:
