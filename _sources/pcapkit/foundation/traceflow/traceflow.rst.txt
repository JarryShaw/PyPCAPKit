Base Class
==========

.. module:: pcapkit.foundation.traceflow.traceflow

:mod:`pcapkit.foundation.traceflow.traceflow` contains
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` only,
which is an abstract base class for all flow tracing classes.

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlow
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: protocol
   .. autoproperty:: index

   .. automethod:: register_dumper
   .. automethod:: register_callback
   .. automethod:: make_fout

   .. automethod:: dump
   .. automethod:: trace
   .. automethod:: submit

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: __callback_fn__
      :no-value:

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _stream
      :no-value:

   .. automethod:: __call__
   .. automethod:: __init_subclass__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlowBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlowMeta
   :no-members:
   :show-inheritance:
