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

   .. automethod:: register
   .. automethod:: make_fout

   .. automethod:: dump
   .. automethod:: trace
   .. automethod:: submit

   .. autoattribute:: __output__
      :no-value:

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _stream
      :no-value:

   .. automethod:: __call__
