Base Class
==========

.. module:: pcapkit.foundation.traceflow.traceflow

:mod:`pcapkit.foundation.traceflow.traceflow` contains
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow` only,
which is an abstract base class for all flow tracing classes.

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlow
   :no-members:
   :show-inheritance:

   .. seealso::

      For more information on customisation and extension, please
      refer to :doc:`../../../ext`.

   .. property:: name
      :type: str

      Protocol name of current class.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__protocol_name__` class attribute.

   .. property:: protocol
      :type: Type[Protocol]

      Protocol of current class.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__protocol_type__` class attribute.

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

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlowBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlowMeta
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.foundation.traceflow.traceflow._DT
   :type: typing.Any

   Buffer ID data structure.

.. data:: pcapkit.foundation.traceflow.traceflow._BT
   :type: pcapkit.corekit.infoclass.Info

   Buffer data structure.

.. data:: pcapkit.foundation.traceflow.traceflow._IT
   :type: pcapkit.corekit.infoclass.Info

   Index data structure.

.. data:: pcapkit.foundation.traceflow.traceflow._PT
   :type: pcapkit.corekit.infoclass.Info

   Packet data structure.
