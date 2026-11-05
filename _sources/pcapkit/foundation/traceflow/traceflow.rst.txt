Flow Tracing Base Class
=======================

.. module:: pcapkit.foundation.traceflow.traceflow

:mod:`pcapkit.foundation.traceflow.traceflow` contains
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlow`, the abstract base
class of a custom flow tracing class, and
:class:`~pcapkit.foundation.traceflow.traceflow.TraceFlowBase`, which it and the
built-in TCP flow tracing class derive from.

.. autoclass:: pcapkit.foundation.traceflow.traceflow.TraceFlow
   :no-members:
   :show-inheritance:

   .. seealso::

      For customisation and extension, see :doc:`../../../ext`.

   .. property:: name
      :type: str

      Protocol name of current class.

      .. note::

         Also a class variable, set by :attr:`__protocol_name__`.

   .. property:: protocol
      :type: typing.Type[pcapkit.protocols.protocol.ProtocolBase]

      Protocol of current class.

      .. note::

         Also a class variable, set by :attr:`__protocol_type__`.

   .. property:: registry
      :type: dict[str, ModuleDescriptor[TraceFlowBase] | typing.Type[TraceFlowBase]]

      Mapping of protocol names to flow tracing classes.

      .. note::

         A class variable only, defined on :class:`TraceFlowMeta`. It is not
         per-class: it reads
         :attr:`~pcapkit.foundation.extraction.Extractor.__traceflow__`, the one
         table every flow tracing registration lands in. It is *not*
         :attr:`__output__`, the separate output-dumper table this class owns.

   .. autoproperty:: index

   .. automethod:: register_dumper
   .. automethod:: register_callback
   .. automethod:: make_fout

   .. automethod:: dump
   .. automethod:: trace
   .. automethod:: finish
   .. automethod:: submit

   .. autoattribute:: __output__
      :no-value:
   .. autoattribute:: __callback_fn__
      :no-value:

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _stream
      :no-value:
   .. autoattribute:: _bidir
      :no-value:

   .. autoattribute:: _fproot
      :no-value:
   .. autoattribute:: _foutio
      :no-value:
   .. autoattribute:: _fdpext
      :no-value:
   .. autoattribute:: _endian
      :no-value:
   .. autoattribute:: _nnsecd
      :no-value:
   .. autoattribute:: _analyse
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

.. data:: _DT
   :type: typing.Any

   Buffer ID data structure.

.. data:: _BT
   :type: pcapkit.corekit.infoclass.Info

   Buffer data structure.

.. data:: _IT
   :type: pcapkit.corekit.infoclass.Info

   Index data structure.

.. data:: _PT
   :type: pcapkit.corekit.infoclass.Info

   Packet data structure.
