Reassembly Base Class
=====================

.. module:: pcapkit.foundation.reassembly.reassembly

:mod:`pcapkit.foundation.reassembly.reassembly` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly`, the abstract base
class of a custom reassembly class, and
:class:`~pcapkit.foundation.reassembly.reassembly.ReassemblyBase`, which it and
the built-in IP, TCP and DTLS reassembly classes derive from. The algorithms
follow :rfc:`791` and :rfc:`815`.

.. autoclass:: pcapkit.foundation.reassembly.reassembly.Reassembly
   :no-members:
   :show-inheritance:

   .. seealso::

      For customisation and extension, see :doc:`../../../ext`.

   .. property:: name
      :type: str

      Protocol name of current reassembly class.

      .. note::

         Also a class variable, set by :attr:`__protocol_name__`.


   .. property:: protocol
      :type: typing.Type[pcapkit.protocols.protocol.ProtocolBase]

      Protocol of current reassembly class.

      .. note::

         Also a class variable, set by :attr:`__protocol_type__`.

   .. property:: registry
      :type: dict[str, ModuleDescriptor[ReassemblyBase] | typing.Type[ReassemblyBase]]

      Mapping of protocol names to reassembly classes.

      .. note::

         A class variable only, defined on :class:`ReassemblyMeta`. It is not
         per-class: it reads
         :attr:`~pcapkit.foundation.extraction.Extractor.__reassembly__`, the
         one table every reassembly registration lands in.

   .. autoproperty:: count
   .. autoproperty:: datagram
   .. autoproperty:: timeout

   .. automethod:: reassembly
   .. automethod:: submit
   .. automethod:: expire
   .. automethod:: fetch
   .. automethod:: index
   .. automethod:: run
   .. automethod:: register

   .. autoattribute:: __callback_fn__
      :no-value:

   .. autoattribute:: _flag_s
      :no-value:
   .. autoattribute:: _flag_d
      :no-value:
   .. autoattribute:: _flag_n
      :no-value:
   .. autoattribute:: _timeout
      :no-value:

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _dtgram
      :no-value:

   .. automethod:: __call__
   .. automethod:: __init_subclass__

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__
   .. autoattribute:: __timeout__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.reassembly.reassembly.ReassemblyBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.reassembly.ReassemblyMeta
   :no-members:
   :show-inheritance:

Type Variables
--------------

.. data:: _PT
   :type: pcapkit.corekit.infoclass.Info

   Packet data structure.

.. data:: _DT
   :type: pcapkit.corekit.infoclass.Info

   Datagram data structure.

.. data:: _IT
   :type: tuple

   Buffer ID data structure.

.. data:: _BT
   :type: pcapkit.corekit.infoclass.Info

   Buffer data structure.
