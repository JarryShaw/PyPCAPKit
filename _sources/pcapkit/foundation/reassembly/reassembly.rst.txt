Base Class
==========

.. module:: pcapkit.foundation.reassembly.reassembly

:mod:`pcapkit.foundation.reassembly.reassembly` contains
:class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
which is an abstract base class for all reassembly classes,
bases on algorithms described in :rfc:`791` and :rfc:`815`,
implements datagram reassembly of IP and TCP packets.

.. autoclass:: pcapkit.foundation.reassembly.reassembly.Reassembly
   :no-members:
   :show-inheritance:

   .. seealso::

      For more information on customisation and extension, please
      refer to :doc:`../../../ext`.

   .. property:: name
      :type: str

      Protocol name of current reassembly class.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__protocol_name__` class attribute.


   .. property:: protocol
      :type: Type[Protocol]

      Protocol of current reassembly class.

      .. note::

         This property is also available as a class variable. Its
         value can be set by :attr:`__protocol_type__` class attribute.

   .. autoproperty:: count
   .. autoproperty:: datagram

   .. automethod:: reassembly
   .. automethod:: submit
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

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _dtgram
      :no-value:

   .. automethod:: __call__
   .. automethod:: __init_subclass__

   .. autoattribute:: __protocol_name__
   .. autoattribute:: __protocol_type__

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

.. data:: pcapkit.foundation.reassembly.reassembly._PT
   :type: pcapkit.corekit.infoclass.Info

   Packet data structure.

.. data:: pcapkit.foundation.reassembly.reassembly._DT
   :type: pcapkit.corekit.infoclass.Info

   Datagram data structure.

.. data:: pcapkit.foundation.reassembly.reassembly._IT
   :type: pcapkit.corekit.infoclass.Info

   Buffer ID data structure.

.. data:: pcapkit.foundation.reassembly.reassembly._BT
   :type: pcapkit.corekit.infoclass.Info

   Buffer data structure.
