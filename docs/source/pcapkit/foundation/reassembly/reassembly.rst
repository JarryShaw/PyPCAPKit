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

   .. autoproperty:: name
   .. autoproperty:: protocol

   .. autoproperty:: count
   .. autoproperty:: datagram

   .. automethod:: reassembly
   .. automethod:: submit
   .. automethod:: fetch
   .. automethod:: index
   .. automethod:: run
   .. automethod:: register

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _dtgram
      :no-value:

   .. autoattribute:: _flag_s
      :no-value:
   .. autoattribute:: _flag_d
      :no-value:
   .. autoattribute:: _flag_n
      :no-value:

   .. autoattribute:: __callback_fn__
      :no-value:

   .. automethod:: __call__
   .. automethod:: __init_subclass__

Internal Definitions
--------------------

.. autoclass:: pcapkit.foundation.reassembly.reassembly.ReassemblyBase
   :no-members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.reassembly.ReassemblyMeta
   :no-members:
   :show-inheritance:
