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

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: name
   .. autoproperty:: count
   .. autoproperty:: datagram
   .. autoproperty:: protocol

   .. automethod:: reassembly
   .. automethod:: submit
   .. automethod:: fetch
   .. automethod:: index
   .. automethod:: run

   .. autoattribute:: _buffer
      :no-value:
   .. autoattribute:: _dtgram
      :no-value:

   .. autoattribute:: _strflg
      :no-value:
   .. autoattribute:: _newflg
      :no-value:

   .. automethod:: __call__
