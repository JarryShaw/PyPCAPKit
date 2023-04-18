Base Class
==========

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin. The following algorithm implement is based on IP
reassembly procedure introduced in :rfc:`791`, using
``RCVBT`` (fragment receivedbit table). Though another
algorithm is explained in :rfc:`815`, replacing ``RCVBT``,
however, this implement still used the elder one.

.. autoclass:: pcapkit.foundation.reassembly.ip.IP
   :no-members:
   :show-inheritance:

   .. automethod:: reassembly
   .. automethod:: submit

Data Models
-----------

.. module:: pcapkit.foundation.reassembly.data.ip

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Packet
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autodata:: pcapkit.foundation.reassembly.data.ip.BufferID

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Buffer
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.ip.DatagramID
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Datagram
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
