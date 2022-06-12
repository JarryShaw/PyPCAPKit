Base Class
==========

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP_Reassembly`
only, which reconstructs fragmented IP packets back to
origin.

.. autoclass:: pcapkit.foundation.reassembly.ip.IP_Reassembly
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: reassembly
   .. automethod:: submit

Data Structures
---------------

.. autoclass:: pcapkit.foundation.reassembly.ip.Packet
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: bufid
   .. autoattribute:: num
   .. autoattribute:: fo
   .. autoattribute:: ihl
   .. autoattribute:: mf
   .. autoattribute:: tl
   .. autoattribute:: header
   .. autoattribute:: payload

.. autoclass:: pcapkit.foundation.reassembly.ip.DatagramID
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: src
   .. autoattribute:: dst
   .. autoattribute:: id
   .. autoattribute:: proto

.. autoclass:: pcapkit.foundation.reassembly.ip.Datagram
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: completed
   .. autoattribute:: id
   .. autoattribute:: index
   .. autoattribute:: header
   .. autoattribute:: payload
   .. autoattribute:: packet

.. autoclass:: pcapkit.foundation.reassembly.ip.Buffer
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: TDL
   .. autoattribute:: RCVBT
   .. autoattribute:: index
   .. autoattribute:: header
   .. autoattribute:: datagram
