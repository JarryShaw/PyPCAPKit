Base Class
==========

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin, using the :rfc:`791` procedure described in :doc:`index`.

.. autoclass:: pcapkit.foundation.reassembly.ip.IP
   :no-members:
   :show-inheritance:

   .. automethod:: reassembly
   .. automethod:: submit

Data Models
-----------

.. module:: pcapkit.foundation.reassembly.data.ip
.. currentmodule:: pcapkit.foundation.reassembly.ip

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Packet
   :members:
   :show-inheritance:

.. data:: pcapkit.foundation.reassembly.data.ip.BufferID
   :type: typing.Tuple[_AT, _AT, int, pcapkit.const.reg.transtype.TransType]

   Data module for buffer ID.

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Buffer
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.ip.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Datagram
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: pcapkit.foundation.reassembly.data.ip._AT
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address
