IP Reassembly Base Class
========================

.. module:: pcapkit.foundation.reassembly.ip

:mod:`pcapkit.foundation.reassembly.ip` contains
:class:`~pcapkit.foundation.reassembly.ip.IP`
only, which reconstructs fragmented IP packets back to
origin, using the :rfc:`791` procedure described in :doc:`index`.

.. autoclass:: pcapkit.foundation.reassembly.ip.IP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __discard_overlap__
   .. automethod:: reassembly
   .. automethod:: submit
   .. automethod:: _detect_conflicts
   .. automethod:: _find_overlap

Data Models
-----------

.. module:: pcapkit.foundation.reassembly.data.ip
.. currentmodule:: pcapkit.foundation.reassembly.ip

.. autoclass:: pcapkit.foundation.reassembly.data.ip.Packet
   :members:
   :show-inheritance:

.. data:: BufferID
   :module: pcapkit.foundation.reassembly.data.ip
   :type: typing.Tuple[~pcapkit.foundation.reassembly.data.ip._AT, ~pcapkit.foundation.reassembly.data.ip._AT, int, pcapkit.const.reg.transtype.TransType]

   Data model for buffer ID.

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

.. data:: _AT
   :module: pcapkit.foundation.reassembly.data.ip
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
