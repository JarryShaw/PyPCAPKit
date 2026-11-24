IP Reassembly Base Class
========================

.. module:: pcapkit.foundation.reassembly.ip
.. module:: pcapkit.foundation.reassembly.ip.reassembly

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.reassembly.ip.logger``, with no alias: it is in
   :mod:`~pcapkit.foundation.reassembly.ip.reassembly`, and
   :mod:`pcapkit.foundation.reassembly.ip` exports the reassembly class alone
   (:issue:`2882`).

:mod:`pcapkit.foundation.reassembly.ip.reassembly` contains
:class:`~pcapkit.foundation.reassembly.ip.reassembly.IP`
only, which reconstructs fragmented IP packets back to
origin, using the :rfc:`791` procedure described in :doc:`index`.

.. autoclass:: pcapkit.foundation.reassembly.ip.reassembly.IP
   :no-members:
   :show-inheritance:

   .. autoattribute:: __discard_overlap__

   .. rubric:: Methods

   .. automethod:: reassembly
   .. automethod:: submit

   .. rubric:: Utilities

   .. automethod:: _detect_conflicts
   .. automethod:: _find_overlap

Data Models
-----------

.. module:: pcapkit.foundation.reassembly.ip.data

.. versionremoved:: 1.7.0

   ``pcapkit.foundation.reassembly.data.ip``, with no alias: the module moved here
   (:issue:`2882`).

.. currentmodule:: pcapkit.foundation.reassembly.ip.reassembly

.. autoclass:: pcapkit.foundation.reassembly.ip.data.Packet
   :members:
   :show-inheritance:

.. data:: BufferID
   :module: pcapkit.foundation.reassembly.ip.data
   :type: typing.Tuple[~pcapkit.foundation.reassembly.ip.data._AT, ~pcapkit.foundation.reassembly.ip.data._AT, int, pcapkit.const.reg.transtype.TransType]

   Data model for buffer ID.

.. autoclass:: pcapkit.foundation.reassembly.ip.data.Buffer
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.ip.data.DatagramID
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.foundation.reassembly.ip.data.Datagram
   :members:
   :show-inheritance:

Type Variables
--------------

.. data:: _AT
   :module: pcapkit.foundation.reassembly.ip.data
   :type: ipaddress.IPv4Address | ipaddress.IPv6Address

   IP address type.
