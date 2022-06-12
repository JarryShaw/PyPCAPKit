TCP Datagram Reassembly
=======================

:mod:`pcapkit.foundation.reassembly.tcp` contains
:class:`~pcapkit.foundation.reassembly.tcp.TCP_Reassembly` only,
which reconstructs fragmented TCP packets back to origin.
The algorithm for TCP reassembly is described as below.

.. toctree::

   algorithm
   tcp
