=============================
Fragmented Packets Reassembly
=============================

.. module:: pcapkit.reassembly

:mod:`pcapkit.reassembly` bases on algorithms described
in :rfc:`791` and :rfc:`815`, implements datagram reassembly
of IP and TCP packets.

.. toctree::
   :maxdepth: 2

   reassembly
   ip/index
   tcp

Auxiliary Data
==============

.. autoclass:: pcapkit.foundation.reassembly.ReassemblyManager
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

.. autoclass:: pcapkit.foundation.reassembly.data.ReassemblyData
   :members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.
