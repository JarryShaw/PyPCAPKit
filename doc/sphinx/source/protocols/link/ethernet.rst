.. module:: pcapkit.protocols.link.ethernet

Ethernet Protocol
=================

:mod:`pcapkit.protocols.link.ethernet` contains
:class:`~pcapkit.protocols.link.ethernet.Ethernet`
only, which implements extractor for Ethernet
Protocol [*]_, whose structure is described as
below::

+========+=======+==============+===========================+
| Octets | Bits  | Name         | Description               |
+========+=======+==============+===========================+
| 0      |     0 | ``eth.dst``  | Destination MAC Address   |
+--------+-------+--------------+---------------------------+
| 1      |     8 | ``eth.src``  | Source MAC Address        |
+--------+-------+--------------+---------------------------+
| 2      |    16 | ``eth.type`` | Protocol (Internet Layer) |
+--------+-------+--------------+---------------------------+

.. [*] https://en.wikipedia.org/wiki/Ethernet

.. automodule:: pcapkit.protocols.link.ethernet
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:
