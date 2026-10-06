RARP/DRARP - (Dynamic) Reverse Address Resolution Protocol
==========================================================

.. module:: pcapkit.protocols.application.rarp

:mod:`pcapkit.protocols.application.rarp` contains
:class:`~pcapkit.protocols.application.rarp.RARP` and
:class:`~pcapkit.protocols.application.rarp.DRARP`,
which implement extractors for (Dynamic) Reverse
Address Resolution Protocol (RARP/DRARP) [*]_,
whose structure is described as below:

====== ========= ========================= =========================
Octets      Bits        Name                    Description
====== ========= ========================= =========================
  0           0   ``rarp.htype``            Hardware Type
  2          16   ``rarp.ptype``            Protocol Type
  4          32   ``rarp.hlen``             Hardware Address Length
  5          40   ``rarp.plen``             Protocol Address Length
  6          48   ``rarp.oper``             Operation
  8          64   ``rarp.sha``              Sender Hardware Address
  14        112   ``rarp.spa``              Sender Protocol Address
  18        144   ``rarp.tha``              Target Hardware Address
  24        192   ``rarp.tpa``              Target Protocol Address
====== ========= ========================= =========================

.. autoclass:: pcapkit.protocols.application.rarp.RARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

   .. automethod:: __index__

.. autoclass:: pcapkit.protocols.application.rarp.DRARP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
