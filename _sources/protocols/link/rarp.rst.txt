RARP/DRARP - (Dynamic) Reverse Address Resolution Protocol
==========================================================

:mod:`pcapkit.protocols.link.rarp` contains
:class:`~pcapkit.protocols.link.rarp.RARP` only,
which implements extractor for (Dynamic) Reverse
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

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.link.rarp
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
