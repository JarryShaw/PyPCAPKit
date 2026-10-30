IP Pseudo-Header
================

.. module:: pcapkit.protocols.internet.ip_pseudo

:mod:`pcapkit.protocols.internet.ip_pseudo` contains
:class:`~pcapkit.protocols.internet.ip_pseudo.IP_Pseudo` only,
which implements the pseudo-header of the IP protocol family
that the upper-layer checksums cover, whose structure is
described as below:

IPv4 (:rfc:`793#section-3.1`, :rfc:`768`):

======= ========= ========================= ===============================
Octets      Bits        Name                    Description
======= ========= ========================= ===============================
  0           0   ``ip_pseudo.src``           Source Address
  4          32   ``ip_pseudo.dst``           Destination Address
  8          64   ``ip_pseudo.zero``          Reserved
  9          72   ``ip_pseudo.protocol``      Protocol
  10         80   ``ip_pseudo.len``           Upper-Layer Packet Length
======= ========= ========================= ===============================

IPv6 (:rfc:`8200#section-8.1`):

======= ========= ========================= ===============================
Octets      Bits        Name                    Description
======= ========= ========================= ===============================
  0           0   ``ip_pseudo.src``           Source Address
  16        128   ``ip_pseudo.dst``           Destination Address
  32        256   ``ip_pseudo.len``           Upper-Layer Packet Length
  36        288   ``ip_pseudo.zero``          Reserved
  39        312   ``ip_pseudo.protocol``      Next Header
======= ========= ========================= ===============================

.. autoclass:: pcapkit.protocols.internet.ip_pseudo.IP_Pseudo
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: version
   .. autoproperty:: src
   .. autoproperty:: dst

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data
   .. automethod:: _from_ip

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ip_pseudo

.. autodata:: pcapkit.protocols.schema.internet.ip_pseudo.IPV4_PSEUDO_LEN
.. autodata:: pcapkit.protocols.schema.internet.ip_pseudo.IPV6_PSEUDO_LEN

.. autoclass:: pcapkit.protocols.schema.internet.ip_pseudo.IP_Pseudo
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.internet.ip_pseudo.is_ipv6
.. autofunction:: pcapkit.protocols.schema.internet.ip_pseudo.ip_pseudo_address_selector
.. autofunction:: pcapkit.protocols.schema.internet.ip_pseudo.ip_pseudo_zero_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ip_pseudo

.. autoclass:: pcapkit.protocols.data.internet.ip_pseudo.IP_Pseudo
   :members:
   :show-inheritance:
