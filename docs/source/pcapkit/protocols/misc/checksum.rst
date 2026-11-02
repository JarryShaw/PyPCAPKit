=========
Checksums
=========

.. module:: pcapkit.protocols.misc.checksum
.. module:: pcapkit.protocols.data.misc.checksum
.. module:: pcapkit.protocols.schema.misc.checksum

:mod:`pcapkit.protocols.misc.checksum` contains the pseudo-header that
upper-layer checksums cover,
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`. What the
one's-complement checksums share, such as
:class:`~pcapkit.corekit.checksum.internet.ChecksumStatus`, is in
:mod:`pcapkit.corekit.checksum.internet`.

IP Pseudo-Header
================

.. module:: pcapkit.protocols.misc.checksum.ip_pseudo

:mod:`pcapkit.protocols.misc.checksum.ip_pseudo` contains
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`,
which implements the pseudo-header of the IP protocol family
that the upper-layer checksums cover, and :func:`pseudo_header` and
:func:`verify_upper`, through which the IP layers use it. The
pseudo-header's structure is described as below:

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

A checksum over the IP pseudo-header is verified and computed by the enclosing
:class:`~pcapkit.protocols.internet.ipv4.IPv4` or
:class:`~pcapkit.protocols.internet.ipv6.IPv6` layer, which builds the
:class:`~pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo`, rather than by
the upper layer reaching back to its parent. So an upper layer constructed
alone, or behind another header such as an IPv6 extension header or an
Authentication Header, has its checksum computed only if given the ``pseudo``
to compute it over, and one parsed alone records no outcome. The sum itself is
in :mod:`pcapkit.corekit.checksum.internet`.

.. autoclass:: pcapkit.protocols.misc.checksum.ip_pseudo.IP_Pseudo
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
   .. automethod:: _source
   .. automethod:: _destination
   .. automethod:: _upper_protocol
   .. automethod:: _upper_length

   .. automethod:: __post_init__
   .. automethod:: __index__

.. autofunction:: pcapkit.protocols.misc.checksum.ip_pseudo.pseudo_header
.. autofunction:: pcapkit.protocols.misc.checksum.ip_pseudo.verify_upper

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.misc.checksum.ip_pseudo

.. autodata:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.IPV4_PSEUDO_LEN
.. autodata:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.IPV6_PSEUDO_LEN

.. autoclass:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.IP_Pseudo
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.is_ipv6
.. autofunction:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.ip_pseudo_address_selector
.. autofunction:: pcapkit.protocols.schema.misc.checksum.ip_pseudo.ip_pseudo_zero_selector

Data Models
-----------

.. module:: pcapkit.protocols.data.misc.checksum.ip_pseudo

.. autoclass:: pcapkit.protocols.data.misc.checksum.ip_pseudo.IP_Pseudo
   :members:
   :show-inheritance:
