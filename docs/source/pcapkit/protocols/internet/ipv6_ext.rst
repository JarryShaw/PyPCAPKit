IPv6_Ext - IPv6 Extension Header
================================

.. module:: pcapkit.protocols.internet.ipv6_ext

:mod:`pcapkit.protocols.internet.ipv6_ext` contains
:class:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext`
only, which serves two roles at once. It is the shared **base class** of all
eight IPv6 extension headers this package implements, supplying the
``extension``-mode contract: the guards that make
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.payload`,
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protocol` and
:attr:`~pcapkit.protocols.internet.ipv6_ext.IPv6_Ext.protochain`
unavailable on a header parsed as part of an IPv6 chain. It also implements a
**generic** extractor for IPv6 extension headers [*]_, standing in whenever a
header's own dedicated parser is unavailable or has failed. :rfc:`6564#section-4`
requires, with an RFC 2119 **MUST**, that any IPv6 extension header defined since
April 2012 carry the same first two octets:

======= ========= ===================== =====================================
Octets      Bits        Name                    Description
======= ========= ===================== =====================================
  0           0   ``next``                    Next Header
  1           8   ``len``                     Hdr Ext Len (8-octet units,
                                                excluding the first 8 octets)
  2          16   ``payload``                 Header-specific content
======= ========= ===================== =====================================

so those two octets are parseable without knowing anything else about the
header. The module docstring in :file:`pcapkit/protocols/internet/ipv6_ext.py`
holds the closed exception table (``IPv6-Frag`` and ``AH`` each use their own
length rule; ``ESP`` has a dedicated parser whose own info reports no next header
rather than lacking one, and ``253`` and ``254`` have no dedicated parser at all,
so none of the three ever reaches this class), the two ways this class is
dispatched to, and why an overrun stops the walk instead of clipping it.

.. autoclass:: pcapkit.protocols.internet.ipv6_ext.IPv6_Ext
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol
   .. autoproperty:: next
   .. autoproperty:: payload
   .. autoproperty:: protochain

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __post_init__
   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.internet.ipv6_ext

.. autoclass:: pcapkit.protocols.schema.internet.ipv6_ext.IPv6_Ext
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.internet.ipv6_ext

.. autoclass:: pcapkit.protocols.data.internet.ipv6_ext.IPv6_Ext
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`6564`
