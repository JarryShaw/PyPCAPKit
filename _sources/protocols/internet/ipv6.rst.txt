IPv6 - Internet Protocol version 6
==================================

:mod:`pcapkit.protocols.internet.ipv6` contains
:class:`~pcapkit.protocols.internet.ipv6.IPv6` only,
which implements extractor for Internet Protocol
version 6 (IPv6) [*]_, whose structure is described
as below:

======= ========= ===================== =======================================
Octets      Bits        Name                    Description
======= ========= ===================== =======================================
  0           0   ``ip.version``              Version (``6``)
  0           4   ``ip.class``                Traffic Class
  1          12   ``ip.label``                Flow Label
  4          32   ``ip.payload``              Payload Length (header excludes)
  6          48   ``ip.next``                 Next Header
  7          56   ``ip.limit``                Hop Limit
  8          64   ``ip.src``                  Source Address
  24        192   ``ip.dst``                  Destination Address
======= ========= ===================== =======================================

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.internet.ipv6
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
--------------

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_IPv6

   :bases: TypedDict

   Structure of IPv6 header [:rfc:`2460`].

   .. attribute:: version
      :type: Literal[6]

      Version.

   .. attribute:: class
      :type: int

      Traffic class.

   .. attribute:: label
      :type: int

      Flow label.

   .. attribute:: payload
      :type: int

      Payload length.

   .. attribute:: next
      :type: pcapkit.const.reg.transtype.TransType

      Next header.

   .. attribute:: limit
      :type: int

      Hop limit.

   .. attribute:: src
      :type: ipaddress.IPv6Address

      Source address.

   .. attribute:: dst
      :type: ipaddress.IPv6Address

      Destination address.

   .. attribute:: packet
      :type: bytes

      Raw packet data.



.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPv6_packet
