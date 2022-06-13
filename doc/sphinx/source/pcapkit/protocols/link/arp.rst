ARP/InARP - (Inverse) Address Resolution Protocol
=================================================

.. module:: pcapkit.protocols.link.arp
.. module:: pcapkit.protocols.data.link.arp

:mod:`pcapkit.protocols.link.arp` contains
:class:`~pcapkit.protocols.link.arp.ARP` only,
which implements extractor for (Inverse) Address Resolution
Protocol (ARP/InARP) [*]_, whose structure is described as
below:

.. table::

   ====== ==== ============= =======================
   Octets Bits Name          Description
   ====== ==== ============= =======================
   0      0    ``arp.htype`` Hardware Type
   ------ ---- ------------- -----------------------
   2      16   ``arp.ptype`` Protocol Type
   ------ ---- ------------- -----------------------
   4      32   ``arp.hlen``  Hardware Address Length
   ------ ---- ------------- -----------------------
   5      40   ``arp.plen``  Protocol Address Length
   ------ ---- ------------- -----------------------
   6      48   ``arp.oper``  Operation
   ------ ---- ------------- -----------------------
   8      64   ``arp.sha``   Sender Hardware Address
   ------ ---- ------------- -----------------------
   14     112  ``arp.spa``   Sender Protocol Address
   ------ ---- ------------- -----------------------
   18     144  ``arp.tha``   Target Hardware Address
   ------ ---- ------------- -----------------------
   24     192  ``arp.tpa``   Target Protocol Address
   ====== ==== ============= =======================

.. raw:: html

   <br />

.. autoclass:: pcapkit.protocols.link.arp.ARP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: __index__

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: src
   .. autoproperty:: dst
   .. autoproperty:: type

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. .. automethod:: _read_addr_resolve
   .. .. automethod:: _read_proto_resolve

.. class:: pcapkit.protocols.link.InARP

   Alias of :class:`~pcapkit.protocols.link.arp.ARP`.

Data Structures
---------------

.. autoclass:: pcapkit.protocols.data.link.arp.ARP(htype, ptype, hlen, plen, oper, sha, spa, tha, tpa, len)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: htype
   .. autoattribute:: ptype
   .. autoattribute:: hlen
   .. autoattribute:: plen
   .. autoattribute:: oper
   .. autoattribute:: sha
   .. autoattribute:: spa
   .. autoattribute:: tha
   .. autoattribute:: tpa
   .. autoattribute:: len

.. autoclass:: pcapkit.protocols.data.link.arp.Address(hardware, protocol)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hardware
   .. autoattribute:: protocol

.. autoclass:: pcapkit.protocols.data.link.arp.Type(hardware, protocol)
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoattribute:: hardware
   .. autoattribute:: protocol

.. raw:: html

   <hr />

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
