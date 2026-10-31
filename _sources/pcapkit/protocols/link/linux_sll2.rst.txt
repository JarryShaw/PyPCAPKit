Linux "Cooked" Capture Encapsulation v2
=========================================

.. module:: pcapkit.protocols.link.linux_sll2

:mod:`pcapkit.protocols.link.linux_sll2` contains
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`
only, which implements the extractor for the Linux "cooked" capture
encapsulation v2 [*]_ of ``LINKTYPE_LINUX_SLL2``, whose structure is described
as below:

.. table::

   ====== ===== ================================ ================================
   Octets Bits  Name                             Description
   ====== ===== ================================ ================================
   0          0 ``linux_sll2.protocol_type``     Protocol (Internet Layer)
   ------ ----- -------------------------------- --------------------------------
   2         16 ``linux_sll2.reserved``          Reserved
   ------ ----- -------------------------------- --------------------------------
   4         32 ``linux_sll2.interface_index``   Interface Index
   ------ ----- -------------------------------- --------------------------------
   8         64 ``linux_sll2.arphrd_type``       ARP Hardware Type
   ------ ----- -------------------------------- --------------------------------
   10        80 ``linux_sll2.packet_type``       Packet Type
   ------ ----- -------------------------------- --------------------------------
   11        88 ``linux_sll2.link_addr_length``  Link-Layer Address Length
   ------ ----- -------------------------------- --------------------------------
   12        96 ``linux_sll2.link_addr``         Link-Layer Address (padded)
   ====== ===== ================================ ================================

Unlike v1, ``protocol_type`` comes first, ``interface_index`` is new, and
``packet_type`` and ``link_addr_length`` are 1 octet rather than 2. See
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1` for v1; next-layer
dispatch is shared, see :mod:`~pcapkit.protocols.link.linux_sll`. Its
:meth:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2.id` is
``('LinuxSLL2',)``, and its
:attr:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2.alias` is ``'LINUX_SLL2'``;
see :ref:`linux-sll-labels`.

.. autoclass:: pcapkit.protocols.link.linux_sll2.LinuxSLL2
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.linux_sll2

.. autoclass:: pcapkit.protocols.schema.link.linux_sll2.LinuxSLL2
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.linux_sll2

.. autoclass:: pcapkit.protocols.data.link.linux_sll2.LinuxSLL2
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL2.html
