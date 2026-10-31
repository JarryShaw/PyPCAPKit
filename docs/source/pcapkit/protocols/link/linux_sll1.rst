Linux "Cooked" Capture Encapsulation
=====================================

.. module:: pcapkit.protocols.link.linux_sll1

:mod:`pcapkit.protocols.link.linux_sll1` contains
:class:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1`
only, which implements the extractor for the Linux "cooked" capture
encapsulation [*]_ of ``LINKTYPE_LINUX_SLL`` -- the header every
``tcpdump -i any`` capture on Linux uses -- whose structure is described as
below:

.. table::

   ====== ===== ============================== ================================
   Octets Bits  Name                           Description
   ====== ===== ============================== ================================
   0          0 ``linux_sll.packet_type``      Packet Type
   ------ ----- ------------------------------ --------------------------------
   2         16 ``linux_sll.arphrd_type``      ARP Hardware Type
   ------ ----- ------------------------------ --------------------------------
   4         32 ``linux_sll.link_addr_length`` Link-Layer Address Length
   ------ ----- ------------------------------ --------------------------------
   6         48 ``linux_sll.link_addr``        Link-Layer Address (padded)
   ------ ----- ------------------------------ --------------------------------
   14       112 ``linux_sll.protocol_type``    Protocol (Internet Layer)
   ====== ===== ============================== ================================

Next-layer dispatch is shared with
:class:`~pcapkit.protocols.link.linux_sll2.LinuxSLL2`; see
:mod:`~pcapkit.protocols.link.linux_sll`. Its
:meth:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1.id` is
``('LinuxSLL1',)``, and its
:attr:`~pcapkit.protocols.link.linux_sll1.LinuxSLL1.alias` is ``'LINUX_SLL1'``;
see :ref:`linux-sll-labels`.

.. autoclass:: pcapkit.protocols.link.linux_sll1.LinuxSLL1
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

.. module:: pcapkit.protocols.schema.link.linux_sll1

.. autoclass:: pcapkit.protocols.schema.link.linux_sll1.LinuxSLL1
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.linux_sll1

.. autoclass:: pcapkit.protocols.data.link.linux_sll1.LinuxSLL1
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.tcpdump.org/linktypes/LINKTYPE_LINUX_SLL.html
