VLAN - 802.1Q/802.1ad VLAN Tag Types
====================================

.. module:: pcapkit.protocols.link.vlan

:mod:`pcapkit.protocols.link.vlan` contains
:class:`~pcapkit.protocols.link.vlan.VLAN` only, an abstract base class holding
the tag layout shared by every VLAN tag [*]_. The two concrete tags live in
modules of their own:

.. list-table::
   :header-rows: 1

   * - EtherType
     - Class
   * - ``0x8100`` (customer tag, 802.1Q)
     - :class:`~pcapkit.protocols.link.c_tag.C_Tag`
   * - ``0x88A8`` (service tag, 802.1ad)
     - :class:`~pcapkit.protocols.link.s_tag.S_Tag`

The tag structure is described as below:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  0           0   ``vlan.tci``              Tag Control Information
  0           0   ``vlan.tci.pcp``          Priority Code Point
  0           3   ``vlan.tci.dei``          Drop Eligible Indicator
  0           4   ``vlan.tci.vid``          VLAN Identifier
  2          16   ``vlan.type``             Protocol (Internet Layer)
======= ========= ====================== =============================

The two tags carry an identical tag control information layout and differ only
in the tag protocol identifier (TPID) that selected them -- ``0x8100`` for the
customer tag, ``0x88A8`` for the service tag. The TPID is not part of either tag:
it is the EtherType field of whatever encapsulates the tag. Both classes read the
same four octets and share all parsing and construction code, which this base
holds.

They are still distinct classes rather than one class bound at two EtherTypes,
because 802.1ad *stacks* them. In a Q-in-Q frame the service tag's own
next-EtherType is ``0x8100``, which selects a customer tag in turn:

.. code-block:: text

   ethernet.type                = 0x88A8
   ethernet.s_tag.tci.vid       = 100     <- service tag,  802.1ad
   ethernet.s_tag.type          = 0x8100
   ethernet.s_tag.c_tag.tci.vid = 200     <- customer tag, 802.1Q
   ethernet.s_tag.c_tag.type    = 0x0800

:attr:`~pcapkit.protocols.protocol.Protocol.info_name` -- ``s_tag`` against
``c_tag`` -- is what keeps the two apart in the parsed
:class:`~pcapkit.corekit.infoclass.Info`. One class bound at both EtherTypes
would nest a ``c_tag`` inside a ``c_tag``, leaving nothing to say which was the
service tag.

Two EtherTypes also mean two :meth:`~pcapkit.protocols.protocol.Protocol.__index__`
values, which is the project's rule for separate modules: siblings that *share* an
index may share a module, as :class:`~pcapkit.protocols.link.arp.InARP` shares
:mod:`~pcapkit.protocols.link.arp` and
:class:`~pcapkit.protocols.application.rarp.DRARP` shares
:mod:`~pcapkit.protocols.application.rarp`. This base is abstract, nothing
dispatches to it, and it declares no index, so its ``__index__`` raises.

.. autoclass:: pcapkit.protocols.link.vlan.VLAN
   :no-members:
   :show-inheritance:

   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.vlan

Both tags share these, since their layouts are identical.

.. autoclass:: pcapkit.protocols.schema.link.vlan.VLAN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.schema.link.vlan.TCI
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.schema.link.vlan.TCIType
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.vlan

.. autoclass:: pcapkit.protocols.data.link.vlan.VLAN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.data.link.vlan.TCI
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q
