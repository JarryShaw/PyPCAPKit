VLAN - 802.1Q/802.1ad VLAN Tag Types
====================================

.. module:: pcapkit.protocols.link.vlan
.. module:: pcapkit.protocols.link.vlan.protocol

:mod:`pcapkit.protocols.link.vlan.protocol` contains
:class:`~pcapkit.protocols.link.vlan.protocol.VLAN` only, an abstract base class holding
the tag layout shared by every VLAN tag [*]_. The concrete tags live in
packages of their own:

.. list-table::
   :header-rows: 1

   * - EtherType
     - Class
   * - ``0x8100`` (customer tag, 802.1Q)
     - :class:`~pcapkit.protocols.link.c_tag.protocol.C_Tag`
   * - ``0x88A8`` (service tag, 802.1ad)
     - :class:`~pcapkit.protocols.link.s_tag.protocol.S_Tag`

The tag structure, keyed as for a customer tag (a service tag's keys start
``s_tag``), is:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  0           0   ``c_tag.tci``             Tag Control Information
  0           0   ``c_tag.tci.pcp``         Priority Code Point
  0           3   ``c_tag.tci.dei``         Drop Eligible Indicator
  0           4   ``c_tag.tci.vid``         VLAN Identifier
  2          16   ``c_tag.type``            Protocol (Internet Layer)
======= ========= ====================== =============================

The two tags differ only in the tag protocol identifier (TPID) that selects
them, which is not part of either tag but the EtherType field of whatever
encapsulates it. Both read the same four octets with the parsing and
construction code this base holds.

They are distinct classes, not one class bound at two EtherTypes, because
802.1ad *stacks* them: in a Q-in-Q frame the service tag's next EtherType,
``0x8100``, selects a customer tag:

.. code-block:: text

   ethernet.type                = 0x88A8
   ethernet.s_tag.tci.vid       = 100     <- service tag,  802.1ad
   ethernet.s_tag.type          = 0x8100
   ethernet.s_tag.c_tag.tci.vid = 200     <- customer tag, 802.1Q
   ethernet.s_tag.c_tag.type    = 0x0800

:attr:`~pcapkit.protocols.protocol.Protocol.info_name` -- ``s_tag`` against
``c_tag`` -- keeps the two apart in the parsed
:class:`~pcapkit.corekit.infoclass.Info`; one class would nest a ``c_tag`` inside
a ``c_tag``, leaving nothing to say which was the service tag.

Each tag has a package of its own because a package holds one protocol class,
named after it, with only the framework bases in :mod:`pcapkit.protocols.protocol`
exempt (:issue:`2529`). This base is abstract, nothing dispatches to it, and it
declares no :meth:`~pcapkit.protocols.protocol.Protocol.__index__`, so its
``__index__`` raises.

.. autoclass:: pcapkit.protocols.link.vlan.protocol.VLAN
   :no-members:
   :show-inheritance:

   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.link.vlan.schema

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.schema.link.vlan``, with no alias: the module moved here
   (:issue:`2534`).

Both tags share these, since their layouts are identical.

.. autoclass:: pcapkit.protocols.link.vlan.schema.VLAN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.vlan.schema.TCI
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.link.vlan.schema.TCIType
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.vlan.data

.. versionremoved:: 1.6.0

   ``pcapkit.protocols.data.link.vlan``, with no alias: the module moved here
   (:issue:`2534`).

.. autoclass:: pcapkit.protocols.link.vlan.data.VLAN
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.vlan.data.TCI
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q
