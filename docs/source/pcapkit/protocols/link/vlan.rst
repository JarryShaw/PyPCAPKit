VLAN - 802.1Q/802.1ad VLAN Tag Types
====================================

.. module:: pcapkit.protocols.link.vlan

:mod:`pcapkit.protocols.link.vlan` contains
:class:`~pcapkit.protocols.link.vlan.VLAN`, an abstract base class holding the
tag layout shared by every VLAN tag, and its two concrete subclasses --
:class:`~pcapkit.protocols.link.vlan.C_Tag` for the 802.1Q customer tag [*]_ and
:class:`~pcapkit.protocols.link.vlan.S_Tag` for the 802.1ad service tag -- whose
structure is described as below:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  1           0   ``vlan.tci``              Tag Control Information
  1           0   ``vlan.tci.pcp``          Priority Code Point
  1           3   ``vlan.tci.dei``          Drop Eligible Indicator
  1           4   ``vlan.tci.vid``          VLAN Identifier
  3          24   ``vlan.type``             Protocol (Internet Layer)
======= ========= ====================== =============================

The two tags carry an identical tag control information layout and are told apart
solely by the tag protocol identifier (TPID) that selected them -- ``0x8100`` for
the customer tag against ``0x88A8`` for the service tag. That TPID is not part of
either tag: it is the EtherType field of whatever encapsulates the tag, so both
classes read the same four octets and share every byte of parsing and
construction code.

They are nonetheless distinct classes rather than one class bound at two
EtherTypes, because 802.1ad *stacks* them. In a Q-in-Q frame the service tag's
own next-EtherType is ``0x8100``, which selects a customer tag in turn, so both
tags appear in one frame:

.. code-block:: text

   ethernet.type          = 0x88A8
   ethernet.s_tag.tci.vid = 100        <- service tag,  802.1ad
   ethernet.s_tag.type    = 0x8100
   ethernet.s_tag.c_tag.tci.vid = 200  <- customer tag, 802.1Q
   ethernet.s_tag.c_tag.type    = 0x0800

:attr:`~pcapkit.protocols.protocol.ProtocolBase.info_name` -- ``s_tag`` against
``c_tag`` -- is what keeps the two apart in the parsed
:class:`~pcapkit.corekit.infoclass.Info`. A single class bound at both EtherTypes
would nest one ``c_tag`` inside another, leaving nothing in the output to say
which of the two was the service tag.

.. autoclass:: pcapkit.protocols.link.vlan.VLAN
   :no-members:
   :show-inheritance:

   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: read
   .. automethod:: make

   .. automethod:: _make_data

   .. automethod:: __index__

.. autoclass:: pcapkit.protocols.link.vlan.C_Tag
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name

   .. automethod:: id

.. autoclass:: pcapkit.protocols.link.vlan.S_Tag
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: info_name

   .. automethod:: id

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
