VLAN - 802.1Q Customer VLAN Tag Type
====================================

:mod:`pcapkit.protocols.link.vlan` contains
:class:`~pcapkit.protocols.link.vlan.VLAN`
only, which implements extractor for 802.1Q
Customer VLAN Tag Type [*]_, whose structure is
described as below:

======= ========= ====================== =============================
Octets      Bits        Name                    Description
======= ========= ====================== =============================
  1           0   ``vlan.tci``              Tag Control Information
  1           0   ``vlan.tci.pcp``          Priority Code Point
  1           3   ``vlan.tci.dei``          Drop Eligible Indicator
  1           4   ``vlan.tci.vid``          VLAN Identifier
  3          24   ``vlan.type``             Protocol (Internet Layer)
======= ========= ====================== =============================

.. raw:: html

   <br />

.. automodule:: pcapkit.protocols.link.vlan
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

Data Structure
~~~~~~~~~~~~~~

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_VLAN

   :bases: typing.TypedDict

   IEEE 802.1Q customer VLAN tag type [:rfc:`7042`].

   .. attribute:: tci
      :type: DataType_TCI

      Tag control information.

   .. attribute:: type
      :type: pcapkit.const.reg.ethertype.EtherType

      Protocol (internet layer).

.. class:: DataType_TCI

   :bases: typing.TypedDict

   Tag control information.

   .. attribute:: pcp
      :type: pcapkit.const.vlan.priority_level.PriorityLevel

      Priority code point.

   .. attribute:: dei
      :type: bool

      Drop eligible indicator.

   .. attribute:: vid
      :type: int

      VLAN identifier.

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IEEE_802.1Q
