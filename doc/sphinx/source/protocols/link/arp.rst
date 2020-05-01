ARP/InARP - (Inverse) Address Resolution Protocol
=================================================

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

.. module:: pcapkit.protocols.link.arp

.. autoclass:: pcapkit.protocols.link.arp.ARP
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. attribute:: _acnm
      :type: Literal['ARP', 'InARP', 'RARP', 'DRARP']

      Acronym of corresponding protocol.

      The value is based on operation type (:attr:`~DataType_ARP.oper`).

   .. attribute:: _name
      :type: Literal['Dynamic Reverse Address Resolution Protocol', 'Inverse Address Resolution Protocol', 'Reverse Address Resolution Protocol', 'Address Resolution Protocol']

      Name of current protocol.

      The value is based on operation type (:attr:`~DataType_ARP.oper`).

Data Structure
~~~~~~~~~~~~~~

.. important::

   Following classes are only for *documentation* purpose.
   They do **NOT** exist in the :mod:`pcapkit` module.

.. class:: DataType_ARP

   :bases: typing.TypedDict

   ARP header [:rfc:`826`].

   .. attribute:: htype
      :type: pcapkit.const.arp.Headware

      hardware type

   .. attribute:: ptype
      :type: Union[pcapkit.const.reg.ethertype.EtherType, str]

      protocol type

   .. attribute:: hlen
      :type: int

      headware address length

   .. attribute:: plen
      :type: int

      protocol address length

   .. attribute:: oper
      :type: pcapkit.const.arp.operation.Operation

      operation

   .. attribute:: sha
      :type: str

      sender hardware address

.. raw:: html

   <hr />

.. [*] http://en.wikipedia.org/wiki/Address_Resolution_Protocol
