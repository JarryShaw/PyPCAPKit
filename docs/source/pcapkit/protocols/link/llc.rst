LLC - Logical Link Control
==========================

.. module:: pcapkit.protocols.link.llc
.. module:: pcapkit.protocols.link.llc.protocol

:mod:`pcapkit.protocols.link.llc.protocol` contains
:class:`~pcapkit.protocols.link.llc.protocol.LLC`,
which implements the extractor for the IEEE 802.2 Logical Link
Control (LLC) [*]_ PDU of ISO/IEC 8802-2, whose structure is:

.. table::

   ====== ===== ================== =========================================
   Octets Bits  Name               Description
   ====== ===== ================== =========================================
   0          0 ``llc.dsap``       DSAP address, its low bit the I/G bit
   ------ ----- ------------------ -----------------------------------------
   1          8 ``llc.ssap``       SSAP address, less its low bit
   ------ ----- ------------------ -----------------------------------------
   1         15 ``llc.cr``         C/R bit, the low bit of the SSAP octet
   ------ ----- ------------------ -----------------------------------------
   2         16 ``llc.control``    Control field, one octet in the U format
                                   and two in the I and S formats
   ====== ===== ================== =========================================

Where the PDU comes from, and where its information field goes:

.. mermaid::

   flowchart TD
       ETH["Ethernet, Length/Type up to 0x05DC"] --> LLC
       WLAN["802.11 data frame carrying an MSDU"] --> LLC
       ATM["LINKTYPE_ATM_RFC1483"] --> LLC
       LLC{"control field format"}
       LLC -->|"I PDU or UI PDU"| DSAP{"LLC.\_\_proto\_\_ by DSAP"}
       LLC -->|"S, or U other than UI"| RAW["Raw"]
       DSAP -->|"0xAA, paired: SSAP 0xAA too"| SNAP{"SNAP, by OUI"}
       DSAP -->|"paired, another SSAP"| RAW
       DSAP -->|"no entry"| RAW
       SNAP -->|"00-00-00: the PID as an EtherType"| LINK["Link.\_\_proto\_\_"]
       SNAP -->|"any other"| RAW

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.link.llc.protocol.LLC
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __paired__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. rubric:: Data Models

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _make_function

Header Schemas
--------------

.. module:: pcapkit.protocols.link.llc.schema

.. autoclass:: pcapkit.protocols.link.llc.schema.LLC
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.link.llc.schema.llc_control_is_long

Data Models
-----------

.. module:: pcapkit.protocols.link.llc.data

.. autoclass:: pcapkit.protocols.link.llc.data.LLC
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.llc.data.Control
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IEEE_802.2
