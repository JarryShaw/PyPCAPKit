IGMP - Internet Group Management Protocol
==========================================

.. module:: pcapkit.protocols.internet.igmp
.. module:: pcapkit.protocols.internet.igmp.protocol

:mod:`pcapkit.protocols.internet.igmp.protocol` contains
:class:`~pcapkit.protocols.internet.igmp.protocol.IGMP`, the abstract base of the
Internet Group Management Protocol (IGMP) [*]_ versions 1, 2 and 3:

=========================================================== ============== =========================================
Version class                                               ``alias``      Schema and data model
=========================================================== ============== =========================================
:class:`~pcapkit.protocols.internet.igmpv1.protocol.IGMPv1` ``'IGMP'``     this page's, keyed ``igmpv1``
:class:`~pcapkit.protocols.internet.igmpv2.protocol.IGMPv2` ``'IGMPv2'``   this page's, keyed ``igmpv2``
:class:`~pcapkit.protocols.internet.igmpv3.protocol.IGMPv3` ``'IGMPv3'``   its own, as its wire format differs by
                                                                           message (:doc:`igmpv3`)
=========================================================== ============== =========================================

IGMPv1's :attr:`~pcapkit.protocols.internet.igmp.protocol.IGMP.alias` is the name
:rfc:`1112` gives it. Constructing the base gives the version class its
``version`` keyword names; without it, octets give the class the message
classifies as, and fields are refused.
:meth:`~pcapkit.protocols.internet.igmp.protocol.IGMP.from_data` gives the class
its data's ``version`` names: every IGMP data model carries one, ``1``, ``2`` or
``3``, set by the class that read or built the message and on no octet, so an
IGMPv1 and an IGMPv2 message read alike apart from it (:issue:`2574`).

:meth:`~pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch` gives octets a
version class, or :class:`~pcapkit.protocols.misc.raw.protocol.Raw`, as
:meth:`~pcapkit.protocols.internet.igmp.protocol.IGMP._classify` decides:

.. mermaid::

   flowchart TD
       NEW["IGMP(octets) with no version=<br/>IGMP.\_\_new\_\_"] --> DISP
       NET["an IP layer's IGMP payload<br/>Internet.\_next\_layer\_class"] --> DISP
       DISP{"\_dispatch: at least 2 octets?"}
       DISP -->|yes| TYPE{"\_classify: the Type"}
       DISP -->|no| RAW
       TYPE -->|"0x12, v1 Report"| V1
       TYPE -->|"0x16, v2 Report<br/>0x17, Leave Group"| V2
       TYPE -->|"0x22, v3 Report"| V3
       TYPE -->|"0x11, Membership Query"| LEN{"the message length?"}
       TYPE -->|"any other"| RAW
       LEN -->|"8 octets"| MRT{"Max Resp Time zero?"}
       LEN -->|"12 or more"| V3
       LEN -->|"any other"| RAW
       MRT -->|yes| V1
       MRT -->|no| V2
       V1["IGMPv1"]
       V2["IGMPv2"]
       V3["IGMPv3"]
       RAW["Raw"]
       RAW -->|"from IGMP.\_\_new\_\_"| ERR["ProtocolError: unknown version"]
       RAW -->|"from Internet"| KEPT["parsed as Raw, the next layer"]

       click NEW "igmp.html#pcapkit.protocols.internet.igmp.protocol.IGMP.__new__"
       click NET "internet.html#pcapkit.protocols.internet.internet.Internet._next_layer_class"
       click DISP "igmp.html#pcapkit.protocols.internet.igmp.protocol.IGMP._dispatch"
       click TYPE "igmp.html#pcapkit.protocols.internet.igmp.protocol.IGMP._classify"
       click V1 "igmpv1.html#pcapkit.protocols.internet.igmpv1.protocol.IGMPv1"
       click V2 "igmpv2.html#pcapkit.protocols.internet.igmpv2.protocol.IGMPv2"
       click V3 "igmpv3.html#pcapkit.protocols.internet.igmpv3.protocol.IGMPv3"

The IGMPv1 and IGMPv2 structure, keyed as for IGMPv1:

======= ========= ========================= ===================================
Octets      Bits        Name                    Description
======= ========= ========================= ===================================
  0           0   ``igmpv1.type``           Type
  1           8   ``igmpv1.max_resp_time``  Max Response Time
  2          16   ``igmpv1.checksum``       Checksum
  4          32   ``igmpv1.group``          Group Address
======= ========= ========================= ===================================

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.igmp.protocol.IGMP
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: version
   .. autoproperty:: alias
   .. autoproperty:: length

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make
   .. automethod:: from_data

   .. automethod:: __index__
   .. automethod:: __init__
   .. automethod:: __new__

   .. automethod:: _make_data
   .. automethod:: _classify
   .. automethod:: _verify_checksum
   .. automethod:: _dispatch
   .. automethod:: _member_of_version

Header Schemas
--------------

.. module:: pcapkit.protocols.internet.igmp.schema

.. autoclass:: pcapkit.protocols.internet.igmp.schema.IGMP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.internet.igmp.data

.. autoclass:: pcapkit.protocols.internet.igmp.data.IGMP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Group_Management_Protocol
