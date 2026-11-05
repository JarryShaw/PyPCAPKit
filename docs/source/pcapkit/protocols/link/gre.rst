GRE - Generic Routing Encapsulation
====================================

.. module:: pcapkit.protocols.link.gre
.. module:: pcapkit.protocols.link.gre.protocol

:mod:`pcapkit.protocols.link.gre.protocol` contains
:class:`~pcapkit.protocols.link.gre.protocol.GRE`
only, which implements the extractor for the Generic Routing Encapsulation
base header [*]_ and its optional Key and Sequence Number extensions [*]_. It
is reached through IP protocol number 47 behind any layer sharing
:attr:`Internet.__proto__ <pcapkit.protocols.internet.internet.Internet.__proto__>`,
IPv4 and IPv6 among them, or on a ``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2``
capture whose ``arphrd_type`` is ``ARPHRD_IPGRE`` or ``ARPHRD_IP6GRE``, which
differ only in the outer IP version. With every optional field present, its
structure is:

.. table::

   ====== ==== ========================= ====================================
   Octets Bits Name                      Description
   ====== ==== ========================= ====================================
   0      0    ``gre.checksum_present``  Checksum Present (``C``)
   ------ ---- ------------------------- ------------------------------------
   0      2    ``gre.key_present``       Key Present (``K``), :rfc:`2890`
   ------ ---- ------------------------- ------------------------------------
   0      3    ``gre.sequence_present``  Sequence Number Present (``S``), :rfc:`2890`
   ------ ---- ------------------------- ------------------------------------
   0      13   ``gre.version``           Version Number (``0``)
   ------ ---- ------------------------- ------------------------------------
   2      16   ``gre.protocol_type``     Protocol Type (EtherType)
   ------ ---- ------------------------- ------------------------------------
   4      32   ``gre.checksum``          Checksum, present only if ``C``
   ------ ---- ------------------------- ------------------------------------
   6      48   ``gre.reserved1``         Reserved1, present only if ``C``
   ------ ---- ------------------------- ------------------------------------
   8/4    64   ``gre.key``               Key, present only if ``K``, :rfc:`2890`
   ------ ---- ------------------------- ------------------------------------
   12/8/4 96   ``gre.sequence_number``   Sequence Number, present only if ``S``, :rfc:`2890`
   ====== ==== ========================= ====================================

``C``, ``K`` and ``S`` each gate their own field, so the header is 4, 8, 12 or
16 octets. The Protocol Type is an EtherType, dispatched through
:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>` as for
Ethernet and VLAN; unlike :class:`~pcapkit.protocols.link.frad.protocol.FRAD`, GRE
keeps no registry of its own. A nonzero Version Number (:rfc:`2637`'s Enhanced
GRE, version 1) is a different protocol, so it raises
:exc:`~pcapkit.utilities.exceptions.ProtocolError` rather than being misread.

Flow tracing and TCP reassembly follow the tunnel's inner flow, keyed by the
IP header nearest the TCP segment as for any tunnel (:issue:`1581`), and IPv4
reassembly of an outer datagram fragmented in transit yields a parsed GRE
layer.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.link.gre.protocol.GRE
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.link.gre.schema

.. autoclass:: pcapkit.protocols.link.gre.schema.GRE
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.gre.data

.. autoclass:: pcapkit.protocols.link.gre.data.GRE
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`2784`
.. [*] :rfc:`2890`
