GRE - Generic Routing Encapsulation
====================================

.. module:: pcapkit.protocols.link.gre

:mod:`pcapkit.protocols.link.gre` contains
:class:`~pcapkit.protocols.link.gre.GRE`
only, which implements the extractor for the Generic Routing Encapsulation
base header [*]_ plus the optional Key and Sequence Number extensions [*]_, as
seen on a ``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose
``arphrd_type`` is ``ARPHRD_IPGRE`` or ``ARPHRD_IP6GRE`` -- both land on this
one class, the "IP"/"IP6" distinction being only which outer IP version the
tunnel carries. Its structure, with every optional field present, is
described as below:

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

``C``, ``K`` and ``S`` each gate their own field independently, so the header
is 4, 8, 12 or 16 octets depending on which are set. The Protocol Type field
is an EtherType, dispatched onward through
:attr:`Link.__proto__ <pcapkit.protocols.link.link.Link.__proto__>`, the same
family registry Ethernet, VLAN and LinuxSLL already share -- unlike
:class:`~pcapkit.protocols.link.frad.FRAD`, this class keeps no registry of
its own. A nonzero Version Number (RFC 2637's "Enhanced GRE"/PPTP, version 1)
is a different, incompatible protocol and is refused rather than misread; see
the module docstring's *Scope* section.

.. autoclass:: pcapkit.protocols.link.gre.GRE
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

.. module:: pcapkit.protocols.schema.link.gre

.. autoclass:: pcapkit.protocols.schema.link.gre.GRE
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.gre

.. autoclass:: pcapkit.protocols.data.link.gre.GRE
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`2784`
.. [*] :rfc:`2890`
