SNAP - Subnetwork Access Protocol
=================================

.. module:: pcapkit.protocols.link.snap
.. module:: pcapkit.protocols.link.snap.protocol

:mod:`pcapkit.protocols.link.snap.protocol` contains
:class:`~pcapkit.protocols.link.snap.protocol.SNAP`,
which implements the extractor for the IEEE 802 Subnetwork Access
Protocol (SNAP) [*]_ header, the information field of an
:class:`~pcapkit.protocols.link.llc.protocol.LLC` PDU addressed to the SNAP
LSAP, whose structure is:

.. table::

   ====== ===== ================ =========================================
   Octets Bits  Name             Description
   ====== ===== ================ =========================================
   0          0 ``snap.oui``     Organizationally Unique Identifier
   ------ ----- ---------------- -----------------------------------------
   3         24 ``snap.pid``     Protocol identifier
   ====== ===== ================ =========================================

Under the OUI ``00-00-00`` the protocol identifier is an EtherType
(:rfc:`9542#section-3`), and the payload is dispatched as Ethernet dispatches
it; under any other it is kept as
:class:`~pcapkit.protocols.misc.raw.protocol.Raw`.

.. versionadded:: 1.9.0

.. autoclass:: pcapkit.protocols.link.snap.protocol.SNAP
   :no-members:
   :show-inheritance:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make

   .. rubric:: Data Models

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data

Header Schemas
--------------

.. module:: pcapkit.protocols.link.snap.schema

.. autoclass:: pcapkit.protocols.link.snap.schema.SNAP
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.snap.data

.. autoclass:: pcapkit.protocols.link.snap.data.SNAP
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Subnetwork_Access_Protocol
