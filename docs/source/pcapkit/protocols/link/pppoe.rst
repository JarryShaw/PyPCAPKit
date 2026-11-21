PPPoE - PPP over Ethernet
=========================

.. module:: pcapkit.protocols.link.pppoe
.. module:: pcapkit.protocols.link.pppoe.protocol

:mod:`pcapkit.protocols.link.pppoe.protocol` contains
:class:`~pcapkit.protocols.link.pppoe.protocol.PPPoE`,
which implements the extractor for PPP over Ethernet
(PPPoE) [*]_ of :rfc:`2516`, whose structure is:

.. table::

   ====== ===== ===================== =========================================
   Octets Bits  Name                  Description
   ====== ===== ===================== =========================================
   0          0 ``pppoe.version``     Version (``1``)
   ------ ----- --------------------- -----------------------------------------
   0          4 ``pppoe.type``        Type (``1``)
   ------ ----- --------------------- -----------------------------------------
   1          8 ``pppoe.code``        Code
   ------ ----- --------------------- -----------------------------------------
   2         16 ``pppoe.session_id``  Session ID
   ------ ----- --------------------- -----------------------------------------
   4         32 ``pppoe.length``      Length of the payload
   ------ ----- --------------------- -----------------------------------------
   6         48 ``pppoe.tags``        Tags (discovery stage)
   ====== ===== ===================== =========================================

The Code tells the stages apart: a discovery packet carries tags and no next
layer, and a session packet a PPP frame.

.. versionadded:: 1.7.0

.. autoclass:: pcapkit.protocols.link.pppoe.protocol.PPPoE
   :no-members:
   :show-inheritance:

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: code

   .. automethod:: read
   .. automethod:: make

   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _make_tag

Header Schemas
--------------

.. module:: pcapkit.protocols.link.pppoe.schema

.. autoclass:: pcapkit.protocols.link.pppoe.schema.PPPoE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.pppoe.schema.Tag
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.link.pppoe.schema.VersionType
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.link.pppoe.schema.pppoe_payload_length

Data Models
-----------

.. module:: pcapkit.protocols.link.pppoe.data

.. autoclass:: pcapkit.protocols.link.pppoe.data.PPPoE
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.pppoe.data.Tag
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Point-to-Point_Protocol_over_Ethernet
