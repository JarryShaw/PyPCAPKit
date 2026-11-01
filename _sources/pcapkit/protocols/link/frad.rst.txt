FRAD - Frame Relay Access Device
=================================

.. module:: pcapkit.protocols.link.frad

:mod:`pcapkit.protocols.link.frad` contains
:class:`~pcapkit.protocols.link.frad.FRAD`
only, which implements the extractor for Frame Relay's multiprotocol
encapsulation [*]_, as seen on a ``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2``
capture whose ``arphrd_type`` is ``ARPHRD_FRAD``. Its structure, the Q.922
LAPF address onward with no trailing FCS, is described as below:

.. table::

   ====== ==== ================= ==========================================
   Octets Bits Name              Description
   ====== ==== ================= ==========================================
   0      0    ``frad.addr``     Q.922 Address (2-octet form)
   2      16   ``frad.control``  Control (``0x03``, UI, for data traffic)
   3      24   ``frad.nlpid``    NLPID, or the ``0x00`` pad ahead of a SNAP
                                  header
   ====== ==== ================= ==========================================

When ``nlpid`` is the ``0x00`` pad marker, a further NLPID octet (``0x80``
for SNAP), a 3-octet OUI and a 2-octet PID follow, kept as ``frad.ext_nlpid``,
``frad.oui`` and ``frad.pid``.

.. autoclass:: pcapkit.protocols.link.frad.FRAD
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
   .. automethod:: _import_next_layer

   .. autoattribute:: __proto__
      :no-value:

Header Schemas
--------------

.. module:: pcapkit.protocols.schema.link.frad

.. autoclass:: pcapkit.protocols.schema.link.frad.FRAD
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.data.link.frad

.. autoclass:: pcapkit.protocols.data.link.frad.FRAD
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`2427` (obsoleting :rfc:`1490`)
