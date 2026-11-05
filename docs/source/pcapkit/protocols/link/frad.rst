FRAD - Frame Relay Access Device
=================================

.. module:: pcapkit.protocols.link.frad
.. module:: pcapkit.protocols.link.frad.protocol

:mod:`pcapkit.protocols.link.frad.protocol` contains
:class:`~pcapkit.protocols.link.frad.protocol.FRAD`
only, which implements the extractor for Frame Relay's multiprotocol
encapsulation [*]_, as seen on a ``LINKTYPE_FRELAY`` capture, or on a
``LINKTYPE_LINUX_SLL``/``LINKTYPE_LINUX_SLL2`` capture whose ``arphrd_type`` is
``ARPHRD_FRAD``. Its structure, the Q.922
LAPF address onward with no trailing FCS, is described as below:

.. table::

   ====== ==== ================= ==========================================
   Octets Bits Name              Description
   ====== ==== ================= ==========================================
   0      0    ``frad.addr``     Q.922 Address (2-octet form)
   2      16   ``frad.control``  Control (``0x03``, UI, for data traffic)
   3      24   ``frad.nlpid``    NLPID, or the ``0x00`` pad ahead of one
   ====== ==== ================= ==========================================

When ``nlpid`` is the ``0x00`` pad, the NLPID follows it as ``frad.ext_nlpid``.
An NLPID of ``0x80``, with or without the pad, is followed by a SNAP header, a
3-octet OUI and a 2-octet PID, kept as ``frad.oui`` and ``frad.pid``.

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.link.frad.protocol.FRAD
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

   .. autoproperty:: name
   .. autoproperty:: alias
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. automethod:: id
   .. automethod:: read
   .. automethod:: make
   .. automethod:: register

   .. automethod:: __length_hint__
   .. automethod:: __index__

   .. automethod:: _make_data
   .. automethod:: _import_next_layer

Header Schemas
--------------

.. module:: pcapkit.protocols.link.frad.schema

.. autoclass:: pcapkit.protocols.link.frad.schema.FRAD
   :members:
   :show-inheritance:

Data Models
-----------

.. module:: pcapkit.protocols.link.frad.data

.. autoclass:: pcapkit.protocols.link.frad.data.FRAD
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] :rfc:`2427` (obsoleting :rfc:`1490`)
