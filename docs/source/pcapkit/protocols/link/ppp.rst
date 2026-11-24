PPP - Point-to-Point Protocol
=============================

.. module:: pcapkit.protocols.link.ppp
.. module:: pcapkit.protocols.link.ppp.protocol

:mod:`pcapkit.protocols.link.ppp.protocol` contains
:class:`~pcapkit.protocols.link.ppp.protocol.PPP`,
which implements the extractor for the Point-to-Point Protocol
(PPP) [*]_ frame of :rfc:`1661`, in the HDLC-like framing of
:rfc:`1662`, whose structure is:

.. table::

   ====== ===== ================ =========================================
   Octets Bits  Name             Description
   ====== ===== ================ =========================================
   0          0 ``ppp.address``  Address (``0xFF``, optional)
   ------ ----- ---------------- -----------------------------------------
   1          8 ``ppp.control``  Control (``0x03``, optional)
   ------ ----- ---------------- -----------------------------------------
   2         16 ``ppp.protocol`` Protocol (one octet when compressed)
   ====== ===== ================ =========================================

The Address and Control fields are read where the frame opens with ``0xFF 0x03``,
and the Protocol field is one octet where its first octet is odd. LCP, IPCP,
IPv6CP, PAP and CHAP packets are read at header level, as
``ppp.control_packet``.

.. versionadded:: 1.7.0

.. autoclass:: pcapkit.protocols.link.ppp.protocol.PPP
   :no-members:
   :show-inheritance:

   .. rubric:: Defaults

   .. autoattribute:: __proto__
      :no-value:
   .. autoattribute:: __proto_key__
      :no-value:
   .. autoattribute:: __control__
      :no-value:

   .. rubric:: Properties

   .. autoproperty:: name
   .. autoproperty:: length
   .. autoproperty:: protocol

   .. rubric:: Methods

   .. automethod:: read
   .. automethod:: make
   .. automethod:: register
   .. automethod:: register_control

   .. rubric:: Data Models

   .. automethod:: __index__

   .. rubric:: Utilities

   .. automethod:: _make_data
   .. automethod:: _lookup_control
   .. automethod:: _read_control_header
   .. automethod:: _make_control_header

Header Schemas
--------------

.. module:: pcapkit.protocols.link.ppp.schema

.. autoclass:: pcapkit.protocols.link.ppp.schema.PPP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.ppp.schema.ControlPacket
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.ppp.schema.ControlHeader
   :members:
   :show-inheritance:

Type Stubs
~~~~~~~~~~

.. autoclass:: pcapkit.protocols.link.ppp.schema.ControlTest
   :members:
   :show-inheritance:

Auxiliary Functions
~~~~~~~~~~~~~~~~~~~

.. autofunction:: pcapkit.protocols.link.ppp.schema.ppp_protocol_selector
.. autofunction:: pcapkit.protocols.link.ppp.schema.ppp_is_control
.. autofunction:: pcapkit.protocols.link.ppp.schema.ppp_control_selector

Data Models
-----------

.. module:: pcapkit.protocols.link.ppp.data

.. autoclass:: pcapkit.protocols.link.ppp.data.PPP
   :members:
   :show-inheritance:

.. autoclass:: pcapkit.protocols.link.ppp.data.ControlPacket
   :members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Point-to-Point_Protocol
