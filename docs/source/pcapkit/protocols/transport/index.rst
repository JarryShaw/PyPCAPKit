Transport Layer
===============

.. module:: pcapkit.protocols.transport
.. module:: pcapkit.protocols.data.transport
.. module:: pcapkit.protocols.schema.transport

:mod:`pcapkit.protocols.transport` is the collection of all protocols in
transport layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 1

   transport
   dccp
   sctp
   tcp
   udp

.. todo::

   Implement RSVP.

Protocol Registry
-----------------

.. data:: TRANSTYPE
   :module: pcapkit.protocols.transport

   alias of :class:`pcapkit.const.reg.transtype.TransType`
