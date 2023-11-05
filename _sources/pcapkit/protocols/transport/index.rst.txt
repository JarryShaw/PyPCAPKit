Transport Layer
===============

.. module:: pcapkit.protocols.transport
.. module:: pcapkit.protocols.data.transport
.. module:: pcapkit.protocols.schema.transport

:mod:`pcapkit.protocols.transport` is collection of all protocols in
transport layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 1

   transport
   tcp
   udp

.. todo::

   Implements DCCP, RSVP, SCTP.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.transport.TRANSTYPE

   alias of :class:`pcapkit.const.reg.transtype.TransType`
