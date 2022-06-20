Transport Layer Protocols
=========================

.. module:: pcapkit.protocols.transport
.. module:: pcapkit.protocols.data.transport

:mod:`pcapkit.protocols.transport` is collection of all protocols in
transport layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 5

   transport
   tcp
   udp

.. todo::

   Implements DCCP, RSVP, SCTP.

Protocol Registry
-----------------

.. data:: pcapkit.protocols.transport.TRANSTYPE

   Alias of :class:`pcapkit.const.reg.transtype.TransType`.
