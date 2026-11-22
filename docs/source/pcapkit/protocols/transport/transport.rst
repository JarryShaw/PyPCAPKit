Transport Layer Base Protocol
=============================

.. module:: pcapkit.protocols.transport.transport

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, e.g.
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP`,
:class:`~pcapkit.protocols.transport.udp.protocol.UDP` and
:class:`~pcapkit.protocols.transport.sctp.protocol.SCTP`.

.. versionremoved:: 1.7.0

   ``pcapkit.protocols.transport.transport.logger``, which nothing logged to once
   :meth:`Transport.analyze <pcapkit.protocols.transport.transport.Transport.analyze>`
   stopped (:issue:`2862`).

.. autoclass:: pcapkit.protocols.transport.transport.Transport
   :no-members:
   :show-inheritance:

   .. autoattribute:: __proto__
      :no-value:

      .. important::

         The attribute **must** be defined and maintained in subclass.

   .. autoattribute:: __layer__
      :no-value:

   .. autoproperty:: layer

   .. automethod:: register
   .. automethod:: analyze
   .. automethod:: from_data

   .. automethod:: __post_init__

   .. automethod:: _make_port
   .. automethod:: _decode_next_layer
