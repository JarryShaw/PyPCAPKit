Base Protocol
=============

.. module:: pcapkit.protocols.transport.transport

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

.. autoclass:: pcapkit.protocols.transport.transport.Transport
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. autoproperty:: layer

   .. automethod:: register
   .. automethod:: analyze

   .. automethod:: _decode_next_layer

   .. autoattribute:: __layer__
   .. autoattribute:: __proto__

      .. important::

         The attribute **must** be defined and maintained in subclass.
