Transport Layer Protocols
=========================

.. module:: pcapkit.protocols.transport

:mod:`pcapkit.protocols.transport` is collection of all protocols in
transport layer, with detailed implementation and methods.

.. toctree::
   :maxdepth: 4

Base Protocol
-------------

:mod:`pcapkit.protocols.transport.transport` contains
:class:`~pcapkit.protocols.transport.transport.Transport`,
which is a base class for transport layer protocols, eg.
:class:`~pcapkit.protocols.transport.transport.tcp.TCP` and
:class:`~pcapkit.protocols.transport.transport.udp.UDP`.

.. module:: pcapkit.protocols.transport.transport

.. autoclass:: pcapkit.protocols.transport.transport.Transport
   :members:
   :undoc-members:
   :private-members:
   :show-inheritance:

   .. autoattribute:: __layer__
