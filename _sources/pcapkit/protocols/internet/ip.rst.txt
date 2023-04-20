IP - Internet Protocol
======================

.. module:: pcapkit.protocols.internet.ip

:mod:`pcapkit.protocols.internet.ip` contains
:class:`~pcapkit.protocols.internet.ip.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, eg.
:class:`~pcapkit.protocols.internet.ipv4.IPv4`,
:class:`~pcapkit.protocols.internet.ipv6.IPv6`, and
:class:`~pcapkit.protocols.internet.ipsec.IPsec`.

.. autoclass:: pcapkit.protocols.internet.ip.IP
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: id

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol
