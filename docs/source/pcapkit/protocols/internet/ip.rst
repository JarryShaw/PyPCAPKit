IP - Internet Protocol
======================

.. module:: pcapkit.protocols.internet.ip
.. module:: pcapkit.protocols.internet.ip.protocol

:mod:`pcapkit.protocols.internet.ip.protocol` contains
:class:`~pcapkit.protocols.internet.ip.protocol.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` and
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`. Constructing the base gives the one
its ``version`` keyword names; without it, octets give the one their Version field
names, and fields are refused. Its
:meth:`~pcapkit.protocols.internet.ip.protocol.IP.from_data` reads the ``version`` of its
data (:issue:`2574`).

.. autoclass:: pcapkit.protocols.internet.ip.protocol.IP
   :no-members:
   :show-inheritance:

   .. automethod:: id
   .. automethod:: from_data

   .. automethod:: __init__
   .. automethod:: __new__

   .. automethod:: _member_of_version

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol
