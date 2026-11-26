IP - Internet Protocol
======================

.. module:: pcapkit.protocols.internet.ip
.. module:: pcapkit.protocols.internet.ip.protocol

:mod:`pcapkit.protocols.internet.ip.protocol` contains
:class:`~pcapkit.protocols.internet.ip.protocol.IP` only,
which is a base class for Internet Protocol (IP)
protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` and
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6`. Parsing octets through the base,
or building it with ``from_fields``, gives the one its ``version`` keyword names,
which a member checks as its own on both paths (:issue:`2840`); without it, octets
give the one their Version field names, and fields are refused. Its
:meth:`~pcapkit.protocols.internet.ip.protocol.IP.from_data` reads the ``version`` of its
data (:issue:`2574`).

.. autoclass:: pcapkit.protocols.internet.ip.protocol.IP
   :no-members:
   :show-inheritance:

   .. rubric:: Methods

   .. automethod:: id
   .. automethod:: from_data

   .. rubric:: Data Models

   .. automethod:: __init__
   .. automethod:: __new__

   .. rubric:: Utilities

   .. automethod:: _member_of_version
   .. automethod:: _construction_member

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Protocol
