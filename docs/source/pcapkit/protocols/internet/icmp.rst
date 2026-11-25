ICMP - Internet Control Message Protocol
========================================

.. module:: pcapkit.protocols.internet.icmp
.. module:: pcapkit.protocols.internet.icmp.protocol

:mod:`pcapkit.protocols.internet.icmp.protocol` contains
:class:`~pcapkit.protocols.internet.icmp.protocol.ICMP` only,
which is a base class for Internet Control Message
Protocol (ICMP) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.icmpv4.protocol.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.protocol.ICMPv6`. Parsing octets through the
base, or building it with ``from_fields``, gives the one its ``version`` keyword
names, which a member checks as its own on both paths (:issue:`2840`), and is
refused without it, since an ICMP message carries no version of its own. Its
:meth:`~pcapkit.protocols.internet.icmp.protocol.ICMP.from_data` gives the one whose data
model it is handed (:issue:`2574`).

.. versionadded:: 1.6.0

.. autoclass:: pcapkit.protocols.internet.icmp.protocol.ICMP
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

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
