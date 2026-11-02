ICMP - Internet Control Message Protocol
========================================

.. module:: pcapkit.protocols.internet.icmp

:mod:`pcapkit.protocols.internet.icmp` contains
:class:`~pcapkit.protocols.internet.icmp.ICMP` only,
which is a base class for Internet Control Message
Protocol (ICMP) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6`. Constructing the base gives the
one its ``version`` keyword names, from octets or from fields, and is refused
without it, since an ICMP message carries no version of its own. Its
:meth:`~pcapkit.protocols.internet.icmp.ICMP.from_data` gives the one whose data
model it is handed (:issue:`2574`).

.. autoclass:: pcapkit.protocols.internet.icmp.ICMP
   :no-members:
   :show-inheritance:

   .. automethod:: id
   .. automethod:: from_data

   .. automethod:: __init__
   .. automethod:: __new__

   .. automethod:: _member_of_version

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
