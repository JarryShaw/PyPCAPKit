ICMP - Internet Control Message Protocol
========================================

.. module:: pcapkit.protocols.internet.icmp

:mod:`pcapkit.protocols.internet.icmp` contains
:class:`~pcapkit.protocols.internet.icmp.ICMP` only,
which is a base class for Internet Control Message
Protocol (ICMP) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.icmpv4.ICMPv4` and
:class:`~pcapkit.protocols.internet.icmpv6.ICMPv6`.

.. autoclass:: pcapkit.protocols.internet.icmp.ICMP
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/Internet_Control_Message_Protocol
