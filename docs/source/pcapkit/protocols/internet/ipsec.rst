IPsec - Internet Protocol Security
==================================

.. module:: pcapkit.protocols.internet.ipsec
.. module:: pcapkit.protocols.internet.ipsec.protocol

:mod:`pcapkit.protocols.internet.ipsec.protocol` contains
:class:`~pcapkit.protocols.internet.ipsec.protocol.IPsec`
only, which is a base class for Internet Protocol
Security (IPsec) protocol family [*]_, e.g.
:class:`~pcapkit.protocols.internet.ah.protocol.AH` and
:class:`~pcapkit.protocols.internet.esp.protocol.ESP`.

.. autoclass:: pcapkit.protocols.internet.ipsec.protocol.IPsec
   :no-members:
   :show-inheritance:

   .. automethod:: id

.. rubric:: Footnotes

.. [*] https://en.wikipedia.org/wiki/IPsec
