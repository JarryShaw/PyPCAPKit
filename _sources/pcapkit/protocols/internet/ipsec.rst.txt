IPsec - Internet Protocol Security
==================================

.. module:: pcapkit.protocols.internet.ipsec

:mod:`pcapkit.protocols.internet.ipsec` contains
:class:`~pcapkit.protocols.internet.ipsec.IPsec`
only, which is a base class for Internet Protocol
Security (IPsec) protocol family [*]_, eg.
:class:`~pcapkit.protocols.internet.ah.AH` and
:class:`~pcapkit.protocols.internet.esp.ESP` [*]_.

.. autoclass:: pcapkit.protocols.internet.ipsec.IPsec
   :no-members:
   :show-inheritance:

   :param \*args: Arbitrary positional arguments.
   :param \*\*kwargs: Arbitrary keyword arguments.

   .. automethod:: id

.. raw:: html

   <hr />

.. [*] https://en.wikipedia.org/wiki/IPsec
.. [*] :class:`~pcapkit.protocols.internet.esp.ESP` class is currently **NOT** implemented.
