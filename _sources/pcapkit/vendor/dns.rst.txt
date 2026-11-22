================================================================================
:class:`~pcapkit.protocols.application.dns.protocol.DNS` Vendor Crawlers
================================================================================

.. module:: pcapkit.vendor.dns

.. list-table::

   * - :class:`DNS_RRClass <pcapkit.vendor.dns.rr_class.RRClass>`
     - DNS CLASSes [*]_
   * - :class:`DNS_RRType <pcapkit.vendor.dns.rr_type.RRType>`
     - Resource Record (RR) TYPEs [*]_
   * - :class:`DNS_Opcode <pcapkit.vendor.dns.opcode.Opcode>`
     - DNS OpCodes [*]_
   * - :class:`DNS_RCode <pcapkit.vendor.dns.rcode.RCode>`
     - DNS RCODEs [*]_
   * - :class:`DNS_Option <pcapkit.vendor.dns.option.Option>`
     - DNS EDNS0 Option Codes (OPT) [*]_

DNS CLASSes
===========

.. module:: pcapkit.vendor.dns.rr_class

Generates :class:`pcapkit.const.dns.rr_class.RRClass`.

.. autoclass:: pcapkit.vendor.dns.rr_class.RRClass
   :members: FLAG, LINK
   :show-inheritance:

Resource Record (RR) TYPEs
==========================

.. module:: pcapkit.vendor.dns.rr_type

Generates :class:`pcapkit.const.dns.rr_type.RRType`.

.. autoclass:: pcapkit.vendor.dns.rr_type.RRType
   :members: FLAG, LINK
   :show-inheritance:

DNS OpCodes
===========

.. module:: pcapkit.vendor.dns.opcode

Generates :class:`pcapkit.const.dns.opcode.Opcode`.

.. autoclass:: pcapkit.vendor.dns.opcode.Opcode
   :members: FLAG, LINK
   :show-inheritance:

DNS RCODEs
==========

.. module:: pcapkit.vendor.dns.rcode

Generates :class:`pcapkit.const.dns.rcode.RCode`.

.. autoclass:: pcapkit.vendor.dns.rcode.RCode
   :members: FLAG, LINK
   :show-inheritance:

DNS EDNS0 Option Codes (OPT)
============================

.. module:: pcapkit.vendor.dns.option

Generates :class:`pcapkit.const.dns.option.Option`.

.. autoclass:: pcapkit.vendor.dns.option.Option
   :members: FLAG, LINK
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11
