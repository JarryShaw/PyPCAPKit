# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.dns.protocol.DNS` Vendor Crawlers
==============================================================================

.. module:: pcapkit.vendor.dns

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.application.dns.protocol.DNS` implementations. Available
enumerations include:

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

.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11

"""

from pcapkit.vendor.dns.opcode import Opcode as DNS_Opcode
from pcapkit.vendor.dns.option import Option as DNS_Option
from pcapkit.vendor.dns.rcode import RCode as DNS_RCode
from pcapkit.vendor.dns.rr_class import RRClass as DNS_RRClass
from pcapkit.vendor.dns.rr_type import RRType as DNS_RRType

__all__ = ['DNS_RRClass', 'DNS_RRType', 'DNS_Opcode', 'DNS_RCode', 'DNS_Option']
