# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.application.dns.protocol.DNS` Constant Enumerations
====================================================================================

.. module:: pcapkit.const.dns

This module contains all constant enumerations of
:class:`~pcapkit.protocols.application.dns.protocol.DNS` implementations. Available
enumerations include:

.. list-table::

   * - :class:`DNS_RRClass <pcapkit.const.dns.rr_class.RRClass>`
     - DNS CLASSes [*]_
   * - :class:`DNS_RRType <pcapkit.const.dns.rr_type.RRType>`
     - Resource Record (RR) TYPEs [*]_
   * - :class:`DNS_Opcode <pcapkit.const.dns.opcode.Opcode>`
     - DNS OpCodes [*]_
   * - :class:`DNS_RCode <pcapkit.const.dns.rcode.RCode>`
     - DNS RCODEs [*]_
   * - :class:`DNS_Option <pcapkit.const.dns.option.Option>`
     - DNS EDNS0 Option Codes (OPT) [*]_

.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-2
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-5
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-6
.. [*] https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-11

"""

from typing import TYPE_CHECKING

from pcapkit.utilities.importlib import lazy_exports

if TYPE_CHECKING:
    from pcapkit.const.dns.opcode import Opcode as DNS_Opcode
    from pcapkit.const.dns.option import Option as DNS_Option
    from pcapkit.const.dns.rcode import RCode as DNS_RCode
    from pcapkit.const.dns.rr_class import RRClass as DNS_RRClass
    from pcapkit.const.dns.rr_type import RRType as DNS_RRType

__all__ = ['DNS_RRClass', 'DNS_RRType', 'DNS_Opcode', 'DNS_RCode', 'DNS_Option']

__getattr__, __dir__ = lazy_exports(__name__, globals(), {
    'DNS_RRClass': ('rr_class', 'RRClass'),
    'DNS_RRType': ('rr_type', 'RRType'),
    'DNS_Opcode': ('opcode', 'Opcode'),
    'DNS_RCode': ('rcode', 'RCode'),
    'DNS_Option': ('option', 'Option'),
})
