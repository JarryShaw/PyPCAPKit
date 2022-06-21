# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.ipv4.IPv4` Vendor Crawlers
====================================================================

.. module:: pcapkit.vendor.ipv4

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipv4.IPv4` implementations. Available
crawlers include:

.. list-table::

   * - :class:`IPv4_ClassificationLevel <pcapkit.vendor.ipv4.classification_level.ClassificationLevel>`
     - Classification Level Encodings
   * - :class:`IPv4_OptionClass <pcapkit.vendor.ipv4.option_class.OptionClass>`
     - Option Classes
   * - :class:`IPv4_OptionNumber <pcapkit.vendor.ipv4.option_number.OptionNumber>`
     - IP Option Numbers [*]_
   * - :class:`IPv4_ProtectionAuthority <pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority>`
     - Protection Authority Bit Assignments
   * - :class:`IPv4_QSFunction <pcapkit.vendor.ipv4.qs_function.QSFunction>`
     - QS Functions
   * - :class:`IPv4_RouterAlert <pcapkit.vendor.ipv4.router_alert.RouterAlert>`
     - IPv4 Router Alert Option Values [*]_
   * - :class:`IPv4_ToSDelay <pcapkit.vendor.ipv4.tos_del.ToSDelay>`
     - ToS (DS Field) Delay
   * - :class:`IPv4_ToSECN <pcapkit.vendor.ipv4.tos_ecn.ToSECN>`
     - ToS ECN Field
   * - :class:`IPv4_ToSPrecedence <pcapkit.vendor.ipv4.tos_pre.TOSPrecedence>`
     - ToS (DS Field) Precedence
   * - :class:`IPv4_ToSReliability <pcapkit.vendor.ipv4.tos_rel.TOSReliability>`
     - ToS (DS Field) Reliability
   * - :class:`IPv4_ToSThroughput <pcapkit.vendor.ipv4.tos_thr.TOSThroughput>`
     - ToS (DS Field) Throughput

.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ipv4-router-alert-option-values

"""

from pcapkit.vendor.ipv4.classification_level import ClassificationLevel as IPv4_ClassificationLevel
from pcapkit.vendor.ipv4.option_class import OptionClass as IPv4_OptionClass
from pcapkit.vendor.ipv4.option_number import OptionNumber as IPv4_OptionNumber
from pcapkit.vendor.ipv4.protection_authority import ProtectionAuthority as IPv4_ProtectionAuthority
from pcapkit.vendor.ipv4.qs_function import QSFunction as IPv4_QSFunction
from pcapkit.vendor.ipv4.router_alert import RouterAlert as IPv4_RouterAlert
from pcapkit.vendor.ipv4.tos_del import ToSDelay as IPv4_ToSDelay
from pcapkit.vendor.ipv4.tos_ecn import ToSECN as IPv4_ToSECN
from pcapkit.vendor.ipv4.tos_pre import ToSPrecedence as IPv4_ToSPrecedence
from pcapkit.vendor.ipv4.tos_rel import ToSReliability as IPv4_ToSReliability
from pcapkit.vendor.ipv4.tos_thr import ToSThroughput as IPv4_ToSThroughput
from pcapkit.vendor.ipv4.ts_flag import TSFlag as IPv4_TSFlag

__all__ = ['IPv4_ClassificationLevel', 'IPv4_OptionClass', 'IPv4_OptionNumber', 'IPv4_ProtectionAuthority',
           'IPv4_QSFunction', 'IPv4_RouterAlert', 'IPv4_ToSDelay', 'IPv4_ToSECN', 'IPv4_ToSPrecedence',
           'IPv4_ToSReliability', 'IPv4_ToSThroughput', 'IPv4_TSFlag']
