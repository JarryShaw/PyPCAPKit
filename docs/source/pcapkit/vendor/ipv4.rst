=======================================================================
:class:`~pcapkit.protocols.internet.ipv4.protocol.IPv4` Vendor Crawlers
=======================================================================

.. module:: pcapkit.vendor.ipv4

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
   * - :class:`IPv4_ToSPrecedence <pcapkit.vendor.ipv4.tos_pre.ToSPrecedence>`
     - ToS (DS Field) Precedence
   * - :class:`IPv4_ToSReliability <pcapkit.vendor.ipv4.tos_rel.ToSReliability>`
     - ToS (DS Field) Reliability
   * - :class:`IPv4_ToSThroughput <pcapkit.vendor.ipv4.tos_thr.ToSThroughput>`
     - ToS (DS Field) Throughput
   * - :class:`IPv4_TSFlag <pcapkit.vendor.ipv4.ts_flag.TSFlag>`
     - TS Flag

Classification Level Encodings
==============================

.. module:: pcapkit.vendor.ipv4.classification_level

Generates :class:`pcapkit.const.ipv4.classification_level.ClassificationLevel`.

.. autoclass:: pcapkit.vendor.ipv4.classification_level.ClassificationLevel
   :members: FLAG
   :show-inheritance:

Option Classes
==============

.. module:: pcapkit.vendor.ipv4.option_class

Generates :class:`pcapkit.const.ipv4.option_class.OptionClass`.

.. autoclass:: pcapkit.vendor.ipv4.option_class.OptionClass
   :members: FLAG
   :show-inheritance:

IP Option Numbers
=================

.. module:: pcapkit.vendor.ipv4.option_number

Generates :class:`pcapkit.const.ipv4.option_number.OptionNumber`.

.. autoclass:: pcapkit.vendor.ipv4.option_number.OptionNumber
   :members: FLAG, LINK
   :show-inheritance:

Protection Authority Bit Assignments
====================================

.. module:: pcapkit.vendor.ipv4.protection_authority

Generates :class:`pcapkit.const.ipv4.protection_authority.ProtectionAuthority`.

.. autoclass:: pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority
   :members: FLAG
   :show-inheritance:

QS Functions
============

.. module:: pcapkit.vendor.ipv4.qs_function

Generates :class:`pcapkit.const.ipv4.qs_function.QSFunction`.

.. autoclass:: pcapkit.vendor.ipv4.qs_function.QSFunction
   :members: FLAG
   :show-inheritance:

IPv4 Router Alert Option Values
===============================

.. module:: pcapkit.vendor.ipv4.router_alert

Generates :class:`pcapkit.const.ipv4.router_alert.RouterAlert`.

.. autoclass:: pcapkit.vendor.ipv4.router_alert.RouterAlert
   :members: FLAG, LINK
   :show-inheritance:

ToS (DS Field) Delay
====================

.. module:: pcapkit.vendor.ipv4.tos_del

Generates :class:`pcapkit.const.ipv4.tos_del.ToSDelay`.

.. autoclass:: pcapkit.vendor.ipv4.tos_del.ToSDelay
   :members: FLAG
   :show-inheritance:

ToS ECN Field
=============

.. module:: pcapkit.vendor.ipv4.tos_ecn

Generates :class:`pcapkit.const.ipv4.tos_ecn.ToSECN`.

.. autoclass:: pcapkit.vendor.ipv4.tos_ecn.ToSECN
   :members: FLAG
   :show-inheritance:

ToS (DS Field) Precedence
=========================

.. module:: pcapkit.vendor.ipv4.tos_pre

Generates :class:`pcapkit.const.ipv4.tos_pre.ToSPrecedence`.

.. autoclass:: pcapkit.vendor.ipv4.tos_pre.ToSPrecedence
   :members: FLAG
   :show-inheritance:

ToS (DS Field) Reliability
==========================

.. module:: pcapkit.vendor.ipv4.tos_rel

Generates :class:`pcapkit.const.ipv4.tos_rel.ToSReliability`.

.. autoclass:: pcapkit.vendor.ipv4.tos_rel.ToSReliability
   :members: FLAG
   :show-inheritance:

ToS (DS Field) Throughput
=========================

.. module:: pcapkit.vendor.ipv4.tos_thr

Generates :class:`pcapkit.const.ipv4.tos_thr.ToSThroughput`.

.. autoclass:: pcapkit.vendor.ipv4.tos_thr.ToSThroughput
   :members: FLAG
   :show-inheritance:

TS Flag
=======

.. module:: pcapkit.vendor.ipv4.ts_flag

Generates :class:`pcapkit.const.ipv4.ts_flag.TSFlag`.

.. autoclass:: pcapkit.vendor.ipv4.ts_flag.TSFlag
   :members: FLAG
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ipv4-router-alert-option-values
