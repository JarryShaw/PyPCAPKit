==============================================================
:class:`~pcapkit.protocols.internet.ipv4.IPv4` Vendor Crawlers
==============================================================

.. module:: pcapkit.vendor.ipv4

This module contains all vendor crawlers of
:class:`~pcapkit.protocols.internet.ipv4.IPv4` implementations. Available
vendor crawlers include:

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
   * - :class:`IPv4_TSFlag <pcapkit.vendor.ipv4.ts_flag.TSFlag>`
     - TS Flag

Classification Level Encodings
==============================

.. module:: pcapkit.vendor.ipv4.classification_level

This module contains the vendor crawler for **Classification Level Encodings**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.classification_level.ClassificationLevel`.

.. autoclass:: pcapkit.vendor.ipv4.classification_level.ClassificationLevel
   :members: FLAG, LINK
   :show-inheritance:

Option Classes
==============

.. module:: pcapkit.vendor.ipv4.option_class

This module contains the vendor crawler for **Option Classes**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.option_class.OptionClass`.

.. autoclass:: pcapkit.vendor.ipv4.option_class.OptionClass
   :members: FLAG, LINK
   :show-inheritance:

IP Option Numbers
=================

.. module:: pcapkit.vendor.ipv4.option_number

This module contains the vendor crawler for **IP Option Numbers**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.option_number.OptionNumber`.

.. autoclass:: pcapkit.vendor.ipv4.option_number.OptionNumber
   :members: FLAG, LINK
   :show-inheritance:

Protection Authority Bit Assignments
====================================

.. module:: pcapkit.vendor.ipv4.protection_authority

This module contains the vendor crawler for **Protection Authority Bit Assignments**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.protection_authority.ProtectionAuthority`.

.. autoclass:: pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority
   :members: FLAG, LINK
   :show-inheritance:

QS Functions
============

.. module:: pcapkit.vendor.ipv4.qs_function

This module contains the vendor crawler for **QS Functions**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.qs_function.QSFunction`.

.. autoclass:: pcapkit.vendor.ipv4.qs_function.QSFunction
   :members: FLAG, LINK
   :show-inheritance:

IPv4 Router Alert Option Values
===============================

.. module:: pcapkit.vendor.ipv4.router_alert

This module contains the vendor crawler for **IPv4 Router Alert Option Values**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.router_alert.RouterAlert`.

.. autoclass:: pcapkit.vendor.ipv4.router_alert.RouterAlert
   :members: FLAG, LINK
   :show-inheritance:

ToS (DS Field) Delay
====================

.. module:: pcapkit.vendor.ipv4.tos_del

This module contains the vendor crawler for **ToS (DS Field) Delay**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.tos_del.ToSDelay`.

.. autoclass:: pcapkit.vendor.ipv4.tos_del.ToSDelay
   :members: FLAG, LINK
   :show-inheritance:

ToS ECN Field
=============

.. module:: pcapkit.vendor.ipv4.tos_ecn

This module contains the vendor crawler for **ToS ECN Field**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.tos_ecn.ToSECN`.

.. autoclass:: pcapkit.vendor.ipv4.tos_ecn.ToSECN
   :members: FLAG, LINK
   :show-inheritance:

ToS (DS Field) Precedence
=========================

.. module:: pcapkit.vendor.ipv4.tos_pre

This module contains the vendor crawler for **ToS (DS Field) Precedence**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.tos_pre.ToSPrecedence`.

.. autoclass:: pcapkit.vendor.ipv4.tos_pre.ToSPrecedence
   :members: FLAG, LINK
   :show-inheritance:

ToS (DS Field) Reliability
==========================

.. module:: pcapkit.vendor.ipv4.tos_rel

This module contains the vendor crawler for **ToS (DS Field) Reliability**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.tos_rel.ToSReliability`.

.. autoclass:: pcapkit.vendor.ipv4.tos_rel.ToSReliability
   :members: FLAG, LINK
   :show-inheritance:

ToS (DS Field) Throughput
=========================

.. module:: pcapkit.vendor.ipv4.tos_thr

This module contains the vendor crawler for **ToS (DS Field) Throughput**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.tos_thr.ToSThroughput`.

.. autoclass:: pcapkit.vendor.ipv4.tos_thr.ToSThroughput
   :members: FLAG, LINK
   :show-inheritance:

TS Flag
=======

.. module:: pcapkit.vendor.ipv4.ts_flag

This module contains the vendor crawler for **TS Flag**,
which is automatically generating :class:`pcapkit.+vendor+.ipv4.ts_flag.TSFlag`.

.. autoclass:: pcapkit.vendor.ipv4.ts_flag.TSFlag
   :members: FLAG, LINK
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ipv4-router-alert-option-values
