:class:`~pcapkit.protocols.internet.ipv4.IPv4` Vendor Crawlers
==============================================================

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

.. automodule:: pcapkit.vendor.ipv4.classification_level
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.classification_level.ClassificationLevel
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.classification_level.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.option_class
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.option_class.OptionClass
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.option_class.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.option_number
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.option_number.OptionNumber
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv4.protection_authority
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.protection_authority.ProtectionAuthority
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.protection_authority.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.qs_function
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.qs_function.QSFunction
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.qs_function.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.router_alert
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.router_alert.RouterAlert
   :noindex:
   :members: FLAG, LINK
   :show-inheritance:

.. automodule:: pcapkit.vendor.ipv4.tos_del
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.tos_del.ToSDelay
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.tos_del.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.tos_ecn
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.tos_ecn.ToSECN
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.tos_ecn.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.tos_pre
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.tos_pre.ToSPrecedence
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.tos_pre.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.tos_rel
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.tos_rel.ToSReliability
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.tos_rel.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.tos_thr
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.tos_thr.ToSThroughput
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.tos_thr.DATA
   :no-value:

.. automodule:: pcapkit.vendor.ipv4.ts_flag
   :no-members:

.. autoclass:: pcapkit.vendor.ipv4.ts_flag.TSFlag
   :noindex:
   :members: FLAG
   :show-inheritance:

.. autodata:: pcapkit.vendor.ipv4.ts_flag.DATA
   :no-value:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ip-parameters-1
.. [*] https://www.iana.org/assignments/ip-parameters/ip-parameters.xhtml#ipv4-router-alert-option-values
