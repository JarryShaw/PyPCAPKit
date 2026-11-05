============================================================================
:class:`~pcapkit.protocols.transport.tcp.protocol.TCP` Constant Enumerations
============================================================================

.. module:: pcapkit.const.tcp

.. list-table::

   * - :class:`TCP_Checksum <pcapkit.const.tcp.checksum.Checksum>`
     - TCP Checksum [*]_
   * - :class:`TCP_MPTCPOption <pcapkit.const.tcp.mp_tcp_option.MPTCPOption>`
     - Multipath TCP options [*]_
   * - :class:`TCP_Option <pcapkit.const.tcp.option.Option>`
     - TCP Option Kind Numbers [*]_
   * - :class:`TCP_Flags <pcapkit.const.tcp.flags.Flags>`
     - TCP Header Flags [*]_

TCP Checksum
============

.. module:: pcapkit.const.tcp.checksum

Generated from :class:`pcapkit.vendor.tcp.checksum.Checksum`.

.. autoclass:: pcapkit.const.tcp.checksum.Checksum
   :members:
   :undoc-members:
   :show-inheritance:

Multipath TCP Options
=====================

.. module:: pcapkit.const.tcp.mp_tcp_option

Generated from :class:`pcapkit.vendor.tcp.mp_tcp_option.MPTCPOption`.

.. autoclass:: pcapkit.const.tcp.mp_tcp_option.MPTCPOption
   :members:
   :undoc-members:
   :show-inheritance:

TCP Option Kind Numbers
=======================

.. module:: pcapkit.const.tcp.option

Generated from :class:`pcapkit.vendor.tcp.option.Option`.

.. autoclass:: pcapkit.const.tcp.option.Option
   :members:
   :undoc-members:
   :show-inheritance:

TCP Header Flags
================

.. module:: pcapkit.const.tcp.flags

Generated from :class:`pcapkit.vendor.tcp.flags.Flags`.

.. versionchanged:: 1.5.0

   A value outside ``0``-``0xFFF``, the flag bits of their 16-bit header word,
   raises :exc:`ValueError`, where
   |aenum|_ composed a pseudo-member for any integer.

.. autoclass:: pcapkit.const.tcp.flags.Flags
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-2
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#mptcp-option-subtypes
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-parameters-1
.. [*] https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml#tcp-header-flags
