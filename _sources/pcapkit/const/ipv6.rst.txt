==============================================================================
:class:`~pcapkit.protocols.internet.ipv6.protocol.IPv6` Constant Enumerations
==============================================================================

.. module:: pcapkit.const.ipv6

.. list-table::

   * - :class:`IPv6_ExtensionHeader <pcapkit.const.ipv6.extension_header.ExtensionHeader>`
     - IPv6 Extension Header Types [*]_
   * - :class:`IPv6_Option <pcapkit.const.ipv6.option.Option>`
     - Destination Options and Hop-by-Hop Options [*]_
   * - :class:`IPv6_OptionAction <pcapkit.const.ipv6.option_action.OptionAction>`
     - Option Actions [*]_
   * - :class:`IPv6_QSFunction <pcapkit.const.ipv6.qs_function.QSFunction>`
     - IPv6 QS Functions
   * - :class:`IPv6_RouterAlert <pcapkit.const.ipv6.router_alert.RouterAlert>`
     - IPv6 Router Alert Option Values [*]_
   * - :class:`IPv6_Routing <pcapkit.const.ipv6.routing.Routing>`
     - Routing Types [*]_
   * - :class:`IPv6_SeedID <pcapkit.const.ipv6.seed_id.SeedID>`
     - Seed-ID Types
   * - :class:`IPv6_SMFDPDMode <pcapkit.const.ipv6.smf_dpd_mode.SMFDPDMode>`
     - Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
   * - :class:`IPv6_TaggerID <pcapkit.const.ipv6.tagger_id.TaggerID>`
     - Tagger-ID Types [*]_

IPv6 Extension Header Types
===========================

.. module:: pcapkit.const.ipv6.extension_header

Generated from :class:`pcapkit.vendor.ipv6.extension_header.ExtensionHeader`.

.. versionchanged:: 1.5.0

   Generated from IANA's *IPv6 Extension Header Types* registry, where it was
   generated from the protocol-numbers registry (:issue:`925`).

.. autoclass:: pcapkit.const.ipv6.extension_header.ExtensionHeader
   :members:
   :undoc-members:
   :show-inheritance:

Option Actions
==============

.. module:: pcapkit.const.ipv6.option_action

Generated from :class:`pcapkit.vendor.ipv6.option_action.OptionAction`.

.. autoclass:: pcapkit.const.ipv6.option_action.OptionAction
   :members:
   :undoc-members:
   :show-inheritance:

Destination Options and Hop-by-Hop Options
==========================================

.. module:: pcapkit.const.ipv6.option

Generated from :class:`pcapkit.vendor.ipv6.option.Option`.

.. autoclass:: pcapkit.const.ipv6.option.Option
   :members:
   :undoc-members:
   :show-inheritance:

QS Functions
============

.. module:: pcapkit.const.ipv6.qs_function

Generated from :class:`pcapkit.vendor.ipv6.qs_function.QSFunction`.

.. autoclass:: pcapkit.const.ipv6.qs_function.QSFunction
   :members:
   :undoc-members:
   :show-inheritance:

IPv6 Router Alert Option Values
===============================

.. module:: pcapkit.const.ipv6.router_alert

Generated from :class:`pcapkit.vendor.ipv6.router_alert.RouterAlert`.

.. autoclass:: pcapkit.const.ipv6.router_alert.RouterAlert
   :members:
   :undoc-members:
   :show-inheritance:

IPv6 Routing Types
==================

.. module:: pcapkit.const.ipv6.routing

Generated from :class:`pcapkit.vendor.ipv6.routing.Routing`.

.. autoclass:: pcapkit.const.ipv6.routing.Routing
   :members:
   :undoc-members:
   :show-inheritance:

Seed-ID Types
=============

.. module:: pcapkit.const.ipv6.seed_id

Generated from :class:`pcapkit.vendor.ipv6.seed_id.SeedID`.

.. autoclass:: pcapkit.const.ipv6.seed_id.SeedID
   :members:
   :undoc-members:
   :show-inheritance:

Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
================================================================================

.. module:: pcapkit.const.ipv6.smf_dpd_mode

Generated from :class:`pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode`.

.. autoclass:: pcapkit.const.ipv6.smf_dpd_mode.SMFDPDMode
   :members:
   :undoc-members:
   :show-inheritance:

TaggerID Types
==============

.. module:: pcapkit.const.ipv6.tagger_id

Generated from :class:`pcapkit.vendor.ipv6.tagger_id.TaggerID`.

.. autoclass:: pcapkit.const.ipv6.tagger_id.TaggerID
   :members:
   :undoc-members:
   :show-inheritance:

.. rubric:: Footnotes

.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
.. [*] https://www.rfc-editor.org/rfc/rfc8200#section-4.2
.. [*] https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml#ipv6-routeralert-values-1
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#taggerId-types
