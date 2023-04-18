=====================================================================
:class:`~pcapkit.protocols.internet.ipv6.IPv6` Constant Enumerations
=====================================================================

.. module:: pcapkit.const.ipv6

This module contains all constant enumerations of
:class:`~pcapkit.protocols.internet.ipv6.IPv6` implementations. Available
enumerations include:

.. list-table::

   * - :class:`IPv6_Extension_Header <pcapkit.const.ipv6.extension_header.ExtensionHeader>`
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

This module contains the constant enumeration for **IPv6 Extension Header Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.extension_header.ExtensionHeader`.

.. autoclass:: pcapkit.const.ipv6.extension_header.ExtensionHeader
   :members:
   :undoc-members:
   :show-inheritance:

Option Actions
==============

.. module:: pcapkit.const.ipv6.option_action

This module contains the constant enumeration for **Option Actions**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.option_action.OptionAction`.

.. autoclass:: pcapkit.const.ipv6.option_action.OptionAction
   :members:
   :undoc-members:
   :show-inheritance:

Destination Options and Hop-by-Hop Options
==========================================

.. module:: pcapkit.const.ipv6.option

This module contains the constant enumeration for **Destination Options and Hop-by-Hop Options**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.option.Option`.

.. autoclass:: pcapkit.const.ipv6.option.Option
   :members:
   :undoc-members:
   :show-inheritance:

QS Functions
============

.. module:: pcapkit.const.ipv6.qs_function

This module contains the constant enumeration for **QS Functions**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.qs_function.QSFunction`.

.. autoclass:: pcapkit.const.ipv6.qs_function.QSFunction
   :members:
   :undoc-members:
   :show-inheritance:

IPv6 Router Alert Option Values
===============================

.. module:: pcapkit.const.ipv6.router_alert

This module contains the constant enumeration for **IPv6 Router Alert Option Values**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.router_alert.RouterAlert`.

.. autoclass:: pcapkit.const.ipv6.router_alert.RouterAlert
   :members:
   :undoc-members:
   :show-inheritance:

IPv6 Routing Types
==================

.. module:: pcapkit.const.ipv6.routing

This module contains the constant enumeration for **IPv6 Routing Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.routing.Routing`.

.. autoclass:: pcapkit.const.ipv6.routing.Routing
   :members:
   :undoc-members:
   :show-inheritance:

Seed-ID Types
=============

.. module:: pcapkit.const.ipv6.seed_id

This module contains the constant enumeration for **Seed-ID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.seed_id.SeedID`.

.. autoclass:: pcapkit.const.ipv6.seed_id.SeedID
   :members:
   :undoc-members:
   :show-inheritance:

Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options
================================================================================

.. module:: pcapkit.const.ipv6.smf_dpd_mode

This module contains the constant enumeration for **Simplified Multicast Forwarding Duplicate Packet Detection (``SMF_DPD``) Options**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.smf_dpd_mode.SMFDPDMode`.

.. autoclass:: pcapkit.const.ipv6.smf_dpd_mode.SMFDPDMode
   :members:
   :undoc-members:
   :show-inheritance:

TaggerID Types
==============

.. module:: pcapkit.const.ipv6.tagger_id

This module contains the constant enumeration for **TaggerID Types**,
which is automatically generated from :class:`pcapkit.vendor.ipv6.tagger_id.TaggerID`.

.. autoclass:: pcapkit.const.ipv6.tagger_id.TaggerID
   :members:
   :undoc-members:
   :show-inheritance:

.. raw:: html

   <hr />

.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
.. [*] https://www.rfc-editor.org/rfc/rfc8200#section-4.2
.. [*] https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml#ipv6-routeralert-values-1
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#taggerId-types
