# -*- coding: utf-8 -*-
# pylint: disable=unused-import
""":class:`~pcapkit.protocols.internet.ipv6.IPv6` Constant Enumerations
===========================================================================

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

.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#extension-header
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-2
.. [*] https://www.rfc-editor.org/rfc/rfc8200#section-4.2
.. [*] https://www.iana.org/assignments/ipv6-routeralert-values/ipv6-routeralert-values.xhtml#ipv6-routeralert-values-1
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#ipv6-parameters-3
.. [*] https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml#taggerId-types

"""

from pcapkit.const.ipv6.extension_header import ExtensionHeader as IPv6_ExtensionHeader
from pcapkit.const.ipv6.option import Option as IPv6_Option
from pcapkit.const.ipv6.option_action import OptionAction as IPv6_OptionAction
from pcapkit.const.ipv6.qs_function import QSFunction as IPv6_QSFunction
from pcapkit.const.ipv6.router_alert import RouterAlert as IPv6_RouterAlert
from pcapkit.const.ipv6.routing import Routing as IPv6_Routing
from pcapkit.const.ipv6.seed_id import SeedID as IPv6_SeedID
from pcapkit.const.ipv6.smf_dpd_mode import SMFDPDMode as IPv6_SMFDPDMode
from pcapkit.const.ipv6.tagger_id import TaggerID as IPv6_TaggerID

__all__ = ['IPv6_ExtensionHeader', 'IPv6_Option', 'IPv6_QSFunction', 'IPv6_RouterAlert', 'IPv6_Routing',
           'IPv6_SeedID', 'IPv6_SMFDPDMode', 'IPv6_TaggerID', 'IPv6_OptionAction']
